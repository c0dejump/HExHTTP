#!/usr/bin/env python3

from __future__ import annotations

import gzip
import hashlib
import socket
import ssl
import zlib
from typing import Any
from concurrent.futures import ThreadPoolExecutor, as_completed

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

DEFAULT_USER_AGENT = "python-requests/2.28.1"

# Configuration des timeouts par défaut
DEFAULT_SOCKET_TIMEOUT = 10
DEFAULT_READ_TIMEOUT = 8
DEFAULT_QUICK_TIMEOUT = 5


def parse_target(url: str) -> tuple[str, str | None, int, str]:
    """Parse une URL et retourne ses composants (scheme, host, port, path)"""
    u = urlparse(url)
    scheme = u.scheme or "http"
    host = u.hostname
    path = u.path or "/"
    if u.query:
        path = f"{path}?{u.query}"
    port = u.port or (443 if scheme == "https" else 80)
    return scheme, host, port, path


def detect_http_version_support(url: str) -> list[str]:
    """Détecte les versions HTTP supportées via ALPN"""
    try:
        scheme, host, port, path = parse_target(url)
        if scheme != "https":
            return []

        raw = socket.create_connection((host, port), timeout=DEFAULT_SOCKET_TIMEOUT)
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
    host: str | None, port: int, *, force_h1: bool = False, timeout: int = DEFAULT_SOCKET_TIMEOUT
) -> ssl.SSLSocket:
    """Crée un socket TLS configuré"""
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
    read_timeout: int = DEFAULT_READ_TIMEOUT,
    expect_more: bool = False,
) -> bytes:
    """Envoie des données et lit la réponse avec gestion intelligente du Content-Length"""
    sock.settimeout(read_timeout)
    if data:
        sock.sendall(data)
    time.sleep(0.1)

    buff = b""
    headers_complete = False
    content_length = None
    is_chunked = False

    try:
        while True:
            try:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                buff += chunk

                # Parse headers une seule fois
                if not headers_complete and b"\r\n\r\n" in buff:
                    headers_complete = True
                    header_part = buff.split(b"\r\n\r\n")[0]
                    
                    for line in header_part.split(b"\r\n"):
                        line_lower = line.lower()
                        if line_lower.startswith(b"content-length:"):
                            try:
                                content_length = int(line.split(b":")[1].strip())
                            except Exception:
                                pass
                        elif line_lower.startswith(b"transfer-encoding:") and b"chunked" in line_lower:
                            is_chunked = True

                # Arrêt si Content-Length atteint
                if headers_complete and content_length is not None and not is_chunked:
                    body_start = buff.find(b"\r\n\r\n") + 4
                    if len(buff) - body_start >= content_length:
                        break
                
                # Pour chunked encoding, chercher le marqueur de fin
                if headers_complete and is_chunked and buff.endswith(b"0\r\n\r\n"):
                    break

            except socket.timeout:
                break
            except Exception:
                break

    except Exception:
        pass

    return buff


def analyze_response_headers(response_data: bytes) -> dict[str, str | None]:
    """Analyse les headers HTTP de la réponse"""
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
            "cache_control": headers.get("cache-control"),
            "x_powered_by": headers.get("x-powered-by"),
        }

        return info
    except Exception:
        return {}


def decompress_if_needed(response_data: bytes, url: str | None = None) -> bytes:
    """Décompresse la réponse si nécessaire (gzip/deflate)"""
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
        elif b"content-encoding: br" in headers_part:
            try:
                import brotli
                decompressed_body = brotli.decompress(body_part)
                return response_data[: header_end + 4] + decompressed_body
            except (ImportError, Exception):
                pass

    except Exception:
        pass

    return response_data


def first_line_and_code(resp: bytes) -> tuple[str, int | None]:
    """Extrait la première ligne et le code de statut HTTP"""
    try:
        line = resp.split(b"\r\n", 1)[0][:200]
        m = re.search(rb"HTTP/\d\.\d\s+(\d+)", line)
        return line.decode(errors="replace"), int(m.group(1)) if m else None
    except Exception:
        return (resp[:80].decode(errors="replace"), None)


def sanitize_first_line(fl: Any) -> str:
    """Nettoie la première ligne pour l'affichage"""
    if not isinstance(fl, str):
        try:
            fl = str(fl)
        except Exception:
            return "Error"
    s = fl.lstrip().upper()
    
    # Détection de réponses HTML/erreur
    html_indicators = ["<!DOCTYPE", "<HTML", "<!DOCTYPE HTML", "<"]
    if any(s.startswith(ind) for ind in html_indicators):
        return "Error"
    
    if "�" in fl:
        return "Binary/Unknown"
    
    return str(fl)


VALID_TOKENS = {"HTTP/0.9", "HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3"}


def classify_version_token(v: str) -> list[str]:
    """Classifie un token de version HTTP et détecte les anomalies"""
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
    """Détermine si une réponse ressemble à du HTTP/0.9"""
    if not response or len(response) == 0:
        return False

    # HTTP/0.9 ne contient pas de headers
    if b"HTTP/" in response[:200]:
        return False

    if b"Content-Type:" in response[:500] or b"Server:" in response[:500]:
        return False

    response_start = response[:500].lower()
    html_indicators = [b"<!doctype", b"<html", b"<head", b"<body", b"<title"]

    if any(response_start.startswith(indicator) for indicator in html_indicators):
        return True

    # Texte brut sans marqueur HTML
    if not response_start.startswith(b"<") and len(response) > 10:
        return True

    return False


def probe_http_09(url: str) -> tuple[bool, bytes]:
    """Teste le support HTTP/0.9 avec plusieurs variantes de requêtes"""
    scheme, host, port, path = parse_target(url)

    tests = [
        f"GET {path}\r\n\r\n",
        f"GET {path}\n\n",
        f"GET {path}",
    ]

    results = []

    for request_template in tests:
        try:
            s: socket.socket | ssl.SSLSocket
            if scheme == "https":
                s = make_tls_socket(host, port, force_h1=True, timeout=DEFAULT_SOCKET_TIMEOUT)
            else:
                s = socket.create_connection((host, port), timeout=DEFAULT_SOCKET_TIMEOUT)

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

    # Validation: au moins 2 résultats positifs similaires
    if len(positive_results) >= 2:
        response_hashes = [
            hashlib.md5(r[1]).hexdigest()  # nosec B324 - MD5 pour comparaison uniquement
            for r in positive_results
        ]
        if len(set(response_hashes)) <= 2:
            return True, positive_results[0][1]

    return False, b""


def validate_vulnerability_response(
    response: bytes, test_name: str
) -> tuple[bool, str]:
    """Valide si une réponse indique une vulnérabilité réelle"""
    if not response or len(response) < 10:
        return False, "Empty or too short response"

    false_positive_signatures = [
        b"400 Bad Request",
        b"404 Not Found",
        b"405 Method Not Allowed",
        b"500 Internal Server Error",
        b"502 Bad Gateway",
        b"503 Service Unavailable",
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


def analyze_proxy_response(response: bytes) -> bool:
    """Analyse stricte de la réponse pour détecter un comportement de proxy"""
    if not response or len(response) < 100:
        return False
    
    first_line, code = first_line_and_code(response)
    if code != 200:
        return False
    
    # Marqueurs spécifiques httpbin.org
    specific_markers = [
        (b'"origin":', b'"url": "http://httpbin.org/get"'),
        (b'"args": {}', b'"headers": {'),
        (b'"User-Agent":', b'"Accept-Encoding":'),
    ]
    
    response_lower = response.lower()
    marker_hits = 0
    
    for marker_pair in specific_markers:
        if all(marker in response_lower for marker in marker_pair):
            marker_hits += 1
    
    # Élimination des faux positifs
    false_positive_indicators = [
        b"404 not found",
        b"403 forbidden", 
        b"error",
        b"exception",
        b"<html",
        b"<!doctype",
    ]
    
    for indicator in false_positive_indicators:
        if indicator in response_lower:
            return False
    
    return marker_hits >= 2


def confirm_proxy_behavior(scheme: str, host: str, port: int) -> bool:
    """Test de confirmation avec httpbin.org/ip"""
    try:
        confirm_url = "http://httpbin.org/ip"
        payload = f"GET {confirm_url}\r\nHost: httpbin.org\r\n\r\n".encode()
        
        s: socket.socket | ssl.SSLSocket
        if scheme == "https":
            s = make_tls_socket(host, port, force_h1=True, timeout=DEFAULT_SOCKET_TIMEOUT)
        else:
            s = socket.create_connection((host, port), timeout=DEFAULT_SOCKET_TIMEOUT)
        
        resp = send_recv(s, payload, read_timeout=DEFAULT_READ_TIMEOUT)
        s.close()
        
        # Structure JSON spécifique de httpbin/ip
        if (b'"origin":' in resp and 
            resp.count(b'"') >= 4 and
            b'.' in resp and
            len(resp) < 500):
            
            if not any(x in resp.lower() for x in [b'<html', b'error', b'exception', b'404']):
                return True
                
    except Exception:
        pass
    
    return False


def check_for_false_positive(scheme: str, host: str, port: int) -> bool:
    """Vérification avec une URL invalide pour détecter les faux positifs"""
    try:
        invalid_url = "http://this-domain-should-never-exist-xyz123456.invalid/nonexistent"
        payload = f"GET {invalid_url}\r\nHost: this-domain-should-never-exist-xyz123456.invalid\r\n\r\n".encode()
        
        s: socket.socket | ssl.SSLSocket
        if scheme == "https":
            s = make_tls_socket(host, port, force_h1=True, timeout=DEFAULT_QUICK_TIMEOUT)
        else:
            s = socket.create_connection((host, port), timeout=DEFAULT_QUICK_TIMEOUT)
        
        resp = send_recv(s, payload, read_timeout=DEFAULT_QUICK_TIMEOUT)
        s.close()
        
        # Réponse positive à une URL invalide = faux positif
        first_line, code = first_line_and_code(resp)
        if code and code == 200 and len(resp) > 100:
            return True
            
    except Exception:
        pass
    
    return False


def calculate_confidence_score(is_valid: bool, is_confirmed: bool, is_false_positive: bool) -> int:
    """Calcule un score de confiance de 0 à 100%"""
    if is_false_positive:
        return 0
    
    score = 0
    if is_valid:
        score += 50
    if is_confirmed:
        score += 50
    
    return min(score, 100)


def determine_rejection_reason(is_valid: bool, is_confirmed: bool, is_false_positive: bool) -> str:
    """Détermine la raison du rejet d'une vulnérabilité"""
    if is_false_positive:
        return "False positive detected - server responds to invalid URLs"
    elif not is_valid:
        return "Response doesn't match expected proxy patterns"
    elif not is_confirmed:
        return "Could not confirm proxy with secondary test"
    else:
        return "Insufficient evidence of proxy"


def test_http09_misconf(url: str) -> dict[str, Any]:
    """Teste les vulnérabilités liées au support HTTP/0.9"""
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
        b"aws_access_key",
        b"private_key",
    ]

    # Test 1: Desync Injection
    try:
        payload = f"GET {path}\n\rHTTP/1.1 200 OK\n\r\n\r".encode()
        s: socket.socket | ssl.SSLSocket
        if scheme == "https":
            s = make_tls_socket(host, port, force_h1=True, timeout=DEFAULT_SOCKET_TIMEOUT)
        else:
            s = socket.create_connection((host, port), timeout=DEFAULT_SOCKET_TIMEOUT)
        resp_desync = send_recv(s, payload, read_timeout=DEFAULT_READ_TIMEOUT)
        s.close()

        is_vuln, reason = validate_vulnerability_response(resp_desync, "desync_injection")
        results["desync_injection"] = is_vuln
        results["desync_injection_reason"] = reason

        if is_vuln:
            results["desync_injection_payload"] = payload.decode(errors="replace")
            results["desync_injection_response"] = resp_desync[:500]
    except Exception as e:
        results["desync_injection"] = False
        results["desync_injection_reason"] = f"Error: {str(e)}"

    # Test 2: Pipeline Injection
    try:
        payload = f"GET {path}\n\rGET /admin\n\r".encode()
        s2: socket.socket | ssl.SSLSocket
        if scheme == "https":
            s2 = make_tls_socket(host, port, force_h1=True, timeout=DEFAULT_SOCKET_TIMEOUT)
        else:
            s2 = socket.create_connection((host, port), timeout=DEFAULT_SOCKET_TIMEOUT)
        resp_pipeline = send_recv(s2, payload, read_timeout=DEFAULT_READ_TIMEOUT)
        s2.close()

        is_vuln, reason = validate_vulnerability_response(resp_pipeline, "pipeline_possible")
        results["pipeline_possible"] = is_vuln
        results["pipeline_possible_reason"] = reason

        if is_vuln:
            results["pipeline_possible_payload"] = payload.decode(errors="replace")
            results["pipeline_possible_response"] = resp_pipeline[:500]
    except Exception as e:
        results["pipeline_possible"] = False
        results["pipeline_possible_reason"] = f"Error: {str(e)}"

    # Test 3: Proxy Path Confusion (amélioré)
    try:
        _tgt = urlparse(url)
        _probe = urlparse(PROXY_PROBE_URL)

        if (_probe.hostname or "").lower() == (_tgt.hostname or "").lower():
            results["proxy_path_confusion"] = False
            results["proxy_path_confusion_exploit"] = "Test skipped - probe URL matches target host"
        else:
            payload1 = f"GET {PROXY_PROBE_URL}\r\nHost: httpbin.org\r\n\r\n".encode()
            s3: socket.socket | ssl.SSLSocket
            if scheme == "https":
                s3 = make_tls_socket(host, port, force_h1=True, timeout=DEFAULT_SOCKET_TIMEOUT)
            else:
                s3 = socket.create_connection((host, port), timeout=DEFAULT_SOCKET_TIMEOUT)
            resp_proxy = send_recv(s3, payload1, read_timeout=DEFAULT_READ_TIMEOUT)
            s3.close()

            is_valid_proxy_response = analyze_proxy_response(resp_proxy)
            is_confirmed = False
            if is_valid_proxy_response:
                is_confirmed = confirm_proxy_behavior(scheme, host, port)
            
            false_positive_check = check_for_false_positive(scheme, host, port)
            is_vuln = is_valid_proxy_response and is_confirmed and not false_positive_check

            results["proxy_path_confusion"] = bool(is_vuln)
            results["proxy_confidence"] = calculate_confidence_score(
                is_valid_proxy_response, is_confirmed, false_positive_check
            )

            if is_vuln:
                exploit_info = [
                    "CONFIRMED PROXY VULNERABILITY:",
                    "1. Server forwards absolute URLs to external hosts",
                    "2. Can be used to bypass firewalls and access internal resources",
                    "3. Potential for SSRF (Server-Side Request Forgery) attacks",
                    "",
                    "POC PAYLOADS:",
                    "• GET http://169.254.169.254/latest/meta-data/ (AWS metadata)",
                    "• GET http://metadata.google.internal/computeMetadata/v1/ (GCP metadata)",
                    "• GET http://internal-server.local/admin (Internal services)",
                    "• GET http://localhost:22 (Port scanning)",
                    "• GET http://127.0.0.1:3306 (Database access)",
                    "• GET http://127.0.0.1:6379 (Redis access)",
                ]

                results["proxy_path_confusion_exploit"] = "\n         ".join(exploit_info)
                results["proxy_path_confusion_payload"] = f"Successful payload: {payload1.decode(errors='replace')}"
                results["proxy_path_confusion_response"] = resp_proxy[:500]
            else:
                results["proxy_path_confusion_reason"] = determine_rejection_reason(
                    is_valid_proxy_response, is_confirmed, false_positive_check
                )

    except Exception as e:
        results["proxy_path_confusion"] = False
        results["proxy_path_confusion_exploit"] = f"Test failed: {str(e)}"

    # Analyse de fuite de contenu sensible
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


def probe_single_version(
    scheme: str, host: str, port: int, path: str, version: str
) -> dict[str, Any]:
    """Teste une seule version HTTP (pour parallélisation)"""
    flags = classify_version_token(version)
    req = None
    try:
        s: socket.socket | ssl.SSLSocket
        if scheme == "https":
            s = make_tls_socket(host, port, force_h1=True, timeout=DEFAULT_SOCKET_TIMEOUT)
        else:
            s = socket.create_connection((host, port), timeout=DEFAULT_SOCKET_TIMEOUT)

        version_str = f" {version}" if version else ""
        req = (
            f"GET {path}{version_str}\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {DEFAULT_USER_AGENT}\r\n"
            f"Accept-Encoding: gzip, deflate\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

        resp = send_recv(s, req, read_timeout=15)
        s.close()

        resp = decompress_if_needed(resp)
        header_info = analyze_response_headers(resp)

        fl, code = first_line_and_code(resp)
        size = len(resp)
        accepted = (code is not None and code < 400) or (code in (101,))

        return {
            "version": version,
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
    except Exception as e:
        return {
            "version": version,
            "code": None,
            "size": 0,
            "first_line": f"ERR: {e.__class__.__name__}",
            "flags": flags,
            "accepted": False,
            "raw_request": req.decode(errors="replace") if req else "",
        }


def probe_weird_versions(url: str, versions: list[str]) -> list[dict[str, Any]]:
    """Teste plusieurs versions HTTP en parallèle"""
    scheme, host, port, path = parse_target(url)
    results = []

    # Exécution parallèle avec ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(probe_single_version, scheme, host, port, path, v): v
            for v in versions
        }
        
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                version = futures[future]
                results.append({
                    "version": version,
                    "code": None,
                    "size": 0,
                    "first_line": f"ERR: {e.__class__.__name__}",
                    "flags": classify_version_token(version),
                    "accepted": False,
                    "raw_request": "",
                })

    # Tri par version pour cohérence d'affichage
    results.sort(key=lambda x: versions.index(x["version"]))
    return results


def risk_badge(item: dict[str, Any]) -> str:
    """Retourne un badge de risque si des flags suspects sont détectés"""
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
        return f"{Colors.YELLOW}💡{Colors.RESET}"
    return ""


def print_line(
    v: str, code: int | None, size: int, extra: str = "", server: str = ""
) -> None:
    """Affiche une ligne formatée de résultat"""
    code_str = f"{code}" if code is not None else "—"
    server_info = f" ({server[:30]})" if server and server != "Unknown" else ""
    spaces3 = " " * 3
    spaces5 = " " * 5
    print(f" ├── {v:<15}: {code_str:<3}{spaces3}[{size}b]{server_info}{spaces5}{extra}")


def check_http_version(url: str) -> None:
    """Fonction principale d'analyse des versions HTTP"""
    print(f"{Colors.CYAN} ├ Version & protocol analysis{Colors.RESET}")

    versions = [
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
    ]

    # Test de connectivité basique
    try:
        requests.get(url, verify=False, allow_redirects=False, timeout=10)
    except Exception as e:
        print(f" ├── Base connectivity error: {e}")

    # Test HTTP/0.9
    try:
        is09, sample = probe_http_09(url)
        stat = f"{Colors.GREEN}Supported{Colors.RESET}" if is09 else f"{Colors.RED}Not supported{Colors.RESET}"
        print(f" ├── HTTP/0.9: {stat} [{len(sample)} bytes]")

        if is09:
            misconf = test_http09_misconf(url)
            main_tests = ["desync_injection", "pipeline_possible", "proxy_path_confusion"]
            
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
                        print(f"         └─ Test payload: {misconf[payload_key][:100]}...")

                    response_key = f"{test_name}_response"
                    if response_key in misconf:
                        response_preview = misconf[response_key].decode(errors="replace")[:150]
                        print(f"         └─ Response preview: {repr(response_preview)}...")
                else:
                    status = f"{Colors.GREEN}SAFE{Colors.RESET}"
                    print(f"       - {test_name}: {status}")

                    reason_key = f"{test_name}_reason"
                    if reason_key in misconf:
                        print(f"         └─ {misconf[reason_key]}")

            # Score de confiance pour le test proxy
            if 'proxy_confidence' in misconf:
                confidence = misconf['proxy_confidence']
                if confidence > 0:
                    confidence_color = Colors.GREEN if confidence >= 90 else Colors.YELLOW if confidence >= 50 else Colors.RED
                    print(f"       - Proxy confidence score: {confidence_color}{confidence}%{Colors.RESET}")

            # Analyse de fuite de contenu
            content_leak_tests = [k for k in misconf.keys() if k.endswith("_content_leak")]
            if content_leak_tests:
                print("       Content leak analysis:")
                for leak_test in content_leak_tests:
                    if misconf.get(leak_test, False):
                        sig_key = leak_test.replace("_content_leak", "_leaked_signature")
                        signature = misconf.get(sig_key, "Unknown signature")
                        print(f"         - {leak_test}: {Colors.RED}DETECTED{Colors.RESET} ({signature})")

    except Exception as e:
        print(f" ├── HTTP/0.9: error during enhanced testing: {e}")
        logger.exception("HTTP/0.9 testing error")

    # Test des versions anormales (parallélisé)
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
        for item in rejected_versions[:10]:  # Limite à 10 pour lisibilité
            v = item["version"] if item["version"] != "" else "<empty>"
            flags = ",".join(item["flags"]) if item["flags"] else "N/A"
            badge = risk_badge(item)
            fl_sane = sanitize_first_line(item["first_line"])
            extra = f"{badge} [{fl_sane}] flags={flags}"
            print_line(v, item["code"], item["size"], extra, item.get("server", ""))