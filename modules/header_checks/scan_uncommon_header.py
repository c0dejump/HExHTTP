#!/usr/bin/env python3
"""
Script for analyzing uncommon HTTP headers with parameter testing
to identify potential error behaviors and detect reflections.

Includes detection of headers from the target's HTML/JS sources
"""

import re
from urllib.parse import urljoin, urlparse
from collections import defaultdict

from utils.style import Colors, Identify
from utils.utils import configure_logger, random, requests, sys
from utils.print_utils import format_payload
from modules.global_requests import send_global_requests
from utils.collect import add_finding

logger = configure_logger(__name__)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko"
)

reflect_word = "bycodejump"


_HEADER_PATTERNS = [
    r'["\']((?:X|x)-[A-Za-z0-9\-]{2,})["\']',
    r'["\'](Authorization)["\']',
    r'["\'](Api-Key)["\']',
    r'["\'](Client-ID)["\']',
    r'["\'](XSRF-TOKEN)["\']',
    r'["\'](Bearer)["\']',
    r'["\'](Content-Type)["\']',
    r'["\'](Accept)["\']',
    r'["\'](Cookie)["\']',
    r'["\'](Referer)["\']',
    r'["\'](Origin)["\']',
    r'["\'](Access-Control-[A-Za-z0-9\-]+)["\']',
]

_USAGE_PATTERNS = [
    r'setRequestHeader\(["\']([^"\']+)["\']',
    r'headers\s*[=:]\s*{([^}]+)}',
    r'axios\.(?:get|post|put|patch|delete|request)\s*\(.*?headers\s*:\s*{([^}]+)}',
    r'fetch\(.*?headers\s*:\s*{([^}]+)}',
    r'\.header\(["\']([^"\']+)["\']',
    r'\.set\(["\']([^"\']+)["\']',
    r'new\s+Headers\s*\(\s*{([^}]+)}',
    r'append\(["\']([^"\']+)["\']',
]

_ERROR_PATTERNS = [
    r'(?:Missing|Invalid|missing|invalid)\s+([A-Za-z][A-Za-z0-9\-]{2,})\s+[Hh]eader',
    r'[Hh]eader\s+["\']?([A-Za-z][A-Za-z0-9\-]{2,})["\']?\s+(?:is\s+)?(?:missing|required|invalid)',
    r'require[s]?\s+(?:a\s+)?[Hh]eader\s+["\']?([A-Za-z][A-Za-z0-9\-]{2,})',
    r'([A-Za-z][A-Za-z0-9\-]{2,})\s+[Hh]eader\s+(?:is\s+)?(?:required|missing|invalid)',
]

_NOISE_VALUES = {
    "true", "false", "null", "undefined", "none", "function", "return",
    "var", "let", "const", "if", "else", "for", "while", "class",
    "import", "export", "default", "this", "new", "type", "name",
    "value", "data", "id", "key", "get", "set", "use", "map",
    "string", "number", "object", "array", "boolean", "any",
    "http", "https", "url", "path", "host", "port",
}


def _clean_header(raw: str) -> str | None:
    h = raw.strip().strip(":").strip()
    if not h or len(h) < 3 or len(h) > 80:
        return None
    if h.lower() in _NOISE_VALUES:
        return None
    if not re.match(r'^[A-Za-z][A-Za-z0-9\-]+$', h):
        return None
    return h.lower()


def _same_origin(base_url: str, url: str) -> bool:
    return urlparse(base_url).netloc == urlparse(url).netloc


def _extract_from_content(content: str) -> set[str]:
    """
    Extracts HTTP header names from text content (HTML or JS)
    using the patterns inherited from header_scanner.py.
    Returns a set of normalized (lowercase) names.
    """
    found: set[str] = set()

    for pattern in _HEADER_PATTERNS:
        for m in re.finditer(pattern, content):
            h = _clean_header(m.group(1))
            if h:
                found.add(h)

    for pattern in _USAGE_PATTERNS:
        for block_match in re.finditer(pattern, content, re.DOTALL):
            block = block_match.group(1) if block_match.lastindex else block_match.group(0)
            for raw in re.findall(r'["\']([^"\']{2,60})["\']', block):
                h = _clean_header(raw)
                if h:
                    found.add(h)

    for pattern in _ERROR_PATTERNS:
        for m in re.finditer(pattern, content):
            raw = m.group(1) if m.lastindex else m.group(0)
            h = _clean_header(raw)
            if h:
                found.add(h)

    return found


def scan_source_for_headers(
    url: str,
    s: requests.Session,
    timeout: int = 8,
) -> list[str]:
    """
    Download the target page and its external JS files, and extract
    all HTTP header names present in the source code.

    Returns a list of normalized (lowercase) header names,
    ready to be injected into uncommon_header_test / test_reflection.
    """
    found: set[str] = set()

    try:
        resp = s.get(url, timeout=timeout, verify=False, allow_redirects=True)
        html = resp.text
    except requests.RequestException as e:
        logger.warning(f"scan_source_for_headers — Download error {url}: {e}")
        return []

    found |= _extract_from_content(html)

    inline_scripts = re.findall(
        r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE
    )
    for script in inline_scripts:
        found |= _extract_from_content(script)

    js_srcs = re.findall(
        r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE
    )
    for src in js_srcs:
        full_url = urljoin(url, src)
        if not _same_origin(url, full_url):
            continue
        try:
            js_resp = s.get(full_url, timeout=timeout, verify=False)
            found |= _extract_from_content(js_resp.text)
            logger.debug(f"  [source-scan] JS analysed : {full_url} — {len(found)} headers groups")
        except requests.RequestException as e:
            logger.debug(f"  [source-scan] JS Error {full_url}: {e}")

    headers_list = sorted(found)
    return headers_list


common_header = [
    "content-type", "content-length", "date", "server", "cache-control",
    "connection", "accept", "accept-encoding", "accept-language", "user-agent",
    "host", "referer", "cookie", "set-cookie", "authorization",
    "content-encoding", "transfer-encoding", "last-modified", "etag",
    "expires", "pragma", "vary", "content-disposition",
    "access-control-allow-origin", "Content-language", "X-Frame-Options",
    "Content-Security-Policy", "Strict-Transport-Security", "Referrer-Policy",
    "Permissions-Policy", "X-CDN", "X-Drupal-Cache", "x-xss-protection",
    "x-content-type-options", "x-robots-tag", "Age", "x-cache",
    "X-Cache-Hits", "Keep-Alive", "X-Permitted-Cross-Domain-Policies",
    "x-powered-by", "Content-Security-Policy-Report-Only", "Accept-Ranges",
    "X-Served-By", "X-Timer", "via", "cf-cache-status", "cf-ray", "Alt-Svc",
    "status", "P3P", "Features-Policy", "Feature-Policy",
    "Access-Control-Max-Age", "Expect-CT", "X-Age", "Report-To",
    "x-real-age", "Server-Timing", "cross-origin-embedder-policy",
    "cross-origin-opener-policy", "Mime-Version", "X-Content-Security-Policy",
    "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy",
    "cache-status",
]

errors_payload = ["A" * 1024, "xxxx", "©", "®", "=", ";"]


def verify_cp_reflect(
    url: str,
    s: requests.Session,
    payload: dict[str, str],
    authent: tuple[str, str] | None = None,
) -> None:
    uri = f"{url}{random.randrange(999)}"

    for _ in range(3):
        s.get(
            uri,
            headers=payload,
            verify=False,
            allow_redirects=False,
            timeout=10,
            auth=authent,
        )
    req_verify = s.get(
        uri, verify=False, allow_redirects=False, timeout=10, auth=authent
    )

    if reflect_word in req_verify.text:
        print(
            f" {Identify.confirmed} | BODY REFLECTED | "
            f"{Colors.BLUE}{uri}{Colors.RESET} | "
            f"PAYLOAD: {Colors.THISTLE}{format_payload(payload)}{Colors.RESET}"
        )
        add_finding(url, {
            "type": "UH CP",
            "severity": "critical",
            "title": "UH CP",
            "description": "BODY REFLECTED",
            "payload": payload,
            "evidence": {
                "status_code": req_verify.status_code,
                "response_size": len(req_verify.content),
                "initial_status": 0,
                "initial_size": 0,
                "uri": uri,
            },
        })
    elif reflect_word in req_verify.headers:
        print(
            f" {Identify.confirmed} | HEADER REFLECTED | "
            f"{Colors.BLUE}{uri}{Colors.RESET} | "
            f"PAYLOAD: {Colors.THISTLE}{format_payload(payload)}{Colors.RESET}"
        )
        add_finding(url, {
            "type": "UH CP",
            "severity": "critical",
            "title": "UH CP",
            "description": "HEADER REFLECTED",
            "payload": payload,
            "evidence": {
                "status_code": req_verify.status_code,
                "response_size": len(req_verify.content),
                "initial_status": 0,
                "initial_size": 0,
                "uri": uri,
            },
        })


def test_reflection(
    url: str,
    s: requests.Session,
    uncommon_header: list[str],
    authent: tuple[str, str] | None = None,
) -> None:
    for uh in uncommon_header:
        headers = {uh: reflect_word}
        uri = f"{url}{random.randrange(999)}"
        req_reflected = s.get(
            url, headers=headers, verify=False, allow_redirects=False, timeout=10
        )
        if reflect_word in req_reflected.text:
            print(
                f" {Identify.behavior} | BODY REFLECTED | "
                f"{Colors.BLUE}{uri}{Colors.RESET} | "
                f"PAYLOAD: {Colors.THISTLE}{format_payload(headers)}{Colors.RESET}"
            )
            verify_cp_reflect(url, s, headers, authent)
        elif reflect_word in req_reflected.headers:
            print(
                f" {Identify.behavior} | HEADER REFLECTED | "
                f"{Colors.BLUE}{uri}{Colors.RESET} | "
                f"PAYLOAD: {Colors.THISTLE}{format_payload(headers)}{Colors.RESET}"
            )
            verify_cp_reflect(url, s, headers, authent)


def uncommon_header_test(
    url: str,
    s: requests.Session,
    initialResponse: requests.Response,
    uncommon_header: list[str],
    fp_results: tuple[int, int] | None,
    authent: tuple[str, str] | None = None,
) -> None:
    for uh in uncommon_header:
        for ep in errors_payload:
            probe_headers = {uh: ep}
            uri = f"{url}{random.randrange(999)}"
            send_global_requests(
                uri, s, authent, fp_results, "UH CPDoS", "0", probe_headers, initialResponse
            )


def check_uncommon_header(
    url: str,
    s: requests.Session,
    initialResponse: requests.Response,
    main_head: dict,
    fp_results: tuple[int, int] | None,
    authent: tuple[str, str] | None = None,
) -> None:
    print(f"{Colors.CYAN} ├ Uncommon header analysis{Colors.RESET}")
    url = f"{url}?cb={random.randrange(999)}"

    uncommon_header: list[str] = []

    try:
        for header in main_head:
            if not any(header.lower() == h.lower() for h in common_header):
                uncommon_header.append(header)

        if uncommon_header:
            print(f" └── Uncommon headers (response): {uncommon_header}")

        source_headers = scan_source_for_headers(url, s)


        existing_lower = {h.lower() for h in uncommon_header}
        new_from_source = [
            h for h in source_headers
            if h.lower() not in existing_lower
            and not any(h.lower() == c.lower() for c in common_header)
        ]

        if new_from_source:
            print(
                f" └── Headers added from source scan: "
                f"{Colors.THISTLE}{new_from_source}{Colors.RESET}"
            )
            uncommon_header.extend(new_from_source)

        if uncommon_header:
            test_reflection(url, s, uncommon_header, authent)
            uncommon_header_test(
                url, s, initialResponse, uncommon_header, fp_results, authent
            )
        else:
            print(" └── No uncommon headers found to test.")

    except requests.exceptions.RequestException as re_exc:
        logger.error(f"Error during query : {re_exc}")
    except Exception as e:
        logger.exception(f"Unexpected error : {e}")