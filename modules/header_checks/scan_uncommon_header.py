#!/usr/bin/env python3
"""
Script d'analyse des en-têtes HTTP non-communs avec tests de paramètres
pour identifier des comportements d'erreur potentiels et détecter les réflexions
"""

from utils.style import Colors, Identify
from utils.utils import configure_logger, random, requests, sys
from utils.print_utils import format_payload
from modules.global_requests import send_global_requests

logger = configure_logger(__name__)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko"
)

reflect_word = "bycodejump"


common_header = [
    "content-type",
    "content-length",
    "date",
    "server",
    "cache-control",
    "connection",
    "accept",
    "accept-encoding",
    "accept-language",
    "user-agent",
    "host",
    "referer",
    "cookie",
    "set-cookie",
    "authorization",
    "content-encoding",
    "transfer-encoding",
    "last-modified",
    "etag",
    "expires",
    "pragma",
    "vary",
    "content-disposition",
    "access-control-allow-origin",
    "Content-language",
    "X-Frame-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-CDN",
    "X-Drupal-Cache",
    "x-xss-protection",
    "x-content-type-options",
    "x-robots-tag",
    "Age",
    "x-cache",
    "X-Cache-Hits",
    "Keep-Alive",
    "X-Permitted-Cross-Domain-Policies",
    "x-powered-by",
    "Content-Security-Policy-Report-Only",
    "Accept-Ranges",
    "X-Served-By",
    "X-Timer",
    "via",
    "cf-cache-status",
    "cf-ray",
    "Alt-Svc",
    "status",
    "P3P",
    "Features-Policy",
    "Feature-Policy",
    "Access-Control-Max-Age",
    "Expect-CT",
    "X-Age",
    "Report-To",
    "x-real-age",
    "Server-Timing",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "Mime-Version",
    "X-Content-Security-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "cache-status",
]

errors_payload = ["A" * 1024, "xxxx", "©", "®"]



def verify_cp_reflect(
    url: str,
    s: requests.Session,
    payload: dict[str, str],
    authent: tuple[str, str] | None = None,
) -> None:
    uri = f"{url}{random.randrange(999)}"

    for _ in range(5):
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
            f" {Identify.confirmed} | BODY REFLECTED | {Colors.BLUE}{uri}{Colors.RESET} | PAYLOAD: {Colors.THISTLE}{format_payload(payload)}{Colors.RESET}"
        )
    elif reflect_word in req_verify.headers:
        print(
            f" {Identify.confirmed} | HEADER REFLECTED | {Colors.BLUE}{uri}{Colors.RESET} | PAYLOAD: {Colors.THISTLE}{format_payload(payload)}{Colors.RESET}"
        )


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
                f" {Identify.behavior} | BODY REFLECTED | {Colors.BLUE}{uri}{Colors.RESET} | PAYLOAD: {Colors.THISTLE}{format_payload(headers)}{Colors.RESET}"
            )
            verify_cp_reflect(url, s, headers, authent)
        elif reflect_word in req_reflected.headers:
            print(
                f" {Identify.behavior} | HEADER REFLECTED | {Colors.BLUE}{uri}{Colors.RESET} | PAYLOAD: {Colors.THISTLE}{format_payload(headers)}{Colors.RESET}"
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
            send_global_requests(uri, s, authent, fp_results, "UH CPDoS", "0", probe_headers, initialResponse)


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

    uncommon_header = []

    try:
        for header, _ in main_head.items():
            found = False
            for h in common_header:
                if header.lower() == h.lower():
                    found = True
            if not found:
                uncommon_header.append(header)
        if uncommon_header:
            print(f" └── Uncommon headers: {uncommon_header}")

            test_reflection(url, s, uncommon_header, authent)
            uncommon_header_test(
                url, s, initialResponse, uncommon_header, fp_results, authent
            )

    except requests.exceptions.RequestException as re:
        logger.error(f"Error during query : {re}")
    except Exception as e:
        logger.exception(f"Unexpected error : {e}")
