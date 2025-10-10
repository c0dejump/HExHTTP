#!/usr/bin/env python3

"""
Web Cache Poisoning on unkeyed Header
https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws#using-web-cache-poisoning-to-exploit-unsafe-handling-of-resource-imports
"""

import utils.proxy as proxy
from modules.lists import header_list
from utils.style import Colors, Identify
from utils.utils import configure_logger, random, requests, sys

logger = configure_logger(__name__)


def valid_reflection(
    uri: str,
    s: requests.Session,
    pk: dict,
    authent: tuple[str, str] | None,
    matching_forward: str,
) -> None:
    for _ in range(0, 10):
        s.get(
            uri,
            headers=pk,
            verify=False,
            auth=authent,
            timeout=10,
            allow_redirects=False,
        )
    req_valid = s.get(
        uri,
        verify=False,
        auth=authent,
        timeout=10,
        allow_redirects=False,
    )
    if matching_forward in req_valid.text:
        print(
            f" {Identify.confirmed} | BODY REFLECTION | RESOURCE FILE | \033[34m{uri}\033[0m | PAYLOAD: {Colors.THISTLE}{pk if len(pk) < 60 else pk[0:60]}{Colors.RESET}"
        )
        if proxy.proxy_enabled:
            from utils.proxy import proxy_request

            proxy_request(s, "GET", uri, headers=pk, data=None)
    elif matching_forward in req_valid.headers:
        print(
            f" {Identify.confirmed} | HEADER REFLECTION | RESOURCE FILE | \033[34m{uri}\033[0m | PAYLOAD: {Colors.THISTLE}{pk if len(pk) < 60 else pk[0:60]}{Colors.RESET}"
        )
        if proxy.proxy_enabled:
            from utils.proxy import proxy_request

            proxy_request(s, "GET", uri, headers=pk, data=None)


def check_reflection(
    url: str,
    s: requests.Session,
    authent: tuple[str, str] | None,
    matching_forward: str,
) -> None:
    for hl in header_list:
        uri = f"{url}?cb={random.randrange(9999)}"
        pk = {hl: matching_forward}
        req = s.get(
            uri,
            headers=pk,
            verify=False,
            auth=authent,
            timeout=10,
            allow_redirects=False,
        )
        if matching_forward in req.text:
            print(
                f" {Identify.behavior} | BODY REFLECTION | RESOURCE FILE | \033[34m{uri}\033[0m | PAYLOAD: {Colors.THISTLE}{str(pk) if len(str(pk)) < 60 else str(pk)[0:60]}{Colors.RESET}"
            )
            if proxy.proxy_enabled:
                from utils.proxy import proxy_request

                proxy_request(s, "GET", uri, headers=pk, data=None)
            valid_reflection(uri, s, pk, authent, matching_forward)
        elif matching_forward in req.headers:
            print(
                f" {Identify.behavior} | HEADER REFLECTION | RESOURCE FILE | \033[34m{uri}\033[0m | PAYLOAD: {Colors.THISTLE}{str(pk) if len(str(pk)) < 60 else str(pk)[0:60]}{Colors.RESET}"
            )
            if proxy.proxy_enabled:
                from utils.proxy import proxy_request

                proxy_request(s, "GET", uri, headers=pk, data=None)
            valid_reflection(uri, s, pk, authent, matching_forward)
        else:
            pass
        if len(list(pk.values())[0]) < 50:
            sys.stdout.write(f"\033[34m {pk}\033[0m\r")
            sys.stdout.write("\033[K")


def check_cache_files(
    uri: str,
    s: requests.Session,
    custom_header: dict,
    authent: tuple[str, str] | None,
) -> None:

    matching_forward = "ndvyepenbvtidpvyzh"

    for endpoints in ["plopiplop.js", "plopiplop.css"]:
        url = f"{uri}{endpoints}" if uri[-1] == "/" else f"{uri}/{endpoints}"
        try:
            check_reflection(url, s, authent, matching_forward)
        except requests.Timeout:
            print(f" └── Timeout Error with {endpoints}")
        except KeyboardInterrupt:
            print(" ! Canceled by keyboard interrupt (Ctrl-C)")
            sys.exit()
        except Exception as e:
            print(e)
            logger.exception(e)
