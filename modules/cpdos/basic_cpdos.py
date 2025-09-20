#!/usr/bin/env python3

"""
Attempts to find Cache Poisoning Denial of Service (CpDoS) error based
https://cpdos.org/
"""

import utils.proxy as proxy
from modules.lists import payloads_keys
from utils.style import Colors, Identify
from utils.utils import configure_logger, human_time, random, requests, sys

logger = configure_logger(__name__)


def check_cached_status(
    url: str,
    s: requests.Session,
    pk: dict[str, str],
    main_status_code: int,
    authent: tuple[str, str] | None,
) -> None:
    behavior = False
    confirmed = False
    cache_status: bool = False

    for _ in range(0, 5):
        req = s.get(
            url,
            headers=pk,
            verify=False,
            allow_redirects=False,
            auth=authent,
            timeout=10,
        )
    req_verify = s.get(
        url, verify=False, allow_redirects=False, auth=authent, timeout=10
    )
    logger.debug(f"{req.status_code} :: {req_verify.status_code}")
    if (
        req.status_code == req_verify.status_code
        and req.status_code not in [429, 200, 304, 303, 403]
        or req_verify.status_code not in [429, 200, 304, 303, 403]
        and req_verify.status_code != main_status_code
    ):
        behavior = True
        for rh in req_verify.headers:
            if "age" in rh.lower() or "hit" in req_verify.headers[rh].lower():
                confirmed = True
                cache_status = True
    elif req.status_code != req_verify.status_code and req.status_code == 304:
        for rh in req_verify.headers:
            if "age" in rh.lower() or "hit" in req_verify.headers[rh].lower():
                behavior = True
                cache_status = True
    elif req.status_code != req_verify.status_code and req.status_code not in [
        429,
        304,
    ]:
        for rh in req_verify.headers:
            if "age" in rh.lower() or "hit" in req_verify.headers[rh].lower():
                behavior = True
                cache_status = True

    cache_tag = (
        f"{Colors.RED}{cache_status}{Colors.RESET}"
        if not cache_status
        else f"{Colors.GREEN}{cache_status}{Colors.RESET}"
    )
    if confirmed:
        print(
            f" {Identify.confirmed} | CPDoSError {main_status_code} > {req.status_code} | CACHETAG : {cache_tag} | {Colors.BLUE}{url}{Colors.RESET} | PAYLOAD: {Colors.THISTLE}{pk}{Colors.RESET}"
        )
        if proxy.proxy_enabled:
            from utils.proxy import proxy_request

            proxy_request(s, "GET", url, headers=pk, data=None, severity="confirmed")
        behavior = False
        confirmed = False
    elif behavior:
        pk_str = str(pk)
        print(
            f" {Identify.behavior} | CPDoSError {main_status_code} > {req.status_code} | CACHETAG : {cache_tag} | {Colors.BLUE}{url}{Colors.RESET} | PAYLOAD: {Colors.THISTLE}{pk_str if len(pk_str) < 60 else pk_str[0:60]}{Colors.RESET}"
        )
        if proxy.proxy_enabled:
            from utils.proxy import proxy_request

            proxy_request(s, "GET", url, headers=pk, data=None, severity="behavior")


def check_cached_len(
    url: str,
    s: requests.Session,
    pk: dict[str, str],
    main_len: int,
    authent: tuple[str, str] | None,
) -> None:
    behavior = False
    confirmed = False
    cache_status: bool = False

    for _ in range(0, 5):
        req = s.get(
            url,
            headers=pk,
            verify=False,
            allow_redirects=False,
            auth=authent,
            timeout=10,
        )
    req_verify = s.get(
        url, verify=False, allow_redirects=False, auth=authent, timeout=10
    )
    logger.debug(f"{req.status_code} :: {req_verify.status_code}")
    if (
        len(req.content) == len(req_verify.content)
        and len(req_verify.content) != main_len
        and req_verify.status_code not in [429, 403]
    ):
        behavior = True
        for rh in req_verify.headers:
            if "age" in rh.lower() or "hit" in req_verify.headers[rh].lower():
                confirmed = True
                cache_status = True
    elif len(req.content) != len(req_verify.content):
        for rh in req_verify.headers:
            if "age" in rh.lower():
                behavior = True
                cache_status = True
            else:
                behavior = True
                cache_status = False

    cache_tag = (
        f"{Colors.RED} {cache_status} {Colors.RESET}"
        if not cache_status
        else f"{Colors.GREEN} {cache_status} {Colors.RESET}"
    )
    if confirmed:
        print(
            f" {Identify.confirmed} | CPDoSError {main_len}b > {len(req.content)}b | CACHETAG : {cache_tag} | {Colors.BLUE}{url}{Colors.RESET} | PAYLOAD: {Colors.THISTLE}{pk}{Colors.RESET}"
        )
        if proxy.proxy_enabled:
            from utils.proxy import proxy_request

            proxy_request(s, "GET", url, headers=pk, data=None, severity="confirmed")
        behavior = False
    elif behavior:
        pk_str = str(pk)
        print(
            f" {Identify.behavior} | CPDoSError {main_len}b > {len(req.content)}b | CACHETAG : {cache_tag} | {Colors.BLUE}{url}{Colors.RESET} | PAYLOAD: {Colors.THISTLE}{pk_str if len(pk_str) < 60 else pk_str[0:60]}{Colors.RESET}"
        )
        if proxy.proxy_enabled:
            from utils.proxy import proxy_request

            proxy_request(s, "GET", url, headers=pk, data=None, severity="behavior")


def cpdos_main(
    url: str,
    s: requests.Session,
    initial_response: requests.Response,
    authent: tuple[str, str] | None,
    human: str,
) -> None:
    main_status_code = initial_response.status_code
    main_len = len(initial_response.content)

    blocked = 0
    for pk in payloads_keys:
        uri = f"{url}{random.randrange(99999)}"
        try:
            req = s.get(
                uri,
                headers=pk,
                verify=False,
                auth=authent,
                timeout=10,
                allow_redirects=False,
            )
            len_req = len(req.content)

            if req.status_code == 888:
                print(
                    f" {Identify.behavior} | CPDoSError 888 response | CACHETAG: N/A | {Colors.BLUE}{url}{Colors.RESET} | PAYLOAD: {pk}"
                )
                check_cached_status(uri, s, pk, main_status_code, authent)
            elif req.status_code == 403 or req.status_code == 429:
                uri_403 = f"{url}{random.randrange(999)}"
                req_403_test = s.get(
                    uri_403,
                    verify=False,
                    auth=authent,
                    timeout=10,
                    allow_redirects=False,
                )
                if req_403_test.status_code == 403 or req_403_test.status_code == 429:
                    blocked += 1

            elif (
                blocked < 3
                and req.status_code != 200
                and main_status_code not in [403, 401]
                and req.status_code != main_status_code
            ):
                # print(f"[{main_status_code}>{req.status_code}] [{len(main_status_code.headers)}b>{len(req.headers)}b] [{len(main_status_code.content)}b>{len(req.content)}b] {url} :: {pk}")
                check_cached_status(uri, s, pk, main_status_code, authent)
            elif blocked < 3 and req.status_code == main_status_code:
                if len(str(main_len)) <= 5 and main_len not in range(
                    len_req - 1000, len_req + 1000
                ):
                    check_cached_len(uri, s, pk, main_len, authent)
                elif len(str(main_len)) > 5 and main_len not in range(
                    len_req - 10000, len_req + 10000
                ):
                    check_cached_len(uri, s, pk, main_len, authent)
            human_time(human)

            if len(list(pk.values())[0]) < 50 and len(list(pk.keys())[0]) < 50:
                sys.stdout.write(f"{Colors.BLUE}{pk}{Colors.RESET}\r")
                sys.stdout.write("\033[K")
        except KeyboardInterrupt:
            print("Exiting")
            sys.exit()
        except Exception as e:
            logger.exception(e)
        uri = url
