#!/usr/bin/env python3

"""
Methods poisoning
"""

from collections.abc import Sequence

import utils.proxy as proxy
from utils.style import Colors, Identify
from utils.utils import (
    BIG_CONTENT_DELTA_RANGE,
    CONTENT_DELTA_RANGE,
    configure_logger,
    random,
    requests,
)

logger = configure_logger(__name__)

VULN_NAME = "Fat Methods"


def print_result(
    status: str,
    vuln: str,
    method: str,
    reason: str,
    reason_result: str,
    url: str,
    payload: str,
) -> None:
    if payload:
        print(
            f" {status} | {vuln} {method} | {reason} {reason_result} | \033[34m{url}\033[0m | PAYLOAD: {Colors.THISTLE}{method} with {payload}{Colors.RESET}"
        )
    else:
        print(
            f" {status} | {vuln} {method} | {reason} {reason_result} | \033[34m{url}\033[0m | PAYLOAD: {Colors.THISTLE}{method}{Colors.RESET}"
        )


def verify_fat_get_poisoning(
    s: requests.Session,
    url: str,
    d: str,
    rm: str,
    req_main: requests.Response,
    len_main: int,
    authent: tuple[str, str] | None,
) -> None:
    for _ in range(5):
        req_verify = s.request(
            rm,
            url=url,
            data=d,
            verify=False,
            allow_redirects=False,
            timeout=10,
            auth=authent,
        )
    req_main_check = s.get(
        url, verify=False, allow_redirects=False, timeout=10, auth=authent
    )

    if (
        req_verify.status_code == req_main_check.status_code
        and req_main_check.status_code != req_main.status_code
    ):
        print_result(
            Identify.confirmed,
            "FAT",
            f"{rm}",
            "DIFFERENT STATUS-CODE",
            f"{req_main.status_code} > {req_verify.status_code}",
            url,
            d,
        )
    elif (
        len(req_verify.content) == len(req_main_check.content)
        and len(req_main_check.content) != len_main
    ):
        print_result(
            Identify.confirmed,
            "FAT",
            f"{rm}",
            "DIFFERENT RESP LENGTH",
            f"{len_main}b > {len(req_verify.content)}b",
            url,
            d,
        )
    elif d in req_main_check.text or "codejump" in req_main_check.text:
        print_result(Identify.confirmed, "FAT", f"{rm}", "BODY REFLECTION", "", url, d)
    elif d in req_main_check.headers or "codejump" in req_main_check.headers:
        print_result(
            Identify.confirmed, "FAT", f"{rm}", "HEADERS REFLECTION", "", url, d
        )


def fat_methods_poisoning(
    url: str,
    s: requests.Session,
    requests_method: Sequence[str],
    range_exlusion: range,
    req_main: requests.Response,
    len_main: int,
    custom_header: dict,
    authent: tuple[str, str] | None,
) -> None:
    body_datas = ["data=codejump", '{ "test": "codejump" }']

    for d in body_datas:
        for rm in requests_method:
            url = f"{url}{random.randrange(99)}"
            req_fg = s.request(
                rm,
                url=url,
                data=d,
                verify=False,
                allow_redirects=False,
                timeout=10,
                auth=authent,
            )
            len_fg = len(req_fg.content)
            behavior_check = False

            if req_fg.status_code != req_main.status_code:
                print_result(
                    Identify.behavior,
                    "FAT",
                    f"{rm}",
                    "DIFFERENT STATUS-CODE",
                    f"{req_main.status_code} > {req_fg.status_code}",
                    url,
                    d,
                )
                behavior_check = True
                verify_fat_get_poisoning(s, url, d, rm, req_main, len_main, authent)
            elif len_fg not in range_exlusion:
                print_result(
                    Identify.behavior,
                    "FAT",
                    f"{rm}",
                    "DIFFERENT RESP LENGTH",
                    f"{req_main.status_code}b > {len_fg}b",
                    url,
                    d,
                )
                behavior_check = True
                verify_fat_get_poisoning(s, url, d, rm, req_main, len_main, authent)
            elif d in req_fg.text or "codejump" in req_fg.text:
                print_result(
                    Identify.behavior, "FAT", f"{rm}", "BODY REFLECTION", "", url, d
                )
                behavior_check = True
                verify_fat_get_poisoning(s, url, d, rm, req_main, len_main, authent)
            elif d in req_fg.headers or "codejump" in req_fg.headers:
                print_result(
                    Identify.behavior, "FAT", f"{rm}", "HEADERS REFLECTION", "", url, d
                )
                behavior_check = True
                verify_fat_get_poisoning(s, url, d, rm, req_main, len_main, authent)
            if behavior_check and proxy.proxy_enabled:
                from utils.proxy import proxy_request

                proxy_request(s, "GET", url, headers={"User-Agent": "hexhttp"}, data=d)


def cp_mix(
    url: str,
    s: requests.Session,
    requests_method: Sequence[str],
    range_exlusion: range,
    req_main: requests.Response,
    len_main: int,
    custom_header: dict,
    authent: tuple[str, str] | None,
) -> None:
    if req_main.status_code not in [403, 429]:
        for rm in requests_method:
            behavior_check = False
            url = f"{url}{random.randrange(99)}"

            if rm == "POST":
                body_datas = ["data=codejump", '{ "test": "codejump" }']
                for d in body_datas:
                    req_mix = s.request(
                        rm,
                        url=url,
                        data=d,
                        verify=False,
                        allow_redirects=False,
                        timeout=10,
                        auth=authent,
                    )
                    req_get = s.get(url, auth=authent)
                    if req_mix.status_code != req_get.status_code:
                        print_result(
                            Identify.behavior,
                            "MIX",
                            f"{rm} <> GET",
                            "DIFFERENT STATUS-CODE",
                            f"{req_main.status_code} > {req_mix.status_code}",
                            url,
                            d,
                        )
                        behavior_check = True
                    elif len(req_mix.content) not in range_exlusion and len(
                        req_mix.content
                    ) != len(req_get.content):
                        print_result(
                            Identify.behavior,
                            "MIX",
                            f"{rm} <> GET",
                            "DIFFERENT RESP LENGTH",
                            f"{len(req_main.content)}b > {len(req_mix.content)}b",
                            url,
                            d,
                        )
                        behavior_check = True
                    if behavior_check and proxy.proxy_enabled:
                        from utils.proxy import proxy_request

                        proxy_request(
                            s,
                            "GET",
                            url,
                            headers={"User-Agent": "hexhttp v2.0 security scan"},
                            data=d,
                        )
            else:
                d = ""
                req_mix = s.request(
                    rm,
                    url=url,
                    verify=False,
                    allow_redirects=False,
                    timeout=10,
                    auth=authent,
                )
                req_get = s.get(url, auth=authent)
                if req_mix.status_code != req_get.status_code:
                    print_result(
                        Identify.behavior,
                        "MIX",
                        f"{rm} <> GET",
                        "DIFFERENT STATUS-CODE",
                        f"{req_main.status_code} > {req_mix.status_code}",
                        url,
                        d,
                    )
                    behavior_check = True
                elif len(req_mix.content) not in range_exlusion and len(
                    req_mix.content
                ) != len(req_get.content):
                    print_result(
                        Identify.behavior,
                        "MIX",
                        f"{rm} <> GET",
                        "DIFFERENT RESP LENGTH",
                        f"{len(req_main.content)}b > {len(req_mix.content)}b",
                        url,
                        d,
                    )
                    behavior_check = True
                if behavior_check and proxy.proxy_enabled:
                    from utils.proxy import proxy_request

                    proxy_request(
                        s,
                        "GET",
                        url,
                        headers={"User-Agent": "hexhttp v2.0 security scan"},
                        data=d,
                    )


def check_methods_poisoning(
    url: str, s: requests.Session, custom_header: dict, authent: tuple[str, str] | None
) -> None:
    try:
        url = f"{url}?cb={random.randrange(99)}"
        req_main = s.get(
            url, verify=False, allow_redirects=False, timeout=10, auth=authent
        )

        if req_main.status_code not in [403, 429]:
            len_main = len(req_main.content)
            requests_method = ["GET", "HEAD", "POST"]
            range_exlusion = (
                range(len_main - CONTENT_DELTA_RANGE, len_main + CONTENT_DELTA_RANGE)
                if len_main < 10000
                else range(
                    len_main - BIG_CONTENT_DELTA_RANGE,
                    len_main + BIG_CONTENT_DELTA_RANGE,
                )
            )

            fat_methods_poisoning(
                url,
                s,
                requests_method,
                range_exlusion,
                req_main,
                len_main,
                custom_header,
                authent,
            )
            cp_mix(
                url,
                s,
                requests_method,
                range_exlusion,
                req_main,
                len_main,
                custom_header,
                authent,
            )
        else:
            pass
    except requests.ConnectionError as ce:
        logger.error("Error, cannot connect to target", ce)
    except requests.Timeout as t:
        logger.error("Error, request timeout (10s)", t)
    except Exception as e:
        logger.exception(e)
