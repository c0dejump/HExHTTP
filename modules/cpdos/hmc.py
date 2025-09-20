#!/usr/bin/env python3

"""
Attempts to find Cache Poisoning with HTTP Metachar Character (HMC)
https://cpdos.org/#HMC
"""

import utils.proxy as proxy
from utils.style import Colors, Identify
from utils.utils import configure_logger, human_time, random, requests

logger = configure_logger(__name__)

VULN_NAME = "HTTP Meta Character"


def check_meta_character(
    url: str,
    s: requests.Session,
    main_status_code: int,
    authent: tuple[str, str] | None,
    meta_character: str,
    human: str,
) -> None:
    """Probe and Verify the server for a meta character vulnerability"""

    logger.debug("Testing for %s vulnerabilities", VULN_NAME)

    url = f"{url}{random.randrange(99)}"
    headers = {"X-Metachar-Header": meta_character}
    probe = s.get(
        url,
        headers=headers,
        timeout=10,
        verify=False,
        auth=authent,
        allow_redirects=False,
    )

    reason = ""
    if probe.status_code in [400, 413, 500] and probe.status_code != main_status_code:
        control = s.get(url, verify=False, timeout=10, auth=authent)
        if (
            control.status_code == probe.status_code
            and control.status_code != main_status_code
        ):
            reason = (
                f"{Colors.BLUE}{main_status_code} > {control.status_code}{Colors.RESET}"
            )

    if reason:
        payload = f"PAYLOAD: {headers}"
        print(
            f" {Identify.confirmed} | HMC | {Colors.BLUE}{url}{Colors.RESET} | {reason} | {Colors.THISTLE}{payload}{Colors.RESET}"
        )
        if proxy.proxy_enabled:
            from utils.proxy import proxy_request

            proxy_request(
                s, "GET", url, headers=headers, data=None, severity="confirmed"
            )
    human_time(human)


def HMC(
    url: str,
    s: requests.Session,
    req_main: requests.Response,
    authent: tuple[str, str] | None,
    human: str,
) -> None:  # pylint: disable=invalid-name
    """Prepare the list of meta characters to check for"""
    main_status_code = req_main.status_code

    meta_characters = [
        r"\n",
        r"\a",
        r"\r",
        r"\0",
        r"\b",
        r"\e",
        r"\v",
        r"\f",
        r"\u0000",
        r"\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07metahttptest",
    ]
    for meta_character in meta_characters:
        try:
            check_meta_character(
                url, s, main_status_code, authent, meta_character, human
            )

        except requests.exceptions.ConnectionError as e:
            logger.exception(e)

        print(f" {Colors.BLUE} {VULN_NAME} : {meta_character}{Colors.RESET}\r", end="")
        print("\033[K", end="")
