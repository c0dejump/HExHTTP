#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
Attempts to find Hop-By-Hop Header abuse
https://nathandavison.com/blog/abusing-http-hop-by-hop-request-headers
"""

from modules.utils import requests, generate_cache_buster, configure_logger, human_time, Identify
from modules.lists import header_list

logger = configure_logger(__name__)

VULN_NAME = "Hop-By-Hop"

CONTENT_DELTA_RANGE = 500
BIG_CONTENT_DELTA_RANGE = 1000

MAX_SAMPLE_STATUS = 3
MAX_SAMPLE_CONTENT = 3


def cache_poisoning(
    url, s, parameters, response_1, response_2, authentication, headers
):
    """Function to test for cache poisoning"""

    response_3 = s.get(
        url,
        params=parameters,
        auth=authentication,
        allow_redirects=False,
        verify=False,
        timeout=10,
    )

    reason = ""
    if (
        response_3.status_code == response_2.status_code
        and response_3.status_code != response_1.status_code
        and response_3.status_code != 429
    ):
        reason = (
            f"DIFFERENT STATUS-CODE {response_1.status_code} > {response_3.status_code}"
        )
    if (
        response_3
        and response_3.content
        and len(response_3.content) == len(response_2.content)
        and len(response_3.content) != len(response_1.content)
        and response_3.status_code != 429
    ):
        reason = f"DIFFERENT RESPONSE LENGTH {len(response_1.content)}b > {len(response_3.content)}b"

    if reason:
        payload = f"Connection: {headers['Connection']}"
        print(
            f" {Identify.confirmed} | {VULN_NAME} | \033[34m{response_2.url}\033[0m | {reason} | PAYLOAD: {payload}"
        )
        #print(response_3.headers)
        #print(response_3.text)


def HBH(
    url,
    s,
    initial_response,
    authent,
    human,
    max_sample_status=MAX_SAMPLE_STATUS,
    max_sample_content=MAX_SAMPLE_CONTENT,
):
    """Function to test for Hop by Hop vulnerabilities"""

    logger.debug("Testing for %s vulnerabilities", VULN_NAME)

    response_1 = initial_response

    response_2_previous_status = 0
    response_2_count_status_code = 0

    response_2_previous_size = 0
    response_2_count_size = 0

    for header in header_list:
        headers = {"Connection": f"keep-alive, {header}"}
        parameters = {"cacheBuster": generate_cache_buster()}
        try:
            response_2 = s.get(
                url,
                headers=headers,
                params=parameters,
                auth=authent,
                allow_redirects=False,
                verify=False,
                timeout=10,
            )
            logger.debug("return: %s", response_2)  # DEBUG
            logger.debug(response_2_previous_status)  # DEBUG

            if response_2.status_code not in (
                response_2_previous_status,
                response_1.status_code,
            ):
                response_2_previous_status = response_2.status_code
                response_2_count_status_code = 0
            else:
                response_2_count_status_code += 1

            logger.debug(response_2_count_status_code)

            if (
                len(response_2.content) != response_2_previous_size
                and len(response_2.content) != 0
            ):
                response_2_previous_size = len(response_2.content)
                response_2_count_size = 0
            else:
                response_2_count_size += 1

            behavior = ""
            if (
                response_1.status_code != response_2.status_code
                and response_2.status_code not in [429, 403]
                and response_1.status_code not in [301, 302, 429, 403]
                and response_2_count_status_code < max_sample_status
            ):
                behavior = f"DIFFERENT STATUS-CODE  {response_1.status_code} > {response_2.status_code}"

            len_main = len(response_1.content)
            range_exlusion = range(len_main - CONTENT_DELTA_RANGE, len_main + CONTENT_DELTA_RANGE) if len_main < 10000 else range(len_main - BIG_CONTENT_DELTA_RANGE, len_main + BIG_CONTENT_DELTA_RANGE)
           
            if (
                len(response_1.content) not in range_exlusion
                and response_2.status_code not in [429, 403]
                and response_1.status_code not in [301, 302, 429, 403]
                and response_2_count_size < max_sample_content
            ):
                behavior = f"DIFFERENT RESPONSE LENGTH  {len_main}b > {len(response_2.content)}b"

            if behavior:
                payload = f"Connection: {headers['Connection']}"
                print(
                    f" {Identify.behavior} | {VULN_NAME} | \033[34m{response_2.url}\033[0m | {behavior} | PAYLOAD: {payload}"
                )
                cache_poisoning(
                    url, s, parameters, response_1, response_2, authent, headers
                )
            human_time(human)

        except requests.exceptions.ConnectionError as e:
            logger.exception(e)

        print(f" \033[34m {VULN_NAME} : {headers}\033[0m\r", end="")
        print("\033[K", end="")
