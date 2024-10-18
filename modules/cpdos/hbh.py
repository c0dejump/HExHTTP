#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
Attempts to find Hop-By-Hop Header abuse
https://nathandavison.com/blog/abusing-http-hop-by-hop-request-headers
"""

from modules.utils import logging, requests, generate_cache_buster

logger = logging.getLogger(__name__)

VULN_NAME = "Hop-By-Hop"

CONTENT_DELTA_RANGE = 1000
MAX_SAMPLE_STATUS = 3
MAX_SAMPLE_CONTENT = 3


def cache_poisoning(
    url, s, parameters, response_1, response_2, authentication, headers
):
    """Function to test for cache poisoning"""

    try:
        response_3 = s.get(
            url,
            params=parameters,
            auth=authentication,
            allow_redirects=False,
            verify=False,
            timeout=10,
        )
    except requests.exceptions.ConnectionError as e:
        logger.exception(e)

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
            f" \033[31m└── [VULNERABILITY CONFIRMED]\033[0m | {VULN_NAME} | \033[34m{response_2.url}\033[0m | {reason} | PAYLOAD: {payload}"
        )


def hop_by_hop(
    url,
    s,
    initial_response,
    authent,
    content_delta_range=CONTENT_DELTA_RANGE,
    max_sample_status=MAX_SAMPLE_STATUS,
    max_sample_content=MAX_SAMPLE_CONTENT,
):
    """Function to test for Hop by Hop vulnerabilities"""

    response_1 = initial_response

    response_2_previous_status = 0
    response_2_count_status_code = 0

    response_2_previous_size = 0
    response_2_count_size = 0

    with open("./modules/lists/lowercase-headers.lst", "r", encoding="utf-8") as f:
        lines = f.read().split("\n")
        for header in lines:
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
                # print(f"return: {response_2}") #DEBUG
                # print(response_2_stat) #DEBUG

                if response_2.status_code not in (
                    response_2_previous_status,
                    response_1.status_code,
                ):
                    response_2_previous_status = response_2.status_code
                    response_2_count_status_code = 0
                else:
                    response_2_count_status_code += 1

                # print(response_2_count_status_code)

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

                if (
                    len(response_1.content)
                    not in range(
                        len(response_2.content) - content_delta_range,
                        len(response_2.content) + content_delta_range,
                    )
                    and response_2.status_code not in [429, 403]
                    and response_1.status_code not in [301, 302, 429, 403]
                    and response_2_count_size < max_sample_content
                ):
                    behavior = f"DIFFERENT RESPONSE LENGTH  {len(response_1.content)}b > {len(response_2.content)}b"

                if behavior:
                    payload = f"Connection: {headers['Connection']}"
                    print(
                        f" \033[33m└── [INTERESTING BEHAVIOR]\033[0m | {VULN_NAME} | \033[34m{response_2.url}\033[0m | {behavior} | PAYLOAD: {payload}"
                    )
                    cache_poisoning(
                        url, s, parameters, response_1, response_2, authent, headers
                    )

            except requests.exceptions.ConnectionError as e:
                logger.exception(e)

            except Exception as e:
                logger.exception(e)

            print(f" \033[34m {headers}\033[0m\r", end="")
            print("\033[K", end="")
