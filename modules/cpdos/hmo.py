#!/usr/bin/env python3

"""
Attempts to find Cache Poisoning with HTTP Method Override (HMO)
https://cpdos.org/#HMO
"""

from utils.style import Colors
from utils.utils import configure_logger, random, requests
from modules.global_requests import send_global_requests
from modules.lists.methods_list import methods


logger = configure_logger(__name__)


def HMO(
    url: str,
    s: requests.Session,
    initialResponse: requests.Response,
    authent: tuple[str, str] | None,
    fp_results: tuple[int, int] | None,
    human: str,
) -> None:
    VULN_NAME = "HMO"
    """Function to test for HTTP Method Override vulnerabilities"""

    logger.debug("Testing for %s vulnerabilities", VULN_NAME)


    hmo_headers = [
        "HTTP-Method-Override",
        "X-HTTP-Method-Override",
        "X-Method-Override",
        "Method-Override",
        "X-HTTP-Method",
        "HTTP-Method",
        "_method",
        "_methodOverride",
        "X-Requested-Method",
        "X-HTTP-Verb",
        "Request-Method",
        "Override-Method",
        "X-Method",
        "Method",
        "X-Verb",
        "Verb-Override",
        "HTTP-Verb",
        "X-Override",
        "Override",
        "X-Action",
        "Action-Override",
        "X-Request-Method",
        "Request-Override",
        "X-Tunnel-Method",
        "Tunnel-Method",
        "X-Real-Method",
        "Real-Method",
        "X-Original-Method",
        "Original-Method",
        "X-Forward-Method",
        "Forward-Method",
        "X-Proxy-Method",
        "Proxy-Method",
        "_method"
    ]

    for header, method in (
        (header, method) for header in hmo_headers for method in methods
    ):

        try:
            uri = f"{url}{random.randrange(999)}"

            probe_headers = {header: method}

            send_global_requests(uri, s, authent, fp_results, VULN_NAME, human, probe_headers, initialResponse)

            print(f" {Colors.BLUE} {VULN_NAME} : {probe_headers}{Colors.RESET}\r", end="")
            print("\033[K", end="")

        except requests.exceptions.ConnectionError as e:
            #print(e)
            logger.exception(e)

    # Test _method as query parameter
    for method in methods:
        try:
            # Append ?_method=<method>&_cb= so send_global_requests appends UUID as cache buster value
            uri_base = f"{url}?_method={method}&_cb={random.randrange(999)}"

            send_global_requests(uri_base, s, authent, fp_results, VULN_NAME, human, {}, initialResponse)

            print(f" {Colors.BLUE} {VULN_NAME} : ?_method={method}{Colors.RESET}\r", end="")
            print("\033[K", end="")

        except requests.exceptions.ConnectionError as e:
            logger.exception(e)