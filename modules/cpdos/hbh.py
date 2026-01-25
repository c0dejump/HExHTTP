#!/usr/bin/python3

"""
Attempts to find Hop-By-Hop Header abuse
https://nathandavison.com/blog/abusing-http-hop-by-hop-request-headers
"""

from modules.lists import wcp_headers
from utils.style import Colors
from utils.utils import (
    configure_logger,
    requests,
    random,
    random_ua,
)
from modules.global_requests import send_global_requests

logger = configure_logger(__name__)

VULN_NAME = "HBH"


def HBH(
    url: str,
    s: requests.Session,
    initialResponse: requests.Response,
    authent: tuple[str, str] | None,
    fp_results: tuple[int, int] | None,
    human: str,
) -> None:
    """Function to test for Hop by Hop vulnerabilities"""

    logger.debug("Testing for %s vulnerabilities", VULN_NAME)

    for header in wcp_headers:
        try:
            uri = f"{url}{random.randrange(9999)}"

            probe_headers = {"Connection": f"keep-alive, {header}"}

            send_global_requests(uri, s, authent, fp_results, VULN_NAME, human, probe_headers, initialResponse)

            print(f" {Colors.BLUE} {VULN_NAME} : {probe_headers}{Colors.RESET}\r", end="")
            print("\033[K", end="")
 
        except requests.exceptions.ConnectionError as e:
            logger.exception(e)
