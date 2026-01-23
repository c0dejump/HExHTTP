#!/usr/bin/env python3

"""
Attempts to find Cache Poisoning with Host Header Case Normalization (HHCN)
https://youst.in/posts/cache-key-normalization-denial-of-service/
"""


from utils.style import Colors, Identify
from utils.utils import configure_logger, get_domain_from_url, random, requests
from modules.global_requests import send_global_requests

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
    initialResponse: requests.Response,
    authent: tuple[str, str] | None,
    fp_results: tuple[int, int] | None,
    human: str,
) -> None:
    """Attempts to find Cache Poisoning with Host Header Case Normalization"""

    logger.debug("Testing for %s vulnerabilities", VULN_NAME)

    probe_headers = {"Host": random_domain_capitalization(url)}

    try:
        send_global_requests(url, s, authent, fp_results, VULN_NAME, human, probe_headers, initialResponse)

        print(f" {Colors.BLUE} {VULN_NAME} : {probe_headers}{Colors.RESET}\r", end="")
        print("\033[K", end="")
    except requests.exceptions.ConnectionError as e:
        logger.exception(e)
