#!/usr/bin/env python3

"""
Attempts to find Cache Poisoning with HTTP Metachar Character (HMC)
https://cpdos.org/#HMC
"""

from utils.style import Colors
from utils.utils import configure_logger, random, requests
from modules.global_requests import send_global_requests

logger = configure_logger(__name__)

VULN_NAME = "HTTP Meta Character"



def HMC(
    url: str,
    s: requests.Session,
    initialResponse: requests.Response,
    authent: tuple[str, str] | None,
    fp_results: tuple[int, int] | None,
    human: str,
) -> None:  # pylint: disable=invalid-name
    """Prepare the list of meta characters to check for"""

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
        r"\u00A0",
        r"\u202E",
        r"\x0b",
        r"\x0c",
        r"\x7f",
        r"\x1b[31mred\x1b[0m",
        
    ]
    for meta_character in meta_characters:
        try:
            uri = f"{url}{random.randrange(999)}"
            
            probe_headers = {"X-Metachar-Header": meta_character}
            
            send_global_requests(uri, s, authent, fp_results, VULN_NAME, human, probe_headers, initialResponse)

            print(f" {Colors.BLUE} {VULN_NAME} : {meta_character}{Colors.RESET}\r", end="")
            print("\033[K", end="")

        except requests.exceptions.ConnectionError as e:
            logger.exception(e)
