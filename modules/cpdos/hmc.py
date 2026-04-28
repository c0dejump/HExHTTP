#!/usr/bin/env python3

"""
Attempts to find Cache Poisoning with HTTP Metachar Character (HMC)
https://cpdos.org/#HMC
"""

from utils.style import Colors
from utils.utils import configure_logger, random, requests
from modules.global_requests import send_global_requests

logger = configure_logger(__name__)

VULN_NAME = "HMC"



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
        r"\x01", 
        r"\x02", 
        r"\x03", 
        r"\x04", 
        r"\x05", 
        r"\x06", 
        r"\x1c", 
        r"\x1d", 
        r"\x1e", 
        r"\x1f", 
        r"\x85", 
        r"\xc0\x80",
        r"\xe0\x80\x80",  
        r"\xf0\x80\x80\x80", 
        r"\xed\xa0\x80",  
        r"\xef\xbf\xbe",  
        r"\xef\xbf\xbf",  
        r"\u2028",  
        r"\u2029",  
        r"\ufeff",  
        r":", 
        r"CR\rLF\n",
        r"\r\n\r\n",  
        r"\x00\x00\x00\x00",    
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
