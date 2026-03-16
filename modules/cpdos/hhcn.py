#!/usr/bin/env python3

"""
Attempts to find Cache Poisoning with Host Header Case Normalization (HHCN)
https://youst.in/posts/cache-key-normalization-denial-of-service/
"""

from utils.style import Colors, Identify
from utils.utils import configure_logger, get_domain_from_url, random, requests
from modules.global_requests import send_global_requests

logger = configure_logger(__name__)

VULN_NAME = "HHCN"


def random_domain_capitalization(url: str) -> str:
    """Randomly capitalize characters from the url domain"""

    domain = get_domain_from_url(url)

    index = random.randint(0, len(domain) - 3)
    letter = domain[index]

    if letter != "." and letter != "-":
        letter = domain[index].upper()
    else:
        index = max(0, index - 1)
        letter = domain[index].upper()

    domain = domain[:index] + letter + domain[index + 1 :]
    return domain


def unicode_confusable(domain: str) -> str:
    """Replace characters with unicode confusables"""

    replacements = {
        "e": "е",  # cyrillic
        "a": "а",  # cyrillic
        "o": "ο",  # greek
        "p": "ρ",  # greek
        "l": "ⅼ",  # roman numeral
    }

    for k, v in replacements.items():
        if k in domain:
            return domain.replace(k, v, 1)

    return domain


def generate_headers(url: str) -> list[dict]:
    """Generate Host normalization payloads"""

    domain = get_domain_from_url(url)

    headers_list = []

    # -------------------------
    # Case normalization
    # -------------------------

    headers_list.append({"Host": random_domain_capitalization(url)})
    headers_list.append({"Host": domain.upper()})
    headers_list.append({"Host": domain.lower()})
    headers_list.append({"Host": domain.swapcase()})
 
    # -------------------------
    # Whitespace normalization
    # -------------------------
 
    headers_list.append({"Host": f" {domain}"})
    headers_list.append({"Host": f"{domain} "})
    headers_list.append({"Host": f"\t{domain}"})
    headers_list.append({"Host": f"{domain}\t"})
    headers_list.append({"Host": f"\x0b{domain}"})   # vertical tab
    headers_list.append({"Host": f"\x0c{domain}"})   # form feed
    headers_list.append({"Host": f"\xa0{domain}"})   # non-breaking space
    headers_list.append({"Host": f" \t{domain}"})
    headers_list.append({"Host": f"\t {domain}"})
 
    # -------------------------
    # Dot normalization
    # -------------------------
 
    headers_list.append({"Host": f"{domain}."})
    headers_list.append({"Host": f"{domain}.."})
    headers_list.append({"Host": f".{domain}"})
    headers_list.append({"Host": f"..{domain}"})
 
    # -------------------------
    # Multiple dots
    # -------------------------
 
    headers_list.append({"Host": domain.replace(".", "..", 1)})
    headers_list.append({"Host": domain.replace(".", "...", 1)})
 
    # -------------------------
    # Port normalization
    # -------------------------
 
    headers_list.append({"Host": f"{domain}:80"})
    headers_list.append({"Host": f"{domain}:443"})
    headers_list.append({"Host": f"{domain}:00080"})
    headers_list.append({"Host": f"{domain}:000443"})
    headers_list.append({"Host": f"{domain}:65535"})
    headers_list.append({"Host": f"{domain}:0"})
    headers_list.append({"Host": f"{domain}:8080"})   # common alternate HTTP port
    headers_list.append({"Host": f"{domain}:8443"})   # common alternate HTTPS port
    headers_list.append({"Host": f"{domain}:1337"})   # arbitrary non-standard port
 
    # CDN parsing edge case
    headers_list.append({"Host": f"{domain}:443."})
 
    # -------------------------
    # Slash confusion
    # -------------------------
 
    headers_list.append({"Host": f"{domain}/"})
    headers_list.append({"Host": f"{domain}//"})
 
    # -------------------------
    # Unicode host confusion
    # -------------------------
 
    headers_list.append({"Host": unicode_confusable(domain)})
 
    # -------------------------
    # Punycode / IDNA edge cases
    # Note: these are not valid punycode — they test parser tolerance only.
    # -------------------------
 
    headers_list.append({"Host": f"xn--{domain.replace('.', '-')}"})
    headers_list.append({"Host": f"xn--{domain.replace('.', '')}-test"})
 
    # -------------------------
    # IPv6 normalization
    # -------------------------
 
    headers_list.append({"Host": "[::1]"})
    headers_list.append({"Host": "[::ffff:127.0.0.1]"})
    headers_list.append({"Host": f"[::1]:{domain.split(':')[-1]}" if ':' in domain else "[::1]:80"})
 

    return headers_list


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

    headers_payloads = generate_headers(url)

    for probe_headers in headers_payloads:

        try:

            send_global_requests(
                url,
                s,
                authent,
                fp_results,
                VULN_NAME,
                human,
                probe_headers,
                initialResponse,
            )

            print(
                f" {Colors.BLUE} {VULN_NAME} : {probe_headers}{Colors.RESET}\r",
                end="",
            )
            print("\033[K", end="")

        except requests.exceptions.ConnectionError as e:
            logger.exception(e)