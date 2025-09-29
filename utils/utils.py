#!/usr/bin/env python3

import argparse  # noqa: F401
import random
import re  # noqa: F401
import socket
import string
import sys
import time
import traceback  # noqa: F401
from urllib.parse import (
    urljoin,  # noqa: F401
    urlparse,
)

import requests
import urllib3

from modules.logging_config import configure_logger  # noqa: F401
from utils.style import Colors

import requests.utils

def _noop_check_header_validity(header, value=None):
    return None

requests.utils.check_header_validity = _noop_check_header_validity

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = configure_logger(__name__)

CONTENT_DELTA_RANGE = 500
BIG_CONTENT_DELTA_RANGE = 5000


def format_payload(payload: dict[str, str], max_length: int = 60) -> str:
    """Format payload dictionary with truncated keys and values for readable output"""
    formatted_items = []
    for key, value in payload.items():
        # Truncate key if it's too long
        if len(key) > max_length:
            truncated_key = f"{key[:max_length]}...({len(key)} chars total)"
        else:
            truncated_key = key

        # Truncate value if it's too long
        if len(value) > max_length:
            truncated_value = f"{value[:max_length]}...({len(value)} chars total)"
        else:
            truncated_value = value

        formatted_items.append(f"'{truncated_key}': '{truncated_value}'")
    return "{" + ", ".join(formatted_items) + "}"


def get_domain_from_url(url: str) -> str:
    domain = urlparse(url).netloc
    return domain


def get_ip_from_url(url: str) -> str:
    domain = get_domain_from_url(url)
    ip = socket.gethostbyname(domain)
    return ip


def generate_cache_buster(length: int | None = 12) -> str:
    if not isinstance(length, int) or length <= 0:
        raise ValueError("[!] Lenght of cacheBuster be a positive integer")
    return "".join(
        random.choice(string.ascii_lowercase) for i in range(length)  # nosec B311
    )


def human_time(human: str) -> None:
    if human.isdigit():
        time.sleep(int(human))
    elif human.lower() == "r" or human.lower() == "random":
        time.sleep(random.randrange(6))  # nosec B311
    else:
        pass


def cache_tag_verify(req: requests.Response) -> str:
    cachetag = False
    for rh in req.headers:
        if "age" in rh.lower() or "hit" in rh.lower() or "cache" in rh.lower():
            cachetag = True
        else:
            pass
    colored_cachetag = (
        f"{Colors.GREEN}" if cachetag else f"{Colors.RED}"
    ) + f"{str(cachetag)}{Colors.RESET}"
    return colored_cachetag


def check_auth(auth: str, url: str) -> tuple[str, str] | None:
    try:
        authent = (auth.split(":")[0], auth.split(":")[1])
        r = requests.get(
            url,
            allow_redirects=False,
            verify=False,
            auth=authent,
            timeout=10,  # nosec B501
        )
        if r.status_code in [200, 302, 301]:
            print("\n+ Authentication successful\n")
            return authent
        else:
            print("\nAuthentication error")
            continue_error = input("The authentication seems bad, continue ? [y/N]")
            if continue_error not in ["y", "Y"]:
                print("Exiting")
                sys.exit()
            else:
                return None
    except Exception as e:
        print('Error, the authentication format need to be "user:pass"')
        logger.exception(e)
        sys.exit()


def range_exclusion(main_len):
    range_exlusion = (
        range(main_len - CONTENT_DELTA_RANGE, main_len + CONTENT_DELTA_RANGE)
        if main_len < 10000
        else range(
            main_len - BIG_CONTENT_DELTA_RANGE,
            main_len + BIG_CONTENT_DELTA_RANGE,
        )
    )