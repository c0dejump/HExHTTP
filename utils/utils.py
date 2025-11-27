#!/usr/bin/env python3

import argparse  # noqa: F401
import random
import re  # noqa: F401
import os
import socket
import ssl
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
from bs4 import BeautifulSoup

from modules.logging_config import configure_logger  # noqa: F401


import requests.utils

def _noop_check_header_validity(header, value=None):
    return None

requests.utils.check_header_validity = _noop_check_header_validity

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = configure_logger(__name__)

CONTENT_DELTA_RANGE = 500
BIG_CONTENT_DELTA_RANGE = 5000


def get_domain_from_url(url: str) -> str:
    domain = urlparse(url).netloc
    return domain


def get_ip_from_url(url: str) -> str:
    domain = get_domain_from_url(url)
    ip = socket.gethostbyname(domain)
    return ip


"""def generate_cache_buster(length: int | None = 12) -> str:
    if not isinstance(length, int) or length <= 0:
        raise ValueError("[!] Lenght of cacheBuster be a positive integer")
    return "".join(
        random.choice(string.ascii_lowercase) for i in range(length)  # nosec B311
    )"""


def human_time(human: str) -> None:
    if human.isdigit():
        time.sleep(int(human))
    elif human.lower() == "r" or human.lower() == "random":
        time.sleep(random.randrange(6))  # nosec B311
    else:
        pass


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
    return range_exlusion

def verify_waf(initialResponse, req):
    html = req.text
    soup = BeautifulSoup(html, "html.parser")
    title = soup.title.string if soup.title else False
    amz_waf = req.headers.get("x-amzn-waf-action", "")
    if title:
        if title.lower() == "human verification":
            return True
    if amz_waf:
        if amz_waf.lower() == "captcha":
            return True
    if "verify that you are a real person" in html:
        return True
    if initialResponse.status_code != 403 and req.status_code == 403:
        print(" └── [i] Rate limit WAF activated, wait a moment (60s) or try with -hu option")
        time.sleep(60)
    else:
        return False


def new_session(base_session=None):
    s = requests.Session()

    if base_session:
        s.verify = base_session.verify
        s.max_redirects = base_session.max_redirects

        s.headers.update(base_session.headers)

        s.proxies.update(base_session.proxies)

        for prefix, adapter in base_session.adapters.items():
            s.mount(prefix, adapter)

    return s


def random_ua():
    with open("./modules/lists/user-agent.lst", "r", encoding="utf-8") as f:
        user_agents = [line.strip() for line in f if line.strip()]

    random_user_agent = {"User-Agent": random.choice(user_agents)}
    return(random_user_agent)