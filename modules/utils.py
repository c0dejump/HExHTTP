#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional
from urllib.parse import urlparse
from modules.logging_config import configure_logger

import string
import logging
import random
import sys
import urllib3

# import os
import traceback
import pprint
import re
import time

import requests

# Local imports
#from static.vuln_notify import vuln_found_notify

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_domain_from_url(url: str) -> str:
    """
    Extracts the domain from a given URL.

    Args:
        url (str): The URL from which to extract the domain.

    Returns:
        str: The domain extracted from the URL.
    """
    domain = urlparse(url).netloc
    return domain


def generate_cache_buster(length: Optional[int] = 12) -> str:
    """Generate a random string used as a cache buster"""

    if not isinstance(length, int) or length <= 0:
        raise ValueError("[!] Lenght of cacheBuster be a positive integer")
    return "".join(random.choice(string.ascii_lowercase) for i in range(length))


def human_time(human):
    #print(human)
    if human.isdigit():
        time.sleep(int(human))
    elif human == "r" or human == "random" or human == "R":
            time.sleep(random.randrange(6))
    else:
        pass

class Colors:
    """Colors constants for the output messages"""

    RED = "\033[31m"
    YELLOW = "\033[33m"
    GREEN = "\033[32m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    RESET = "\033[0m"

class Identify:
    behavior = "\033[33m└── [INTERESTING BEHAVIOR]\033[0m"
    confirmed = "\033[31m└── [VULNERABILITY CONFIRMED]\033[0m"