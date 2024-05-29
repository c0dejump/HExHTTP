#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import random
import string
import sys
import os
import traceback
import pprint
from urllib.parse import urlparse
from typing import Optional
# Local imports
from static.vuln_notify import vuln_found_notify

# To remove HTTPS warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

"""
Generate a random string used as a cache buster
"""
def generate_cache_buster(length: Optional[int] = 12) -> str:
    if not isinstance(length, int) or length <= 0:
        raise ValueError("[!] Lenght of cacheBuster be a positive integer")
    return ''.join(random.choice(string.ascii_lowercase) for i in range(length))

class Colors:
    RED = "\033[31m"
    YELLOW = "\033[33m"
    GREEN = "\033[32m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    RESET = "\033[0m"