#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional
from urllib.parse import urlparse
import string
import logging
import random
import sys
import urllib3

# import os
import traceback
import pprint
import re

import requests

# Local imports
from static.vuln_notify import vuln_found_notify

# """configuring overal how the loggin is done"""
# logging.basicConfig(
#     filename=strftime("./logs/%Y%m%d_%H%M.log"),
#     format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
# )

# To remove HTTPS warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def generate_cache_buster(length: Optional[int] = 12) -> str:
    """Generate a random string used as a cache buster"""

    if not isinstance(length, int) or length <= 0:
        raise ValueError("[!] Lenght of cacheBuster be a positive integer")
    return "".join(random.choice(string.ascii_lowercase) for i in range(length))


def configure_logger(
    module_name: str, handler: logging.Handler = logging.NullHandler()
) -> logging.Logger:
    """Provides a logger instance set to the module provided with a default handler"""

    logger = logging.getLogger(module_name)
    logger.addHandler(handler)
    logger.propagate = False
    return logger


class Colors:
    """Colors constants for the output messages"""

    RED = "\033[31m"
    YELLOW = "\033[33m"
    GREEN = "\033[32m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    RESET = "\033[0m"
