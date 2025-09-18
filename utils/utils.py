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
import yaml
import socket

# Local imports
#from static.vuln_notify import vuln_found_notify

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONTENT_DELTA_RANGE = 500
BIG_CONTENT_DELTA_RANGE = 5000


def get_domain_from_url(url):
    domain = urlparse(url).netloc
    return domain

def get_ip_from_url(url):
    domain = get_domain_from_url(url)
    ip = socket.gethostbyname(domain)
    return ip


def generate_cache_buster(length: Optional[int] = 12) -> str:
    if not isinstance(length, int) or length <= 0:
        raise ValueError("[!] Lenght of cacheBuster be a positive integer")
    return "".join(random.choice(string.ascii_lowercase) for i in range(length))


def human_time(human):
    #print(human)
    if human.isdigit():
        time.sleep(int(human))
    elif human.lower() == "r" or human.lower() == "random":
            time.sleep(random.randrange(6))
    else:
        pass

def cache_tag_verify(req):
    cachetag = False
    for rh in req.headers:
        if "age" in rh.lower() or "hit" in rh.lower() or "cache" in rh.lower():
            cachetag = True
        else:
            pass
    cachetag = f"\033[32m{cachetag}\033[0m" if cachetag else f"\033[31m{cachetag}\033[0m"
    return cachetag


def check_auth(auth, url):
    try:
        authent = (auth.split(":")[0], auth.split(":")[1])
        r = requests.get(
            url, allow_redirects=False, verify=False, auth=authent, timeout=10
        )
        if r.status_code in [200, 302, 301]:
            print("\n+ Authentication successfull\n")
            return authent
        else:
            print("\nAuthentication error")
            continue_error = input(
                "The authentication seems bad, continue ? [y/N]"
            )
            if continue_error not in ["y", "Y"]:
                print("Exiting")
                sys.exit()
    except Exception as e:
        traceback.print_exc()
        print('Error, the authentication format need to be "user:pass"')
        sys.exit()