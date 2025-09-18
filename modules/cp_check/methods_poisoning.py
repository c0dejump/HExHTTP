#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Methods poisoning
"""

from utils.utils import requests, random, configure_logger, human_time, CONTENT_DELTA_RANGE, BIG_CONTENT_DELTA_RANGE
from utils.style import Identify, Colors
import traceback
import utils.proxy as proxy

logger = configure_logger(__name__)

VULN_NAME = "Fat Methods"

def print_result(status, vuln, method, reason, reason_result, url, payload):
    if payload:
        print(
            f" {status} | {vuln} {method} | {reason} {reason_result} | \033[34m{url}\033[0m | PAYLOAD: {Colors.THISTLE}{method} with {payload}{Colors.RESET}"
            )
    else:
        print(
            f" {status} | {vuln} {method} | {reason} {reason_result} | \033[34m{url}\033[0m | PAYLOAD: {Colors.THISTLE}{method}{Colors.RESET}"
        ) 


def verify_fat_get_poisoning(s, url, d, rm, req_main, len_main, authent):
    for _ in range(5):
        req_verify = s.request(rm, url=url, data=d, verify=False, allow_redirects=False, timeout=10, auth=authent)
    req_main_check = s.get(url, verify=False, allow_redirects=False, timeout=10, auth=authent)

    if req_verify.status_code == req_main_check.status_code and req_main_check.status_code != req_main.status_code:
        print_result(Identify.confirmed, "FAT", "{}".format(rm), "DIFFERENT STATUS-CODE", "{} > {}".format(req_main.status_code, req_verify.status_code), url, d)
    elif len(req_verify.content) == len(req_main_check.content) and len(req_main_check.content) != len_main:
        print_result(Identify.confirmed, "FAT", "{}".format(rm), "DIFFERENT RESP LENGTH", "{}b > {}b".format(len_main, len(req_verify.content)), url, d)
    elif d in req_main_check.text or "codejump" in req_main_check.text:
        print_result(Identify.confirmed, "FAT", "{}".format(rm), "BODY REFLECTION", "", url, d)
    elif d in req_main_check.headers or "codejump" in req_main_check.headers:
        print_result(Identify.confirmed, "FAT",  "{}".format(rm), "HEADERS REFLECTION", "", url, d)


def fat_methods_poisoning(url, s, requests_method, range_exlusion, req_main, len_main, custom_header, authent):
    body_datas = [
        'data=codejump',
        '{ "test": "codejump" }'
        ]

    for d in body_datas:
        for rm in requests_method:
            url = f"{url}{random.randrange(99)}"
            req_fg = s.request(rm, url=url, data=d, verify=False, allow_redirects=False, timeout=10, auth=authent)
            len_fg = len(req_fg.content)
            behavior_check = False

            if req_fg.status_code != req_main.status_code:
                print_result(Identify.behavior, "FAT" ,"{}".format(rm), "DIFFERENT STATUS-CODE", "{} > {}".format(req_main.status_code, req_fg.status_code), url, d)
                behavior_check = True
                verify_fat_get_poisoning(s, url, d, rm, req_main, len_main, authent)
            elif len_fg not in range_exlusion:
                print_result(Identify.behavior, "FAT", "{}".format(rm), "DIFFERENT RESP LENGTH", "{}b > {}b".format(req_main.status_code, len_fg), url, d)
                behavior_check = True
                verify_fat_get_poisoning(s, url, d, rm, req_main, len_main, authent)
            elif d in req_fg.text or "codejump" in req_fg.text:
                print_result(Identify.behavior, "FAT", "{}".format(rm), "BODY REFLECTION", "", url, d)
                behavior_check = True
                verify_fat_get_poisoning(s, url, d, rm, req_main, len_main, authent)
            elif d in req_fg.headers or "codejump" in req_fg.headers:
                print_result(Identify.behavior, "FAT", "{}".format(rm), "HEADERS REFLECTION", "", url, d)
                behavior_check = True
                verify_fat_get_poisoning(s, url, d, rm, req_main, len_main, authent)
            if behavior_check and proxy.proxy_enabled:
                from utils.proxy import proxy_request
                proxy_request(s, "GET", url, headers={"User-Agent": "hexhttp"}, data=d)


def cp_mix(url, s, requests_method, range_exlusion, req_main, len_main, custom_header, authent):
    if req_main.status_code not in [403, 429]:
        for rm in requests_method:
            behavior_check = False
            url = f"{url}{random.randrange(99)}"

            if rm == "POST":
                body_datas = [
                    'data=codejump',
                    '{ "test": "codejump" }'
                    ]
                for d in body_datas:
                    req_mix = s.request(rm, url=url, data=d, verify=False, allow_redirects=False, timeout=10, auth=authent)
            else:
                req_mix = s.request(rm, url=url, verify=False, allow_redirects=False, timeout=10, auth=authent)
                d = False

            req_get = s.get(url, auth=authent)
            if req_mix.status_code != req_get.status_code:
                print_result(Identify.behavior, "MIX", "{} <> GET".format(rm), "DIFFERENT STATUS-CODE", "{} > {}".format(req_main.status_code, req_mix.status_code), url, d)
                behavior_check = True
            elif len(req_mix.content) not in range_exlusion and len(req_mix.content) != len(req_get.content):
                print_result(Identify.behavior, "MIX", "{} <> GET".format(rm), "DIFFERENT RESP LENGTH", "{}b > {}b".format(len(req_main.content), len(req_mix.content)), url, d)
                behavior_check = True
            if behavior_check and proxy.proxy_enabled:
                from utils.proxy import proxy_request
                proxy_request(s, "GET", url, headers={"User-Agent": "hexhttp v2.0 security scan"}, data=d)


def check_methods_poisoning(url, s, custom_header, authent):
    try:
        url = f"{url}?cb={random.randrange(99)}"
        req_main = s.get(url, verify=False, allow_redirects=False, timeout=10, auth=authent)

        if req_main.status_code not in [403, 429]:
            len_main = len(req_main.content)
            requests_method = ["GET", "HEAD", "POST"]
            range_exlusion = range(len_main - CONTENT_DELTA_RANGE, len_main + CONTENT_DELTA_RANGE) if len_main < 10000 else range(len_main - BIG_CONTENT_DELTA_RANGE, len_main + BIG_CONTENT_DELTA_RANGE)

            fat_methods_poisoning(url, s, requests_method, range_exlusion, req_main, len_main, custom_header, authent)
            cp_mix(url, s, requests_method, range_exlusion, req_main, len_main, custom_header, authent)
        else:
            pass
    except requests.ConnectionError:
        print("Error, cannot connect to target")
    except requests.Timeout:
        print("Error, request timeout (10s)")
    except Exception as e:
        print(e)
        #pass
        traceback.print_exc()