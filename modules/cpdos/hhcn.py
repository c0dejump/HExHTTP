#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import traceback
import random
from urllib.parse import urlparse


requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def HHCN(url, s, authent):
    #Host Header case normalization

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

    if req_hhcn_len != req_len:
        for rf in req_hhcn.headers:
            if "cache" in rf.lower() or "age" in rf.lower():
                behavior = "DIFFERENT RESPONSE LENGTH"
                for x in range(0, 10):
                    req_hhcn_bis = s.get(url, headers=headers, verify=False, timeout=10, auth=authent, allow_redirects=False)

        req_verify = s.get(url, verify=False, timeout=10, auth=authent)

        if len(req_hhcn_bis.content) == len(req_verify.content):
            print(" \033[31m└── VULNERABILITY CONFIRMED\033[0m | HHCN | \033[34m{}\033[0m | {} {}b <> {}b | PAYLOAD: {}".format(url, behavior, req_len, len(req_hhcn_bis.content), headers))
        else:
            if behavior:
                print(" \033[33m└── INTERESTING BEHAVIOR\033[0m | HHCN | \033[34m{}\033[0m | {} {}b <> {}b | PAYLOAD: {}".format(url, behavior, req_len, req_hhcn_len, headers))

    if req_main.status_code != req_hhcn.status_code:
        for rf in req_hhcn.headers:
            if "cache" in rf.lower() or "age" in rf.lower():
                behavior = "DIFFERENT STATUS-CODE"
                for x in range(0, 10):
                    req_hhcn_bis = s.get(url, headers=headers, verify=False, timeout=10, auth=authent, allow_redirects=False)

        req_verify = s.get(url, verify=False, timeout=10, auth=authent)

        if req_hhcn_bis.status_code == req_verify.status_code:
            print(" \033[31m└── VULNERABILITY CONFIRMED\033[0m | HHCN | \033[34m{}\033[0m | {} {} <> {} | PAYLOAD: {}".format(url, behavior, req_main.status_code, req_hhcn_bis.status_code, headers))
        else:
            if behavior:
                print(" \033[33m└── INTERESTING BEHAVIOR\033[0m | HHCN | \033[34m{}\033[0m | {} {} <> {} | PAYLOAD: {}".format(url, behavior, req_main.status_code, req_hhcn.status_code, headers))


