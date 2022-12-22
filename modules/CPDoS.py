#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import traceback



def check_CPDoS(url, s, req_main, domain):
    i = 0
    redirect_req = False

    if req_main.status_code in [301, 302]:
        url = req_main.headers['location'] if "http" in req_main.headers['location'] else "{}{}".format(url, req_main.headers['location'])
    print("\033[36m ├ CPDoS analyse\033[0m")
    url = "{}?CPDoS=1".format(url)
    headers = {"Host":"{}:1234".format(domain)}
    try:
        req_cpdos = s.get(url, headers=headers, verify=False, allow_redirects=False, timeout=10)
        if req_cpdos.status_code in [301, 302, 303, 421]:
            print(" ├ {} + [\033[33m{}\033[0m] → \033[33m{}\033[0m".format(url, headers, req_cpdos.status_code))
            #print(" └── CPDos exploit seem to be possible, next test...")
            redirect_req = True
    except requests.exceptions.Timeout:
        print(" └── \033[31m{} seem to timout, CPDos exploit seem to be possible\033[0m")
        return True
    if "Location" in req_cpdos.headers:
        for rch in req_cpdos.headers:
            if rch == "Location":
                print(" └── Location:  {}".format(req_cpdos.headers[rch]))
                #return True
    if redirect_req:
        print(" --\033[36m├ Check if {} timeout...\033[0m".format(url))

        url_timeout = False
        n_timout = 0
        while i != 10:
            i += 1
            try:
                req_cpdos = s.get(url, verify=False, allow_redirects=False, timeout=6)
                response_time = req_cpdos.elapsed.total_seconds()
                if response_time > 1.5:
                    n_timout += 1
            except requests.exceptions.Timeout:
                print("   └── \033[31m{} seem to timout, CPDos exploit seem to be possible\033[0m".format(url))
                url_timeout = True
        if n_timout > 1:
            print("   └── \033[33m{} answered {}/10 at more than 1,5scd, CPDos exploit seem to be possible !\033[0m".format(url, n_timout))
            url_timeout = True
        if not url_timeout:
            print("   └── Not seem timeout, you can check manually if the exploit is possible")