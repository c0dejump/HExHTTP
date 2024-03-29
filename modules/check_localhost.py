#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import traceback

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def check_localhost(url, s, domain, authent):
    """
    Check_localhost: Function which try automatically if it's possible scanning with "localhost" host for discovery other files/directories
    """
    list_test = ["127.0.0.1", "localhost", "192.168.0.1", "127.0.1", "127.1", "::1", "127.0.0.2", "127.0.0.1", "127.0.0.1:22", 
    "0.0.0.0", "0.0.0.0:443", "[::]:80", "127.0.0.1.nip.io", "127.127.127.127"]

    print("\033[36m ├ Host analyse\033[0m")
    for lt in list_test:
        headers = {"Host": lt}
        try:
            req = s.get(url, headers=headers, verify=False, allow_redirects=False, timeout=10)
            if req.status_code in [301, 302]:
                try:
                    req_redirect = s.get(url, headers=headers, verify=False, allow_redirects=True, timeout=10, auth=authent)
                    print(f" └── Host: {lt:<13}{'→':^3} {req.status_code:>3}{'→':^3}{req.headers['location']}")
                except:
                    print(f" └── Host: {lt:<13}{'→':^3} {req.status_code:>3}{'→':^3}{req.headers['location']}")
            else:
                print(f" └── Host: {lt:<13}{'→':^3} {req.status_code:>3} [{len(req.content)} bytes]")
        except:
            #traceback.print_exc() 
            pass