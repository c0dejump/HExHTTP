#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Attemps to check if localhost can be scanned with Host Header
"""

from modules.utils import *

def check_localhost(url, s, domain, authent):
    list_test = ["127.0.0.1", "localhost", "192.168.0.1", "127.0.1", "127.1", "::1", "127.0.0.2", "127.0.0.1", "127.0.0.1:22", 
    "0.0.0.0", "0.0.0.0:443", "[::]:80", "127.0.0.1.nip.io", "127.127.127.127"]

    print(f"{Colors.CYAN} ├ Host analysis{Colors.RESET}")
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