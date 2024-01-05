#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import traceback
#from static.vuln_notify import vuln_found_notify

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def forwarded_port(url):
    headers = {
        "X-Forwarded-Port": 12345
        }
    try:
        req = requests.get(url, headers=headers, verify=False, timeout=10)
        print(req)
        if "12345" in  req.text:
            print("plop !")
    except:
        traceback.print_exc()



if __name__ == '__main__':
    url = "https://www.sosh.re/?cb=9876"
    forwarded_port(url)