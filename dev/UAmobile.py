#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import sys
import random
import traceback
import pprint

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def uacache(url, s, req_main, ua):
    pass
    #TODO


def uamobile(url, s):
    with open("./lists/mobile-user-agent.lst") as mua:
        len_content_modif = 0
        len_header_modif = 0
        for ua in mua.read().splitlines():
            try:
                req_main = s.get(url, verify=False, timeout=10)
                req = s.get(url, headers={"User-Agent":ua}, verify=False, timeout=10)
                #pprint.pprint(req.content)

                if len(req.content) not in range(len(req_main.content) - 70, len(req_main.content) + 70) and len(req.content) not in range(len_content_modif - 70, len_content_modif + 70):
                    print(f"   └── [C][{req_main.status_code} > {req.status_code}][{len(req_main.content)}b > {len(req.content)}b] :: {ua}\n")
                    len_modif = len(req.content)
                elif len(req.headers) not in range(len(req_main.headers) - 5, len(req_main.headers) + 5) and len(req.headers) not in range(len_header_modif - 5, len_header_modif + 5):
                    #pass
                    print(f"   └── [H][{req_main.status_code > req.status_code}][{len(req_main.headers)}b > {len(req.headers)}b] :: {ua}\n")
                    len_header_modif = len(req.headers)
                uacache(url, s, req_main, ua)
            except KeyboardInterrupt:
                print("Exiting")
                sys.exit()
            except Exception as e:
                #print(f"Error : {e}")
                pass


if __name__ == '__main__':
    url_file = sys.argv[1]
    s = requests.Session()
    uamobile(url_file, s)
    """with open(url_file, "r") as urls:
        urls = urls.read().splitlines()
        for url in urls:
            uamobile(url, s)"""