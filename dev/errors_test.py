#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import sys
import random
import traceback
from pprint import pprint

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def get_error(url, s, main_status_code, authent):

    payload_keys = [
        {"X-CF-APP-INSTANCE": "xxx:1"},
        {"X-CF-APP-INSTANCE":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:1"}
    ]
    for pk in payload_keys:
        try:
            req = s.get(url, headers=pk, verify=False, auth=authent, timeout=10)
            if req.status_code != 200 and main_status_code != req.status_code:
                print(f"\n{url} :: {main_status_code} > {req.status_code} [{pk}]\n")
                #pprint(req.headers)
                #print(f"[{main_status_code}>{req.status_code}] [{len(main_status_code.headers)}b>{len(req.headers)}b] [{len(main_status_code.content)}b>{len(req.content)}b] {url} :: {pk}")
        except requests.Timeout:
            #print(f"request timeout {url} {p}")
            pass
        except KeyboardInterrupt:
            print("Exiting")
            sys.exit()
        except Exception as e:
            print(f"Error : {e}")
            pass


if __name__ == '__main__':
    url_file = sys.argv[1]
    s = requests.Session()
    authent = False
    main_status_code = 0
    #get_error(url_file, s, main_status_code, authent)
    with open(url_file, "r") as urls:
        urls = urls.read().splitlines()
        for url in urls:
            url = "{}?cb={}".format(url, random.randrange(999))
            try:
                req_main = requests.get(url, verify=False, timeout=10)
                main_status_code = req_main.status_code
                authent = False
                get_error(url, s, main_status_code, authent)
            except KeyboardInterrupt:
                print("Exiting")
                sys.exit()
            except:
                pass
            print(f" {url}", end='\r')