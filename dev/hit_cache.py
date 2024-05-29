#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import sys
import random
import traceback

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def check_hit_cache(url, h, req_main):
    if not isinstance(h, dict):
        header = {h:"toto"}
    else:
        header = h
    try:
        for x in range(10):
            req_ = s.get(url, headers=header, verify=False, timeout=10)

        for r in req_.headers:
            if r.lower() == "age" or r.lower() == "x-age":
                #print(r)
                if req_.headers[r] != str(0):
                    print(f" \"Age\" cached the page with {header}")
            elif "hit" in req_.headers[r]:
                print(f" {r}::{req_.headers[r]} \"HIT\" cached the page with {header}")
            else:
                pass
        #if len(req_.headers) != len(req_main.headers):
            #print(f"{len(req_main.headers)} > {len(req_.headers)} with {h}")
    except Exception as e:
        pass
        #print(f"3; Error with {h}: {e}")


def get_header_values(url, s, req_main):
    url = "{}?cb={}".format(url, random.randrange(999))
    print(url)

    hlist = []
    for rv in req_main.headers:
        hlist.append(rv)
    for hl in hlist:
        #print(hl)
        
        try:
            if "Access-Control-Allow-Headers" in hl:
                #print(req_main.headers[hl])
                for acah in req_main.headers[hl].split(","):
                    check_hit_cache(url, acah.replace(" ",""), req_main)
                all_acah = {element.replace(" ",""): "toto" for element in req_main.headers[hl].split(",")}
                check_hit_cache(url, all_acah, req_main)
        except Exception as e:
            #pass
            print(f"2; Error with {hl}: {e}")
        
        try:
            check_hit_cache(url, hl, req_main)
        except Exception as e:
            #pass
            print(f"2.5; Error with {hl}: {e}")


def with_list(url, s, req_main):
    url = "{}?cb={}".format(url, random.randrange(999))
    print(url)

    with open("headers.txt") as header_list:
        for h in header_list.read().splitlines():
            #print(h)
            try:
                check_hit_cache(url, h, req_main)
            except Exception as e:
                #pass
                print(f"1; Error with {h}: {e}")


if __name__ == '__main__':
    url_file = sys.argv[1]

    s = requests.Session()
    s.headers.update({'User-agent': "toto"})

    req_main = s.get(url_file, verify=False, timeout=10)
    print(req_main)
    try:
        get_header_values(url_file, s, req_main)
        with_list(url_file, s, req_main)
    except KeyboardInterrupt:
        print("Exiting")
        sys.exit()
    except Exception as e:
        #pass
        print(f"0; Error : {e}")   
    #with open(url_file, "r") as urls:
        #urls = urls.read().splitlines()
        #for url in urls:
            #try:
                #req_main = s.get(url, verify=False, timeout=6)
                #if "age" not in req_main.headers:
                    #get_header_values(url, s, req_main)
                    #with_list(url, s, req_main)
            #except KeyboardInterrupt:
                #print("Exiting")
                #sys.exit()
            #except Exception as e:
                #pass
                ##print(f"0; Error : {e}")