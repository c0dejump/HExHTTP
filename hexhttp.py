#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import argparse
import traceback
import sys, os, re
import time
from urllib.parse import urlparse

from modules.check_localhost import check_localhost
from modules.server_error import get_server_error
from modules.methods import check_methods
from modules.CPDoS import check_CPDoS
from modules.technologies import technology
from modules.cdn import analyze_cdn
from modules.cache_poisoning_files import check_cache_files
from modules.cookie_reflection import check_cookie_reflection

from tools.autopoisoner.autopoisoner import check_cache_poisoning


requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def get_technos(req_main, url, s):
    """
    Check what is the reverse proxy/waf/cached server... and test based on the result
    #TODO
    """
    print("\033[36m ├ Techno analyse\033[0m")
    technos = {
    "apache": ["Apache", "apache"],
    "nginx": ["nginx"],
    "envoy": ["envoy"]
    }
    for t in technos:
        for v in technos[t]:
            for rt in req_main.headers:
                if v in req_main.text or v in req_main.headers[rt] or v in rt:
                    return t;



def bf_hidden_header(url):
    """
    Check if hidden header used by website
    (https://webtechsurvey.com/common-response-headers)
    """
    print("")


def fuzz_x_header(url):
    """
    When fuzzing for custom X-Headers on a target, a setup example as below can be combined with a dictionary/bruteforce attack. This makes it possible to extract hidden headers that the target uses. 
        X-Forwarded-{FUZZ}
        X-Original-{FUZZ}
        X-{COMPANY_NAME}-{FUZZ}
    (https://blog.yeswehack.com/yeswerhackers/http-header-exploitation/)
    """
    print("\033[36m ├ X-FUZZ analyse\033[0m")
    f_header = {"Forwarded":"for=example.com;host=example.com;proto=https, for=23.45.67.89"}
    try:
        req_f = requests.get(url, headers=f_header, timeout=10, verify=False)
        if req_f.status_code == 500:
            print(" └──  Header {} return 500 error".format(f_header))
    except:
        pass


def check_cache_header(url, req_main):
    result = []
    for headi in base_header:
        if "cache" in headi or "Cache" in headi:
            result.append("{}:{}".format(headi.split(":")[0], headi.split(":")[1]))
    for vary in base_header:
        if "Vary" in vary:
            result.append("{}:{}".format(vary.split(":")[0], vary.split(":")[1]))
    """for age in base_header:
        if "age" in age or "Age" in age:
            result.append("{}:{}".format(age.split(":")[0], age.split(":")[1]))"""
    return(result)


def maj_check_cache_header(check_header):
    print("\033[36m ├ Header cache\033[0m")
    for ch in check_header:
        print(' └──  {cho:<30}'.format(cho=ch))


def main(url, s):
    global base_header
    base_header = []

    a_cdn = analyze_cdn()
    a_tech = technology()

    req_main = s.get(url, verify=False, allow_redirects=False, timeout=10)
    
    print("\033[34m⟙\033[0m")
    print(" URL: {}".format(url))
    print(" URL response: {}".format(req_main.status_code))
    print(" URL response size: {} bytes".format(len(req_main.content)))
    print("\033[34m⟘\033[0m")
    if req_main.status_code not in [200, 302, 301, 403, 401] and not url_file:
        choice = input(" \033[33mThe url does not seem to answer correctly, continue anyway ?\033[0m [y/n]")
        if choice not in ["y", "Y"]:
            sys.exit()
    for k in req_main.headers:
        base_header.append("{}: {}".format(k, req_main.headers[k]))

    #print(base_header)

    get_server_error(url, base_header, full)
    check_localhost(url, s, domain)
    check_methods(url)
    check_CPDoS(url, s, req_main, domain)
    check_cache_poisoning(url)
    check_cache_files(url)
    check_cookie_reflection(url)
    cdn = a_cdn.get_cdn(req_main, url, s)
    if cdn:
        cdn_result = getattr(a_cdn, cdn)(url, s)
    techno = get_technos(req_main, url, s)
    if techno:
        techno_result = getattr(a_tech, techno)(url, s)

    check_header = check_cache_header(url, req_main)

    fuzz_x_header(url)
    maj_check_cache_header(check_header)



if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument("-u", help="URL to test \033[31m[required]\033[0m", dest='url')
    parser.add_argument("-f", help="URL file to test", dest='url_file', required=False)
    parser.add_argument("--full", help="To display full header", dest='full', required=False, action='store_true')
    results = parser.parse_args()
                                     
    url = results.url
    url_file = results.url_file
    full = results.full

    domain =  urlparse(url).netloc

    s = requests.Session()
    s.headers.update({'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko'})
    s.max_redirects = 60


    if len(sys.argv) < 2:
        print("{}URL target is missing, try using -u <url> \n".format(INFO))
        parser.print_help()
        sys.exit()

    if url_file:
        with open(url_file, "r") as urls:
            urls = urls.read().splitlines()
            for url in urls:
                try:
                    main(url, s)
                except KeyboardInterrupt:
                    pass
                except FileNotFoundError:
                    print("Input file not found")
                    sys.exit()
                except:
                    pass
                print("")
    else:
        try:
            main(url, s)
        # basic errors
        except KeyboardInterrupt:
            sys.exit()
        # requests errors
        except requests.ConnectionError:
            print("Error, cannot connect to target")
        except requests.Timeout:
            print("Error, request timeout (10s)")
        except requests.exceptions.MissingSchema: 
            print("Error, missing http:// or https:// schema")
        print("")
