#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import argparse
import traceback
import sys, os, re
import time
import traceback
from urllib.parse import urlparse
from modules.check_localhost import check_localhost
from modules.server_error import get_server_error
from modules.methods import check_methods
from modules.CPDoS import check_CPDoS
from modules.technologies import technology
from modules.cdn import analyze_cdn


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
    req_f = requests.get(url, headers=f_header, timeout=10, verify=False)
    if req_f.status_code == 500:
        print(" └──  Header {} return 500 error".format(f_header))


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


def diff_check_cache_header(check_header_one, check_header_two):
    print("\033[36m ├ Header cache analyse\033[0m")
    print("\033[36m   First check{space:<25}Last check\033[0m".format(space=" "))
    for cho, cht in zip(check_header_one, check_header_two):
        if not full:
            cho = cho.replace(cho[40:], "...") if len(cho) > 40 else cho
            cht = cht.replace(cht[60:], "...\033[0m") if len(cht) > 60 else cht
        print(' └──  {cho:<30} → {cht:<15}'.format(cho=cho, cht=cht))


def main(url, s):
    global base_header
    base_header = []

    a_cdn = analyze_cdn()
    a_tech = technology()

    req_main = s.get(url, verify=False, allow_redirects=False, timeout=10)
    
    print("\033[34m⟙\033[0m")
    print(" URL response: {}".format(req_main.status_code))
    print(" URL response size: {} bytes".format(len(req_main.content)))
    print("\033[34m⟘\033[0m\n")
    if req_main.status_code not in [200, 302, 301, 403, 401]:
        choice = input(" \033[33mThe url does not seem to answer correctly, continue anyway ?\033[0m [y/n]")
        if choice not in ["y", "Y"]:
            sys.exit()
    for k in req_main.headers:
        base_header.append("{}: {}".format(k, req_main.headers[k]))

    #print(base_header)
    # first check header response
    check_header_one = check_cache_header(url, req_main)

    get_server_error(url, base_header, full)
    check_localhost(url, s, domain)
    check_methods(url)
    check_CPDoS(url, s, req_main, domain)
    cdn = a_cdn.get_cdn(req_main, url, s)
    if cdn:
        cdn_result = getattr(a_cdn, cdn)(url, s)
    techno = get_technos(req_main, url, s)
    if techno:
        techno_result = getattr(a_tech, techno)(url, s)


    second_req_main = s.get(url, verify=False, allow_redirects=False, timeout=10)
    #second check header response (to check if the header response changed)
    check_header_two = check_cache_header(url, second_req_main)

    fuzz_x_header(url)
    diff_check_cache_header(check_header_one, check_header_two)



if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument("-u", help="URL login to test \033[31m[required]\033[0m", dest='url')
    parser.add_argument("--full", help="To display full header", dest='full', required=False, action='store_true')
    results = parser.parse_args()
                                     
    url = results.url
    full = results.full

    domain =  urlparse(url).netloc

    s = requests.Session()
    s.headers.update({'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko'})
    s.max_redirects = 60


    if len(sys.argv) < 2:
        print("{}URL target is missing, try using -u <url> \n".format(INFO))
        parser.print_help()
        sys.exit()

    main(url, s)

