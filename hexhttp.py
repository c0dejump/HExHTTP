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
    "Envoy": ["envoy"]
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
    print("")


def check_header(url, req_main):
    print("\033[36m ├ Header analyse\033[0m")
    for headi in base_header:
        #print(headi)
        if "cache" in headi or "Cache" in headi:
            print(" └── {}".format(headi))
    for vary in base_header:
        if "Vary" in vary:
            print(" └── {}".format(vary))


def main(url):
    global base_header
    base_header = []

    a_cdn = analyze_cdn()
    a_tech = technology()

    req_main = s.get(url, verify=False, allow_redirects=False, timeout=10)
    print("\n URL response: {}\n".format(req_main.status_code))
    if req_main.status_code not in [200, 302, 301, 403, 401]:
        choice = input(" \033[33mThe url does not seem to answer correctly, continue anyway ?\033[0m [y/n]")
        if choice not in ["y", "Y"]:
            sys.exit()
    for k in req_main.headers:
        base_header.append("{}: {}".format(k, req_main.headers[k]))
    #print(base_header)
    get_server_error(url, base_header, full)
    check_header(url, req_main)
    check_localhost(url, s, domain)
    check_methods(url)
    check_CPDoS(url, s, req_main, domain)
    cdn = a_cdn.get_cdn(req_main, url, s)
    if cdn:
        cdn_result = getattr(a_cdn, cdn)(url, s)
    techno = get_technos(req_main, url, s)
    if techno:
        techno_result = getattr(a_tech, techno)(url, s)



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

    main(url)

