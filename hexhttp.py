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


requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


class analyze_cdn:
    """
    Cloudflare:
        X-Forwarded-Proto: http => 301/302/303 + CF-Cache-Status: HIT
    Akamai:
        ": 1 => 400 + Server-Timing: cdn-cache; desc=HIT
    """

    def get_cdn(self, req_main, url, s):
        """
        Check what is the reverse proxy/waf/cached server... and test based on the result
        """
        print("\033[36m ├ CDN analyse\033[0m")
        technos = {
        "Akamai": ["Akamai"],
        "Cloudflare": ["cf-ray", "cloudflare", "Cf-Cache-Status", "Cf-Ray"],
        "CacheFly": [""],
        "Fastly": "",
        }
        for t in technos:
            for v in technos[t]:
                if v in req_main.text or v in req_main.headers:
                    return t;


    def Cloudflare(self, url, s):
        # X-Forwarded-Proto: http // redirect loop
        headers = {"X-Forwarded-Proto": "http"}
        cf_loop = s.get(url, headers=headers, verify=False, timeout=6)
        if cf_loop in [301, 302, 303]:
            print(cf_loop.headers)
            if "CF-Cache-Status: HIT" in cf_loop.headers:
                print("wwwooow")


    def Akamai(self, url, s):
        headers = {'"': "1"}
        aka_loop = s.get(url, headers=headers, verify=False, timeout=6)
        if aka_loop.status_code == 400:
            print(aka_loop.headers)
            if "desc=HIT" in aka_loop.headers:
                print("wwwooow")



class analyze_technos:
    """
    nginx:
        X-Real-IP
        Forwarded
    apache:
        X-Forwarded-Server
        X-Real-IP
        Max-Forwards
    Envoy:
        X-Envoy-external-adress
        X-Envoy-internal
        X-Envoy-Original-Dst-Host
    """




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

    req_main = s.get(url, verify=False, allow_redirects=False, timeout=10)
    print("\n URL response: {}\n".format(req_main.status_code))
    if req_main.status_code not in [200, 302, 301, 403, 401]:
        choice = input(" \033[33mThe url does not seem to answer correctly, continue anyway ?\033[0m [y/n]")
        if choice not in ["y", "Y"]:
            sys.exit()
    for k in req_main.headers:
        base_header.append("{}: {}".format(k, req_main.headers[k]))
    #print(base_header)
    get_server_error(url, base_header)
    check_header(url, req_main)
    check_localhost(url, s, domain)
    check_methods(url)
    check_CPDoS(url, s, req_main, domain)
    techno = a_cdn.get_cdn(req_main, url, s)
    techno_result = getattr(a_cdn, techno)(url, s)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument("-u", help="URL login to test \033[31m[required]\033[0m", dest='url')
    results = parser.parse_args()
                                     
    url = results.url

    domain =  urlparse(url).netloc

    s = requests.Session()
    s.max_redirects = 60

    if len(sys.argv) < 2:
        print("{}URL target is missing, try using -u <url> \n".format(INFO))
        parser.print_help()
        sys.exit()

    main(url)

