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

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


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

    req_main = s.get(url, verify=False, timeout=10)
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
    check_localhost(s, url, domain)
    check_methods(url)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument("-u", help="URL login to test \033[31m[required]\033[0m", dest='url')
    results = parser.parse_args()
                                     
    url = results.url

    domain =  urlparse(url).netloc

    s = requests.Session()

    if len(sys.argv) < 2:
        print("{}URL target is missing, try using -u <url> \n".format(INFO))
        parser.print_help()
        sys.exit()

    main(url)

