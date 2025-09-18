#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import random
import string
import sys
import os
import traceback
import pprint
from urllib.parse import urlparse
from typing import Optional
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def print_result(status, vuln, reason, url, payload):
    if payload:
        print(
            f" {status} | {vuln} | {reason} | \033[34m{url}\033[0m |{Colors.THISTLE}{payload}{Colors.RESET}"
            )


def verify_ocd_caching(url, method, headers):
    for _ in range(5):
        req_verify = requests.request(method, url=url, headers=headers, verify=False, allow_redirects=False, timeout=10)
    req_main = requests.get(url, verify=False, allow_redirects=False, timeout=10)
    if 'geluorigin' in req_main.text:
        print_result(Identify.confirmed, "OCD", "{} BODY REFLECTION".format(method), url, "PAYLOAD: 'Origin: https://geluorigin.chat'")
    if 'geluorigin' in req_main.headers:
        print_result(Identify.confirmed, "OCD", "{} HEADER REFLECTION".format(method), url, "PAYLOAD: 'Origin: https://geluorigin.chat'")


def get_ocd(url, headers, main_status_code, main_len, authent):
    req_get = requests.get(url, headers=headers, verify=False, allow_redirects=False, timeout=10)
    if 'geluorigin' in req_get.text:
        print_result(Identify.behavior, "OCD", "GET BODY REFLECTION", url, "PAYLOAD: 'Origin: https://geluorigin.chat'")
        verify_ocd_caching(url, "GET", headers)
    if 'geluorigin' in req_get.headers:
        print_result(Identify.behavior, "OCD", "GET HEADER REFLECTION", url, "PAYLOAD: 'Origin: https://geluorigin.chat'")
        verify_ocd_caching(url, "GET", headers)


def options_ocd(url, headers, main_status_code, main_len, authent):
    req_options = requests.options(url, headers=headers, verify=False, allow_redirects=False, timeout=10)
    if 'geluorigin' in req_options.text:
        print_result(Identify.behavior, "OCD", "OPTIONS BODY REFLECTION", url, "PAYLOAD: 'Origin: https://geluorigin.chat'")
        verify_ocd_caching(url, "OPTIONS", headers)
    if 'geluorigin' in req_options.headers:
        print_result(Identify.behavior, "OCD", "OPTIONS HEADER REFLECTION", url, "PAYLOAD: 'Origin: https://geluorigin.chat'")
        verify_ocd_caching(url, "OPTIONS", headers)



def OCD(url, req_main, authent):
    main_len = len(req_main.content)
    uri = f"{url}{random.randrange(999)}"
    headers = {
        'Origin': 'https://geluorigin.chat'
    }
    get_ocd(uri, headers, req_main, main_len, authent)
    options_ocd(uri, headers, req_main, main_len, authent)



if __name__ == '__main__':
    url_file = sys.argv[1]
    #url = f"{url_file}?cb=foo"
    #req_main = requests.get(url_file, verify=False, timeout=10, allow_redirects=False)
    #main_len = len(req_main.content)
    #main_status_code = req_main.status_code
    #authent = False
    #OCD(url, main_status_code, main_len, authent)
    with open(url_file, "r") as urls:
        urls = urls.read().splitlines()
        for url in urls:
            url = f"{url}?cb=foo"
            try:
                req_main = requests.get(url, verify=False, headers={"User-Agent": "xxxx"}, timeout=10, allow_redirects=False)
                main_len = len(req_main.content)
                main_status_code = req_main.status_code
                authent = False
                OCD(url, main_status_code, main_len, authent)
            except KeyboardInterrupt:
                print("Exiting")
                sys.exit()
            except requests.ConnectionError:
                pass
                #print("Error, cannot connect to target")
            except requests.Timeout:
                pass
                #print("Error, request timeout (10s)")
            except Exception as e:
                print(f"Error : {e}")
                pass
            print(f" {url}", end='\r')