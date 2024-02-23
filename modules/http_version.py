#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import traceback
from http.client import HTTPConnection

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def check_http_version(url):
    print("\033[36m ├ HTTP Version analyse\033[0m")
    versions = ['HTTP/0.9','HTTP/1.0','HTTP/1.1','HTTP/2']

    try:
        req = requests.get(url, verify=False, allow_redirects=False)
    except Exception as e:
        print(f" └── Error {e}")
        return 0

    req_base_version = req.raw.version
    #print(req_base_version)

    for v in versions:
        HTTPConnection._http_vsn_str = v
        try:
            req_v = requests.get(url, timeout=10, verify=False, allow_redirects=False)
            print(" └── {:<9}: {:<3} {:<13} [HS: {}b]".format(v, req_v.status_code, "[{} bytes]".format(len(req_v.content)), len(req_v.headers)))
        except requests.exceptions.Timeout:
            print(f" └── Timeout Error with {v}")
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f" └── Error with {v} : {e}")
            #traceback.print_exc()

    if req_base_version == 10:
        HTTPConnection._http_vsn_str = 'HTTP/1.0'
    elif req_base_version == 11:
        HTTPConnection._http_vsn_str = 'HTTP/1.1'
    elif req_base_version == 20:
        HTTPConnection._http_vsn_str = 'HTTP/2'

if __name__ == '__main__':
    url = "https://www.hosteur.com"
    check_http_version(url)