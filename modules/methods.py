#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import urllib3
import requests
import traceback
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def get(url): req_p = requests.get(url, verify=False, allow_redirects=False, headers={'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko'}, timeout=10); return req_p.status_code, "GET", len(req_p.content)
def post(url): req_p = requests.post(url, verify=False, allow_redirects=False, headers={'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko'}, timeout=10); return req_p.status_code, "POST", len(req_p.content)
def put(url): req_pt = requests.put(url, verify=False, allow_redirects=False, headers={'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko'}, timeout=10); return req_pt.status_code, "PUT", len(req_pt.content)
def patch(url): req_ptch = requests.patch(url, verify=False, allow_redirects=False, headers={'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko'}, timeout=10); return req_ptch.status_code, "PATCH", len(req_ptch.content)
def options(url): req_o = requests.options(url, verify=False, allow_redirects=False, headers={'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko'}, timeout=10); return req_o.status_code, "OPTIONS", len(req_o.content)


def check_methods(url):
    """ 
    Try other method 
    Ex: OPTIONS /admin
    """
    print("\033[36m ├ Methods analyse\033[0m")
    result_list = []
    for funct in [get, post, put, patch, options]:
        try:
            result_list.append(funct(url))
        except:
            pass
            #traceback.print_exc()
    for rs, type_r, len_req in result_list:
        print(" └── {type_r:<8}: {rs:<3} [{len_req} bytes]".format(type_r=type_r, rs=rs, len_req=len_req))
    try:
        http = urllib3.PoolManager()
        resp = http.request('HELP', url)
        rs = resp.status
        len_req = len(resp.data.decode('utf-8'))
        print(f" └── HELP{'':<4}: {rs:<3} [{len_req} bytes]")
    except requests.packages.urllib3.exceptions.MaxRetryError as e:
        print(f" └── HELP{'':<4}: Error due to a too many redirects")
    except Exception:
        pass