#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import urllib3
import requests
import traceback
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


desc_method = {
    204: "204 No Content",
    400: "\033[33m400 Bad Request\033[0m",
    405: "\033[33m405 Method Not Allowed\033[0m",
    406: "\033[33m406 Not Acceptable\033[0m",
    409: "\033[33m409 Conflict\033[0m",
    410: "410 Gone",
    500: "\033[31m500 Internal Server Error\033[0m",
    501: "\033[31m501 Not Implemented\033[0m",
    502: "\033[31m502 Bad Gateway\033[0m"
}


def get(url): req_p = requests.get(url, verify=False, allow_redirects=False, headers={'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko'}, timeout=10, auth=authent); return req_p.status_code, "GET", len(req_p.content), req_p.content
def post(url): req_p = requests.post(url, verify=False, allow_redirects=False, headers={'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko'}, timeout=10, auth=authent); return req_p.status_code, "POST", len(req_p.content), req_p.content
def put(url): req_pt = requests.put(url, verify=False, allow_redirects=False, headers={'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko'}, timeout=10, auth=authent); return req_pt.status_code, "PUT", len(req_pt.content), req_p.content
def patch(url): req_ptch = requests.patch(url, verify=False, allow_redirects=False, headers={'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko'}, timeout=10, auth=authent); return req_ptch.status_code, "PATCH", len(req_ptch.content), req_p.content
def options(url): req_o = requests.options(url, verify=False, allow_redirects=False, headers={'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko'}, timeout=10, auth=authent); return req_o.status_code, "OPTIONS", len(req_o.content), req_p.content
def trace(url): req_o = requests.trace(url, verify=False, allow_redirects=False, headers={'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko'}, timeout=10, auth=authent); return req_o.status_code, "TRACE", len(req_o.content), req_p.content


def check_methods(url, custom_header, authent):
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
            print(" └── Error with {} method".format(funct))
            pass
            #traceback.print_exc()
    for rs, type_r, len_req, req_content in result_list:
        try:
            rs = desc_method[rs]
        except:
            rs = rs
        print(" └── {type_r:<8}: {rs:<3} [{len_req} bytes]".format(type_r=type_r, rs=rs, len_req=len_req))
    try:
        http = urllib3.PoolManager()
        resp = http.request('HELP', url)
        rs = resp.status
        try:
            rs = desc_method[rs]
        except:
            rs = rs
        len_req = len(resp.data.decode('utf-8'))
        print(f" └── HELP{'':<4}: {rs:<3} [{len_req} bytes]")
        #print(resp.data)
    except requests.packages.urllib3.exceptions.MaxRetryError as e:
        print(f" └── HELP{'':<4}: Error due to a too many redirects")
    except:
        pass
    try:
        http = urllib3.PoolManager()
        resp = http.request('PURGE', url)
        rs = resp.status
        try:
            rs = desc_method[rs]
        except:
            rs = rs
        len_req = len(resp.data.decode('utf-8'))
        print(f" └── PURGE{'':<3}: {rs:<3} [{len_req} bytes]")
    except requests.packages.urllib3.exceptions.MaxRetryError as e:
        print(f" └── PURGE{'':<3}: Error due to a too many redirects")
    except Exception:
        pass
    try:
        http = urllib3.PoolManager()
        resp = http.request('DEBUG', url) #check response with a bad method
        rs = resp.status
        try:
            rs = desc_method[rs]
        except:
            rs = rs
        len_req = len(resp.data.decode('utf-8'))
        print(f" └── DEBUG{'':<3}: {rs:<3} [{len_req} bytes]")
        #print(resp.data)
    except requests.packages.urllib3.exceptions.MaxRetryError as e:
        print(f" └── DEBUG{'':<3}: Error due to a too many redirects")
    except:
        pass
    try:
        http = urllib3.PoolManager()
        resp = http.request('PLOP', url) #check response with a bad method
        rs = resp.status
        try:
            rs = desc_method[rs]
        except:
            rs = rs
        len_req = len(resp.data.decode('utf-8'))
        print(f" └── PLOP{'':<4}: {rs:<3} [{len_req} bytes]")
        #print(resp.data)
    except requests.packages.urllib3.exceptions.MaxRetryError as e:
        print(f" └── PLOP{'':<4}: Error due to a too many redirects")
    except:
        pass