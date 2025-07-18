#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Check support for different HTTP methods (NOT DELETE & PATCH)
"""

import urllib3
from urllib3 import Timeout, PoolManager
from modules.utils import requests, configure_logger, Colors, human_time

logger = configure_logger(__name__)

desc_method = {
    200: f"\033[32m200 OK{Colors.RESET}",
    204: f"204 No Content{Colors.RESET}",
    400: f"\033[33m400 Bad Request{Colors.RESET}",
    401: f"\033[31m401 AUTH{Colors.RESET}",
    403: f"\033[31m403 FORBIDDEN{Colors.RESET}",
    405: f"\033[33m405 Method Not Allowed{Colors.RESET}",
    406: f"\033[33m406 Not Acceptable{Colors.RESET}",
    409: f"\033[33m409 Conflict{Colors.RESET}",
    410: f"410 Gone",
    412: f"\033[33m412 Precondition Failed{Colors.RESET}",
    500: f"\033[31m500 Internal Server Error{Colors.RESET}",
    501: f"\033[31m501 Not Implemented{Colors.RESET}",
    502: f"\033[31m502 Bad Gateway{Colors.RESET}",
}

header = {
    "User-agent": "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko"
}


def get(url):
    req_g = requests.get(
        url, verify=False, allow_redirects=False, headers=header, timeout=120
    )
    return req_g.status_code, req_g.headers, "GET", len(req_g.content), req_g.content


def post(url):
    req_p = requests.post(
        url, verify=False, allow_redirects=False, headers=header, timeout=120
    )
    return req_p.status_code, req_p.headers, "POST", len(req_p.content), req_p.content


def put(url):
    req_pt = requests.put(
        url, verify=False, allow_redirects=False, headers=header, timeout=120
    )
    return (
        req_pt.status_code,
        req_pt.headers,
        "PUT",
        len(req_pt.content),
        req_pt.content,
    )


def patch(url):
    req_ptch = requests.patch(
        url, verify=False, allow_redirects=False, headers=header, timeout=120
    )
    return (
        req_ptch.status_code,
        req_ptch.headers,
        "PATCH",
        len(req_ptch.content),
        req_ptch.content,
    )


def options(url):
    req_o = requests.options(
        url, verify=False, allow_redirects=False, headers=header, timeout=120
    )
    return (
        req_o.status_code,
        req_o.headers,
        "OPTIONS",
        len(req_o.content),
        req_o.content,
    )


def check_other_methods(ml, url, http, pad):
    try:
        if ml == "DELETE":
            url = f"{url}plopiplop.css"
        resp = http.request(ml, url)  # check response with a bad method
        rs = resp.status
        resp_h = resp.headers

        cache_status = False
        try:
            rs = desc_method[rs]
        except KeyError:
            logger.debug("No descriptions available for status %s", rs)

        for rh in resp_h:
            if (
                "Cache-Status" in rh
                or "X-Cache" in rh
                or "x-drupal-cache" in rh
                or "X-Proxy-Cache" in rh
                or "X-HS-CF-Cache-Status" in rh
                or "X-Vercel-Cache" in rh
                or "X-nananana" in rh
                or "x-vercel-cache" in rh
                or "X-TZLA-EDGE-Cache-Hit" in rh
                or "x-spip-cache" in rh
                or "x-nextjs-cache" in rh
            ):
                cache_status = True
        len_req = len(resp.data.decode("utf-8"))
        space = " " * (pad - len(ml) + 1)
        print(
                f" └── {ml}{space}{rs:<3}  [{len_req} bytes]{'':<2}[CacheTag: {cache_status}]"
            )

        logger.debug("Data response: %s", resp.data)

    except urllib3.exceptions.MaxRetryError:
        print(f" └── {ml} : Error due to a too many redirects")
    except Exception as e:
        logger.exception(e)


def check_methods(url, custom_header, authent, human):
    """
    Try other method
    Ex: OPTIONS /admin
    """
    htimeout = Timeout(connect=7.0, read=7.0)
    http = PoolManager(timeout=htimeout)

    print("\033[36m ├ Methods analysis\033[0m")
    result_list = []
    for funct in [get, post, put, patch, options]:
        try:
            result_list.append(funct(url))
        except Exception as e:
            print(f" └── Error with {funct} method: {e}")
            logger.exception("Error with %s method", funct, exc_info=True)

    for rs, req_head, type_r, len_req, req_content in result_list:
        try:
            rs = desc_method[rs]
        except KeyError:
            logger.debug("No descriptions available for status %s", rs)

        cache_status = False
        cache_res = ""

        for rh in req_head:
            if "cache" in rh.lower():
                cache_status = True
                cache_res = rh
        print(f" └── {type_r:<10} {rs:<3} [{len_req} bytes] [CacheTag: {cache_status}]")
        if type_r == "OPTIONS":
            for x in req_head:
                if x.lower() == "allow":
                    print(f"    |-- allow: {req_head[x]}")

    list_path = "modules/lists/methods_list.lst"
    with open(list_path, "r") as method_list:
        method_list = method_list.read().splitlines()
        pad = max(len(m) for m in method_list)
        for ml in method_list:
            check_other_methods(ml, url, http, pad)
            human_time(human)
