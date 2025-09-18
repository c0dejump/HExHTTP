#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Based on Zhero research
https://zhero-web-sec.github.io/research-and-things/nuxt-show-me-your-payload
"""

from utils.utils import requests, random, sys, configure_logger, re 
from utils.style import Identify
from modules.cp_cve.unrisk_page import get_unrisk_page

logger = configure_logger(__name__)

from urllib.parse import urljoin


def nuxt_check(url, s, req_main, custom_header, authent):
    try:
        req = requests.get(url, verify=False, auth=authent, headers=custom_header, timeout=10, allow_redirects=False)

        if "nuxt" in req.text or "nuxt" in req.headers:
            unrisk_page = get_unrisk_page(url, req)
            #print(unrisk_page)
            if unrisk_page:
                poison_url = f"{unrisk_page}_payload.json" if unrisk_page[-1] == "/" else f"{unrisk_page}/_payload.json"
                req_nuxt = requests.get(poison_url, verify=False, auth=authent, headers=custom_header, timeout=10, allow_redirects=False)
                len_req = len(req_nuxt.content)
                try:
                    data = req_nuxt.json()
                    print(f" {Identify.behavior} | CVE-2025-27415 | TAG OK | \033[34m{poison_url}\033[0m")
                except requests.exceptions.JSONDecodeError:
                    if "application/json" in req_nuxt.headers.get("Content-Type", ""):
                        print(f" {Identify.behavior} | CVE-2025-27415 | TAG OK | \033[34m{poison_url}\033[0m")
                    elif req_nuxt.status_code != req.status:
                        print(f" {Identify.behavior} | CVE-2025-27415 | DIFFERENT RESPONSE {req.status_code} > {req_nuxt.status_code}| \033[34m{url}\033[0m")
                except Exception as e:
                    #print(f"Error 69: {e}")
                    logger.exception(e)
                    pass
                #check exploit
                req_verify = requests.get(unrisk_page, verify=False, auth=authent, headers=custom_header, timeout=10, allow_redirects=False)
                try:
                    data = req_verify.json()
                    print(f" {Identify.confirmed} | CVE-2025-27415 | TAG OK | \033[34m{unrisk_page}\033[0m")
                except requests.exceptions.JSONDecodeError:
                    if "application/json" in req_verify.headers.get("Content-Type", ""):
                        print(f" {Identify.confirmed} | CVE-2025-27415 | TAG OK | \033[34m{unrisk_page}\033[0m")
                    elif req_verify.status_code != req.status:
                        print(f" {Identify.confirmed} | CVE-2025-27415 | DIFFERENT RESPONSE {req.status_code} > {req_verify.status_code} | \033[34m{unrisk_page}\033[0m")
                except Exception as e:
                    #print(f"Error 81 : {e}")
                    logger.exception(e)
                    pass
            else:
                print(" CVE-2025-27415 | [i] It seems that the nuxt.js framework is used, but no risk-free pages have been found. Please do a manual check.")

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