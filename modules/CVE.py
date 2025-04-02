#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules.utils import requests, random, re, sys, configure_logger

from modules.cp_cve.CVE202446982 import datareq_check
from modules.cp_cve.CVE201919326 import silverstripe
from modules.cp_cve.CVE202447374 import litespeed
from modules.cp_cve.CVE20235256 import drupaljsonapi
from modules.cp_cve.CVE202527415 import nuxt_check
from modules.cp_cve.CVE202529927 import middleware

logger = configure_logger(__name__)


def run_cve_modules(url, s, req_main, domain, custom_header, authent, human):
    uri = f"{url}?cve={random.randint(1, 999)}"
    headers = {
        "User-agent": "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko"
    }
    try:
        req_main = s.get(
            uri,
            headers=headers,
            verify=False,
            allow_redirects=False,
            timeout=15,
            auth=authent,
        )
        logger.debug(req_main.content)

        datareq_check(url, s, req_main, custom_header, authent)
        silverstripe(uri, s, req_main, custom_header, authent)
        litespeed(url)
        drupaljsonapi(url)
        nuxt_check(url, s, req_main, custom_header, authent)
        middleware(url)

        #TODO:https://labs.withsecure.com/advisories/plone-cms-cache-poisoning-xss-vulnerability
        #TODO:https://github.com/ZephrFish/F5-CVE-2022-1388-Exploit/tree/main

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


def check_cpcve(url, s, req_main, domain, custom_header, authent, human):
    if req_main.status_code in [301, 302]:
        url = (
            req_main.headers["location"]
            if "http" in req_main.headers["location"]
            else f'{url}{req_main.headers["location"]}'
        )

    print("\033[36m ├ Cache CVE analysis\033[0m")

    run_cve_modules(url, s, req_main, domain, custom_header, authent, human)