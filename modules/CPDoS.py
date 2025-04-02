#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules.utils import random, re, sys, configure_logger
from modules.cpdos.basic_cpdos import cpdos_main
from modules.cpdos.waf_rules import waf_rules
from modules.cpdos.hho import HHO
from modules.cpdos.hmc import HMC
from modules.cpdos.hmo import HMO
from modules.cpdos.hhcn import HHCN
from modules.cpdos.hbh import HBH
from modules.cpdos.multiple_headers import MHC
from modules.cpdos.path_traversal import path_traversal_check

from modules.utils import random, re, sys, configure_logger

logger = configure_logger(__name__)


def crawl_files(url, s, req_main, domain, custom_header, authent, human):
    try:
        regexp1 = r'(?<=src=")(\/[^\/].+?\.(js|css|html|svg))(?=")'
        regexp2 = r'(?<=href=")(\/[^\/].+?\.(js|css|html|svg))(?=")'
        #regexp3 = r'(?<=src=")(\/[^\/].+?)(?=")'
        #regexp4 = r'(?<=href=")(\/[^\/].+?)(?=")'

        responseText = req_main.text

        filesURL = re.findall(regexp1, responseText)
        filesURL += re.findall(regexp2, responseText)
        #filesURL = re.findall(regexp3, responseText)
        #filesURL += re.findall(regexp4, responseText)

        for fu in filesURL:
            if "<" not in fu[0]:
                if len(url.split("/")) > 4:
                    url = f"{'/'.join(url.split('/')[:3])}/"
                uri = f"{url}{fu[0]}"
                if uri.startswith("https://"):
                    uri = f"https://{uri[8:].replace('//', '/')}"
                elif uri.startswith("http://"):
                    uri = f"https://{uri[7:].replace('//', '/')}"

                # print(uri)
                run_cpdos_modules(uri, s, req_main, domain, custom_header, authent, human)
    except Exception as e:
        logger.exception(e)


def run_cpdos_modules(url, s, req_main, domain, custom_header, authent, human):
    uri = f"{url}?CPDoS={random.randint(1, 100)}"
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

        HHO(uri, s, req_main, authent, human)
        HMC(uri, s, req_main, authent, human)
        HMO(uri, s, req_main, authent, human)
        HHCN(uri, s, req_main, authent)
        HBH(url, s, req_main, authent, human)
        MHC(url, req_main, authent, human)
        path_traversal_check(url, s, req_main, authent)
        cpdos_main(uri, s, req_main, authent, human)
        # waf_rules(url, s, req_main, authent)
    except KeyboardInterrupt:
        print(" ! Canceled by keyboard interrupt (Ctrl-C)")
        sys.exit()
    except Exception as e:
        print(e)
        logger.exception(e)


def check_CPDoS(url, s, req_main, domain, custom_header, authent, human):
    if req_main.status_code in [301, 302]:
        url = (
            req_main.headers["location"]
            if "http" in req_main.headers["location"]
            else f'{url}{req_main.headers["location"]}'
        )

    print("\033[36m ├ CPDoS analysis\033[0m")

    run_cpdos_modules(url, s, req_main, domain, custom_header, authent, human)
    crawl_files(url, s, req_main, domain, custom_header, authent, human)
