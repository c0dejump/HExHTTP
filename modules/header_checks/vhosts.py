#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Checks if web page content is different between IP address and Host 
"""

import socket
from urllib.parse import urlparse
from modules.utils import requests, configure_logger

logger = configure_logger(__name__)

def check_vhost(domain, url):
    print("\033[36m ├ Vhosts misconfiguration \033[0m")
    try:
        req_index = requests.get(url, verify=False, timeout=10)
        len_index = len(req_index.content)
        retrieve_vh = False

        parsed_url = urlparse(url)
        host = parsed_url.netloc
        dom = host if host.split(".")[0] != "www" else host.lstrip("www.")

        #print(dom)

        vhosts = [f"https://{dom}/", f"http://{dom}/", f"http://www2.{dom}/", f"http://www3.{dom}/", f"https://www2.{dom}/",
        f"https://www3.{dom}/"]
        for vh in vhosts:
            #print(vh)
            try:
                req_vh = requests.get(vh, verify=False, timeout=10)
                if req_vh.status_code not in [404, 403, 425, 503, 500, 400] and len(req_vh.content) not in range(len_index - 100, len_index + 100):
                    retrieve_vh = True
                    print(f" └── \033[32m\u251c\033[0m {url} [{len_index}b] <> {vh} [{len(req_vh.content)}b] ")
            except (requests.RequestException, socket.gaierror) as e:
                logger.exception("The host IP has a problem, check it manually please: %s. Exception: %s", vh, e)
    except (requests.RequestException, socket.gaierror) as e:
        logger.exception("Exception occurred: %s", e)
