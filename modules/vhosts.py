#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Checks if web page content is different between IP address and Host 
"""

from modules.utils import *
import socket

def check_vhost(domain, url):
    print("\033[36m ├ Vhosts misconfiguration \033[0m")
    try:
        req_index = requests.get(url, verify=False, timeout=10)
        len_index = len(req_index.content)
        retrieve_ip = False
        dom = socket.gethostbyname(domain)
        ips = [f"https://{dom}/", f"http://{dom}/", f"http://www2.{domain}/", f"http://www3.{domain}/", f"https://www2.{domain}/",
        f"https://www3.{domain}/"]
        for ip in ips:
            try:
                req_ip = requests.get(ip, verify=False, timeout=10)
                if req_ip.status_code not in [404, 403, 425, 503, 500, 400] and len(req_ip.content) not in range(len_index - 50, len_index + 50):
                    retrieve_ip = True
                    print(f" └── \033[32m\u251c\033[0m {url} [{len_index}b] <> {ip} [{len(req_ip.content)}b] ")
            except:
                #print(f" \033[33m\u251c\033[0m The host IP have a problem, check it manualy please: {ip} ")
                pass
    except:
        #traceback.print_exc()
        pass
