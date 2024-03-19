#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import traceback
import socket

def check_vhost(domain, url):
    """
    check_ip:
    Check the host ip if this webpage is different or not
    """
    print("\033[36m ├ Vhosts misconfiguration \033[0m")
    try:
        req_index = requests.get(url, verify=False, timeout=10)
        len_index = len(req_index.content)
        retrieve_ip = False
        dom = socket.gethostbyname(domain)
        ips = ["https://{}/".format(dom), "http://{}/".format(dom), "http://www2.{}/".format(domain), "http://www3.{}/".format(domain), "https://www2.{}/".format(domain),
        "https://www3.{}/".format(domain)]
        for ip in ips:
            try:
                req_ip = requests.get(ip, verify=False, timeout=10)
                if req_ip.status_code not in [404, 403, 425, 503, 500, 400] and len(req_ip.content) not in range(len_index - 50, len_index + 50):
                    retrieve_ip = True
                    print(" └── \033[32m\u251c\033[0m {} [{}b] <> {} [{}b] ".format(url, len_index, ip, len(req_ip.content)))
            except:
                #print(" \033[33m\u251c\033[0m The host IP have a problem, check it manualy please: {} ".format(ip))
                pass
    except:
        #traceback.print_exc()
        pass
