#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules.utils import *
from modules.cpdos.cache_error import get_error
from modules.cpdos.waf_rules import waf_rules
from modules.cpdos.hho import HHO
from modules.cpdos.hmc import HMC
from modules.cpdos.hmo import HMO
from modules.cpdos.hhcn import HHCN
from modules.cpdos.hbh import HBH

def check_CPDoS(url, s, req_main, domain, custom_header, authent):
    i = 0
    redirect_req = False

    if req_main.status_code in [301, 302]:
        url = req_main.headers['location'] if "http" in req_main.headers['location'] else "{}{}".format(url, req_main.headers['location'])
        
    print("\033[36m ├ CPDoS analyse\033[0m")

    uri = "{}?CPDoS={}".format(url, random.randint(1, 100), random.randint(1, 100))
    headers = {'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko'}
    try:
        req_main = s.get(url, headers=headers, verify=False, allow_redirects=False, timeout=15, auth=authent)
        #print(req_main.content)

        main_len = len(req_main.content)
        main_status_code = req_main.status_code

        HHO(uri, s, main_status_code, authent)
        HMC(uri, s, main_status_code, authent)
        HMO(uri, s, main_status_code, authent)
        HHCN(uri, s, authent)
        HBH(url, s, main_status_code, authent)
        get_error(uri, s, main_status_code, main_len, authent)
        #waf_rules(url, s, main_status_code, authent)
    except KeyboardInterrupt:
        print(" ! Canceled by keyboard interrupt (Ctrl-C)")
        sys.exit() 
    except:
        #traceback.print_exc()
        pass