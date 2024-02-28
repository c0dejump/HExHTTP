#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import traceback
from static.vuln_notify import vuln_found_notify

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


params = {
        'cp': '1337',
        }

def get_hit(url, matching_forward, custom_header, authent):
    #web cache poisoning to exploit unsafe handling of resource imports
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
        'X-Forwarded-Host': matching_forward,
        }

    if custom_header:
        headers = headers.update(custom_header)
        
    res_header = {}
    #print(" - {}?cp={}".format(url, params["cp"])) #Debug

    word_in_text = False

    for i in range(10):
        res = requests.get(url, params=params, headers=headers, verify=False, allow_redirects=False, auth=authent, timeout=10)
        if matching_forward in res.text:
            word_in_text = True
        for cs in res.headers:
            if "Cache-Status" in cs or "X-Cache" in cs or "x-drupal-cache" in cs or "X-Proxy-Cache" in cs or "X-HS-CF-Cache-Status" in cs \
            or "X-Vercel-Cache" in cs or "X-nananana" in cs or "x-vercel-cache" in cs or "X-TZLA-EDGE-Cache-Hit" in cs or "x-spip-cache" in cs \
            or "x-nextjs-cache" in cs or "x-pangle-cache-from" in cs or "X-Deploy-Web-Server-Cache-Hit" in cs or "CDN-Cache" in cs:
                #print(res.headers) #Debug
                if "hit" in res.headers[cs].lower():
                    #print("HEADSHOT !!!") #Debug
                    res_header = res.headers
            if res_header:
                if "age" in cs.lower():
                    #To keep the potential cache poisoning ~15scd
                    header_age = 0
                    while int(header_age) < 15:
                        #print(header_age) #Debug
                        #print(res.headers[cs]) #Debug
                        res = requests.get(url, params=params, headers=headers, verify=False, allow_redirects=False, auth=authent,timeout=10)
                        header_age += 1
                else:
                    pass
    if word_in_text:
        print("\033[33m └── INTERESTING BEHAVIOR\033[0m | HEADER REFLECTION | \033[34m{}?cp=1337\033[0m | PAYLOAD: X-Forwarded-Host".format(url))
    #print(res_header) #Debug
    return res_header


def wcp_import(url, matching_forward, custom_header, req_status, authent):
    print("\033[36m --├ {}?cp={}\033[0m have HIT Cache-Status".format(url, params["cp"]))

    url_param = "{}?cp={}".format(url, params["cp"])

    req_verify_redirect = requests.get(url, params=params, headers=custom_header, verify=False, auth=authent, timeout=10)
    req_verify_url = requests.get(url_param, headers=custom_header, verify=False, allow_redirects=True, auth=authent, timeout=10)

    if req_verify_redirect.status_code in [301, 302] or req_verify_url.status_code in [301, 302]:
        if matching_forward in req_verify_redirect.url or matching_forward in req_verify_url.url:
            print("  \033[31m └── VULNERABILITY CONFIRMED\033[0m | DIFFERENT STATUS-CODE | \033[34m{}\033[0m | PAYLOAD: X-Forwarded-Host".format(url_param))
            vuln_found_notify(url_param, "X-Forwarded-Host")
    elif matching_forward in req_verify_redirect.text or matching_forward in req_verify_url.text:
        print("  \033[31m └── VULNERABILITY CONFIRMED\033[0m | HEADER REFLECTION | \033[34m{}\033[0m | PAYLOAD: X-Forwarded-Host".format(url_param))
        vuln_found_notify(url_param, "X-Forwarded-Host")
    elif req_verify_url.status_code != req_status:
        print("  \033[31m └── VULNERABILITY CONFIRMED\033[0m | DIFFERENT STATUS-CODE:\033[36m {} → {}\033[0m | \033[34m{}\033[0m | PAYLOAD: X-Forwarded-Host".format(req_status, req_verify_url.status_code, url_param))
        vuln_found_notify(url_param, "X-Forwarded-Host")
    #print(req_verify_redirect.status_code) #Debug


def check_cache_files(uri, custom_header, authent):


    matching_forward = "ndvyepenbvtidpvyzh.com"

    for endpoints in ["plopiplop.js", "plopiplop.css"]:
        url = "{}{}".format(uri, endpoints)
        try:
            req_status = requests.get(url, params=params, verify=False, allow_redirects=False, auth=authent, timeout=10)
            req_status = req_status.status_code
            valid_hit = get_hit(url, matching_forward, custom_header, authent)
            if valid_hit:
                wcp_import(url, matching_forward, custom_header, req_status, authent)
        except requests.exceptions.Timeout:
            print(" └── Timeout Error with {}".format(endpoints))
        except:
            traceback.print_exc()
            print(" ! Error with {}".format(url))