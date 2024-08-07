#!/usr/bin/python3 
# -*- coding: utf-8 -*-

"""
Attempts to find Hop-By-Hop Header abuse
https://nathandavison.com/blog/abusing-http-hop-by-hop-request-headers
"""

from ..utils import *

VULN_NAME = "Hop-By-Hop"

# Function to make requests and compare responses
def compareRequests(url, s, headers, resp1, params2, authent):
    try:
        resp2 = s.get(url, headers=headers, params=params2, auth=authent, allow_redirects=False, verify=False, timeout=10)
    except requests.exceptions.ConnectionError as e:
        #print(f"Error : {e}")
        return None

    if resp1.status_code != resp2.status_code and resp2.status_code not in [429, 403] and resp1.status_code not in [301, 302]:
        behavior = "DIFFERENT STATUS-CODE"
        print(f" \033[33m└── [INTERESTING BEHAVIOR]\033[0m | {VULN_NAME} | \033[34m{url}?cacheBuster={params2['cacheBuster']}\033[0m | {behavior} {resp1.status_code} > {resp2.status_code} | PAYLOAD: Connection: {headers['Connection']}")
        return resp2
    if len(resp1.content) not in range(len(resp2.content) - 1000, len(resp2.content) + 1000) and resp2.status_code not in [429, 403] and resp1.status_code not in [301, 302]:
        behavior = "DIFFERENT RESPONSE LENGTH"
        print(f" \033[33m└── [INTERESTING BEHAVIOR]\033[0m | {VULN_NAME} | \033[34m{url}?cacheBuster={params2['cacheBuster']}\033[0m | {behavior} {len(resp1.content)}b > {len(resp2.content)}b | PAYLOAD: Connection: {headers['Connection']}")
        return resp2
    return None

# Function to test for cache poisoning
def CachePoisoning(url, s, params2, resp1, resp2, authent, headers):
    try:
        resp3 = s.get(url, params=params2, auth=authent, allow_redirects=False, verify=False, timeout=10)
    except requests.exceptions.ConnectionError as e:
        pass
        #print(f"Error : {e}")
    
    if resp3.status_code == resp2.status_code and resp3.status_code != resp1.status_code and resp2.status_code != 429:
        print(f"  \033[31m └── [VULNERABILITY CONFIRMED]\033[0m | {VULN_NAME} | DIFFERENT STATUS-CODE {resp1.status_code} > {resp3.status_code} | \033[34m{url}?cacheBuster={params2['cacheBuster']}\033[0m | PAYLOAD: Connection {headers['Connection']}")

def HBH(url, s, req_main, main_len, main_status_code, authent):
    uri = f"{url}?cacheBuster={random.randint(1, 100)}"

    resp1 = req_main
    
    with open("./modules/lists/lowercase-headers.lst", "r") as f:
        lines = f.read().split('\n')
        for header in lines:
            headers = {'Connection': f'keep-alive, {header}'}
            params2 = {'cacheBuster': generate_cache_buster()}
            try:
                resp2 = compareRequests(url, s, headers, resp1, params2, authent)
            
                if resp2:
                    CachePoisoning(url, s, params2, resp1, resp2, authent, headers)
            except Exception as e:
                pass
                #print(f"Error : {e}")
