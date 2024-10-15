#!/usr/bin/python3 
# -*- coding: utf-8 -*-

"""
Attempts to find Hop-By-Hop Header abuse
https://nathandavison.com/blog/abusing-http-hop-by-hop-request-headers
"""

from ..utils import *

VULN_NAME = "Hop-By-Hop"

# Function to test for cache poisoning
def cachePoisoning(url, s, params2, resp1, resp2, authent, headers):
    try:
        resp3 = s.get(url, params=params2, auth=authent, allow_redirects=False, verify=False, timeout=10)
    except requests.exceptions.ConnectionError as e:
        pass
        #print(f"Error : {e}")
    reason = ""
    if resp3.status_code == resp2.status_code and resp3.status_code != resp1.status_code and resp3.status_code != 429:
        reason = f"DIFFERENT STATUS-CODE {resp1.status_code} > {resp3.status_code}"
    if len(resp3.content) == len(resp2.content) and len(resp3.content) != len(resp1.content) and resp3.status_code != 429:
        reason = f"DIFFERENT RESPONSE LENGTH {len(resp1.content)}b > {len(resp3.content)}b"

    if reason:
        print(f" \033[31m└── [VULNERABILITY CONFIRMED]\033[0m | {VULN_NAME} | \033[34m{url}?cacheBuster={params2['cacheBuster']}\033[0m | {reason} | PAYLOAD: Connection: {headers['Connection']}")


def HBH(url, s, req_main, main_len, main_status_code, authent):
    uri = f"{url}?cacheBuster={random.randint(1, 100)}"

    resp1 = req_main
    resp2_stat = 0
    resp2_count_code = 0

    resp2_size = 0
    resp2_count_size = 0
    
    with open("./modules/lists/lowercase-headers.lst", "r") as f:
        lines = f.read().split('\n')
        for header in lines:
            headers = {'Connection': f'keep-alive, {header}'}
            params2 = {'cacheBuster': generate_cache_buster()}
            try:
                resp2 = s.get(url, headers=headers, params=params2, auth=authent, allow_redirects=False, verify=False, timeout=10)
                #print(f"return: {resp2}") #DEBUG
                #print(resp2_stat) #DEBUG

                if resp2.status_code != resp2_stat and resp2.status_code != resp1.status_code:
                    resp2_stat = resp2.status_code
                    resp2_count_code = 0
                else:
                    resp2_count_code += 1

                if len(resp2.content) != resp2_size and len(resp2.content) != 0:
                    resp2_size = len(resp2.content)
                    resp2_count_size = 0
                else:
                    resp2_count_size += 1

                behavior = ""
                if resp1.status_code != resp2.status_code and resp2.status_code not in [429, 403] and resp1.status_code not in [301, 302, 429, 403] and resp2_count_code < 3:
                    behavior = f"DIFFERENT STATUS-CODE  {resp1.status_code} > {resp2.status_code}"

                if len(resp1.content) not in range(len(resp2.content) - 1000, len(resp2.content) + 1000) and resp2.status_code not in [429, 403] and resp1.status_code not in [301, 302, 429, 403] and resp2_count_size < 3:
                    behavior = f"DIFFERENT RESPONSE LENGTH  {len(resp1.content)}b > {len(resp2.content)}b"

                if behavior:
                    print(f" \033[33m└── [INTERESTING BEHAVIOR]\033[0m | {VULN_NAME} | \033[34m{url}?cacheBuster={params2['cacheBuster']}\033[0m | {behavior} | PAYLOAD: Connection: {headers['Connection']}")
                    cachePoisoning(url, s, params2, resp1, resp2, authent, headers)

            except Exception as e:
                pass
                #print(f"Error : {e}")
            sys.stdout.write(f" \033[34m {headers}\033[0m\r")
            sys.stdout.write("\033[K")
