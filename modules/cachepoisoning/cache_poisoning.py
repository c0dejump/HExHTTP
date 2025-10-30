#!/usr/bin/env python3

"""
Attempts to find Cache Poisoning without "DoS"
https://cpdos.org/
"""

import utils.proxy as proxy
from modules.lists import payloads_keys
from utils.style import Identify, Colors
from utils.utils import (
    configure_logger,
    human_time,
    random,
    requests,
    sys,
    range_exclusion,
    random_ua,
)
from utils.print_utils import print_results, cache_tag_verify
from modules.lists import wcp_headers


CANARY = "byhexhttpbzh.com"


def randomiz_url(url):
    return f"{url}?cphexhttp={random.randint(1, 9999)}"

def dvcp(uri, s, headers, custom_header, authent, human):
    for _ in range(3):
        dup_req = s.get(
            uri,
            headers=headers,
            verify=False,
            allow_redirects=False,
            timeout=6,
        )
    verif_req = requests.get(
            uri,
            headers=custom_header,
            verify=False,
            allow_redirects=False,
            timeout=6,
        )
    return dup_req, verif_req


def port_poisoning(url, s, initialResponse, custom_header, authent, human):
    VULN_NAME = "HPP"

    host = url.split("://")[1].split("/")[0]

    pheaders = [
        {"Host": f"{host}:31337"},
        {"X-Forwarded-Port": "31337"},
        {"x-forwarded-proto": "31337"},
        {"X-Forwarded-Host": f"{host}:31337"},
        {"X-Host": f"{host}:31337"},
        {"X-HTTP-Host-Override": f"{host}:31337"},
        {"Forwarded": f"{host}:31337"},
        {"Forwarded": f"host={host}:31337"},
        {"Forwarded": f"for={host}:31337"},
        {"X-URL-Scheme": "https"},
        {"Front-End-Https": "on"},
        {"X-Original-URL": f"{host}:31337"},
        {"X-Rewrite-URL": f"{host}:31337"},
        {"CF-Connecting-IP": f"{host}:31337"},
        {"True-Client-IP": f"{host}:31337"},
        {"X-Real-IP": f"{host}:31337"},
        {"X-ProxyUser-Ip": f"{host}:31337"},
        {"X-Forwarded-Server": f"{host}:31337"},
        {"X-Custom-IP-Authorization": f"{host}:31337"},
    ]

    try:
        for ph in pheaders:
            uri = randomiz_url(url)

            if custom_header:
                ph.update(custom_header)

            response = s.get(
                uri,
                headers=ph,
                verify=False,
                allow_redirects=False,
                timeout=6,
            )
            human_time(human)
            ctv = cache_tag_verify(response)

            if (
                response.status_code != initialResponse.status_code
                and response.status_code not in [429, 401, 403]
            ):
                print_results(Identify.behavior, VULN_NAME, f"{initialResponse.status_code} > {response.status_code}", ctv, uri, ph)
                dup_req, verif_req = dvcp(uri, s, ph, custom_header, authent, human)
                if (
                    dup_req.status_code == verif_req.status_code 
                   and verif_req.status_code != initialResponse.status_code
                   ):
                    print_results(Identify.confirmed, VULN_NAME, f"{initialResponse.status_code} > {verif_req.status_code}", ctv, uri, ph)
            if "31337" in response.text:
                print_results(Identify.behavior, VULN_NAME, f"| 31337 IN BODY", ctv, uri, ph)
                dup_req, verif_req = dvcp(uri, s, ph, custom_header, authent, human)
                if "31337" in verif_req.text:
                    print_results(Identify.confirmed, VULN_NAME, f"| 31337 IN BODY", ctv, uri, ph)
            if "31337" in response.headers:
                print_results(Identify.behavior, VULN_NAME, f"| 31337 IN HEADER", ctv, uri, ph)
                dup_req, verif_req = dvcp(uri, s, ph, custom_header, authent, human)
                if "31337" in verif_req.headers:
                    print_results(Identify.confirmed, VULN_NAME, f"| 31337 IN HEADER", ctv, uri, ph)

    except Exception as e:
        #print(f" └── Error with Host: {host}:8888 header: {e}")
        # traceback.print_exc()
        print(f"Error: {e}")



def reflected_cache_poisoning(url, s, initialResponse, custom_header, authent, human):
    VULN_NAME = "Web Cache Poisoning"

    for pl in wcp_headers:
        
        headers = {pl: CANARY}

        uri = randomiz_url(url)

        if custom_header:
            headers.update(custom_header)

        s.headers.update(random_ua())
        response = s.get(
            uri,
            headers=headers,
            verify=False,
            allow_redirects=False,
            timeout=6,
            )

        ctv = cache_tag_verify(response)

        if CANARY in response.text:
            print_results(Identify.behavior, VULN_NAME, "BODY REFLECTION", ctv, uri, headers)

            dup_req, verif_req = dvcp(uri, s, headers, custom_header, authent, human)
            if CANARY in verif_req.headers:
                print_results(Identify.confirmed, VULN_NAME, "BODY REFLECTION", ctv, uri, headers)
        if CANARY in response.headers:
            print_results(Identify.behavior, VULN_NAME, "HEADER REFLECTION", ctv, uri, headers)

            dup_req, verif_req = dvcp(uri, s, headers, custom_header, authent, human)
            if CANARY in verif_req.headers:
                print_results(Identify.confirmed, VULN_NAME, "HEADER REFLECTION", ctv, uri, headers)
        if response.status_code != initialResponse.status_code and response.status_code not in [429, 401]:
            print_results(Identify.behavior, VULN_NAME, f"{initialResponse.status_code} > {response.status_code}", ctv, uri, headers)
            dup_req, verif_req = dvcp(uri, s, headers, custom_header, authent, human)
            if (
                dup_req.status_code == verif_req.status_code 
                and verif_req.status_code != initialResponse.status_code
                ):
                print_results(Identify.confirmed, VULN_NAME, f"{initialResponse.status_code} > {response.status_code}", ctv, uri, headers)

        print(f" {Colors.BLUE} {VULN_NAME} : {headers}{Colors.RESET}\r", end="")
        print("\033[K", end="")


def check_cache_poisoning(url, s, custom_header, authent, human):
    initialResponse = requests.get(
        randomiz_url(url),
        headers=custom_header,
        verify=False,
        allow_redirects=False,
        timeout=6,
    )
    print(f"{Colors.CYAN} ├ Cache poisoning analysis{Colors.RESET}")

    port_poisoning(url, s, initialResponse, custom_header, authent, human)
    reflected_cache_poisoning(url, s, initialResponse, custom_header, authent, human)