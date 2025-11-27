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
    re,
)
from utils.print_utils import print_results, cache_tag_verify
from modules.lists import wcp_headers
import traceback

logger = configure_logger(__name__)


CANARY = "byhexhttpbzh.com"

def crawl_files(
    url: str,
    s: requests.Session,
    req_main: requests.Response,
    custom_header,
    authent: tuple[str, str] | None,
    human: str,
) -> None:
    try:
        regexp1 = r'(?<=src=")(\/[^\/].+?\.(js|css|html|htm)(?=")'
        regexp2 = r'(?<=href=")(\/[^\/].+?\.(js|css|html|htm)(?=")'
        # regexp3 = r'(?<=src=")(\/[^\/].+?)(?=")'
        # regexp4 = r'(?<=href=")(\/[^\/].+?)(?=")'

        responseText = req_main.text

        filesURL = re.findall(regexp1, responseText)
        filesURL += re.findall(regexp2, responseText)
        # filesURL = re.findall(regexp3, responseText)
        # filesURL += re.findall(regexp4, responseText)

        for fu in filesURL:
            if "<" not in fu[0]:
                if len(url.split("/")) > 4:
                    url = f"{'/'.join(url.split('/')[:3])}/"
                uri = f"{url}{fu[0]}"
                if uri.startswith("https://"):
                    uri = f"https://{uri[8:].replace('//', '/')}"
                elif uri.startswith("http://"):
                    uri = f"https://{uri[7:].replace('//', '/')}"

                # print(uri)
                port_poisoning(uri, s, req_main, custom_header, authent, human)
                reflected_cache_poisoning(uri, s, req_main, custom_header, authent, human)


    except Exception as e:
        logger.exception(e)


def randomiz_url(url):
    return f"{url}?cphexhttp={random.randint(1, 9999)}"

def dvcp(uri, s, headers, custom_header, authent, human):
    for _ in range(3):
        dup_req = s.get(
            uri,
            headers=headers,
            verify=False,
            allow_redirects=False,
            timeout=8,
        )
    verif_req = requests.get(
            uri,
            headers=custom_header,
            verify=False,
            allow_redirects=False,
            timeout=8,
        )
    return dup_req, verif_req


def print_(identify, VULN_NAME, reason, cachetag, url, payload):
    print_results(identify, VULN_NAME, reason, cachetag, url, payload)
    if proxy.proxy_enabled:
        from utils.proxy import proxy_request
        proxy_request(s, url, "GET", headers=pk, data=None, severity="behavior" if "BEHAVIOR" in identify else "confirmed")


def port_poisoning(url, s, initialResponse, custom_header, authent, human):
    VULN_NAME = "HPP"

    host = url.split("://")[1].split("/")[0]

    pheaders = [
        {"Host": f"{host}:31337"},
        {"X-Forwarded-Port": "31337"},
        {"X-Forwarded-Port": "99999"},
        {"X-Forwarded-Port": "-1"},
        {"X-Forwarded-Port": "abc"},
        {"X-Forwarded-Port": "0x50"},
        {"X-Forwarded-Port": "80 80"},
        {"X-Forwarded-Port": "80@evil.com:443"},
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
                print_(Identify.behavior, VULN_NAME, f"{initialResponse.status_code} > {response.status_code}", ctv, uri, ph)
                dup_req, verif_req = dvcp(uri, s, ph, custom_header, authent, human)
                if (
                    dup_req.status_code == verif_req.status_code 
                   and verif_req.status_code != initialResponse.status_code
                   ):
                    print_(Identify.confirmed, VULN_NAME, f"{initialResponse.status_code} > {verif_req.status_code}", ctv, uri, ph)
            if "31337" in response.text:
                print_(Identify.behavior, VULN_NAME, f" 31337 IN BODY", ctv, uri, ph)
                dup_req, verif_req = dvcp(uri, s, ph, custom_header, authent, human)
                if "31337" in verif_req.text:
                    print_(Identify.confirmed, VULN_NAME, f" 31337 IN BODY", ctv, uri, ph)
            if "31337" in response.headers:
                print_results(Identify.behavior, VULN_NAME, f" 31337 IN HEADER", ctv, uri, ph)
                dup_req, verif_req = dvcp(uri, s, ph, custom_header, authent, human)
                if "31337" in verif_req.headers:
                    print_(Identify.confirmed, VULN_NAME, f" 31337 IN HEADER", ctv, uri, ph)

    except Exception as e:
        #traceback.print_exc()
        logger.exception(e)



def reflected_cache_poisoning(url, s, initialResponse, custom_header, authent, human):
    VULN_NAME = "WCP"

    try:
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
                print_(Identify.behavior, VULN_NAME, "BODY REFLECTION", ctv, uri, headers)

                dup_req, verif_req = dvcp(uri, s, headers, custom_header, authent, human)
                if CANARY in verif_req.headers:
                    print_(Identify.confirmed, VULN_NAME, "BODY REFLECTION", ctv, uri, headers)
            if CANARY in response.headers:
                print_(Identify.behavior, VULN_NAME, "HEADER REFLECTION", ctv, uri, headers)

                dup_req, verif_req = dvcp(uri, s, headers, custom_header, authent, human)
                if CANARY in verif_req.headers:
                    print_(Identify.confirmed, VULN_NAME, "HEADER REFLECTION", ctv, uri, headers)
            if response.status_code != initialResponse.status_code and response.status_code not in [429, 401]:
                print_(Identify.behavior, VULN_NAME, f"{initialResponse.status_code} > {response.status_code}", ctv, uri, headers)
                dup_req, verif_req = dvcp(uri, s, headers, custom_header, authent, human)
                if (
                    dup_req.status_code == verif_req.status_code 
                    and verif_req.status_code != initialResponse.status_code
                    ):
                    print_(Identify.confirmed, VULN_NAME, f"{initialResponse.status_code} > {response.status_code}", ctv, uri, headers)

            print(f" {Colors.BLUE} {VULN_NAME} : {headers}{Colors.RESET}\r", end="")
            print("\033[K", end="")
    except Exception as e:
        #traceback.print_exc()
        logger.exception(e)


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
    crawl_files(url, s, initialResponse, custom_header, authent, human)