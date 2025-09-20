#!/usr/bin/env python3
# main_status_code: int, main_len: int, authent: tuple[str, str] | None are not used ??

import random
import sys

import requests
import urllib3

from utils.style import Colors, Identify

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def print_result(status: str, vuln: str, reason: str, url: str, payload: str) -> None:
    if payload:
        print(
            f" {status} | {vuln} | {reason} | {Colors.BLUE}{url}{Colors.RESET} |{Colors.THISTLE}{payload}{Colors.RESET}"
            )


def verify_ocd_caching(url: str, method: str, headers: dict[str, str]) -> None:
    for _ in range(5):
        requests.request(method, url=url, headers=headers, verify=False, allow_redirects=False, timeout=10)
    req_main = requests.get(url, verify=False, allow_redirects=False, timeout=10)
    if 'geluorigin' in req_main.text:
        print_result(Identify.confirmed, "OCD", f"{method} BODY REFLECTION", url, "PAYLOAD: 'Origin: https://geluorigin.chat'")
    if 'geluorigin' in req_main.headers:
        print_result(Identify.confirmed, "OCD", f"{method} HEADER REFLECTION", url, "PAYLOAD: 'Origin: https://geluorigin.chat'")


def get_ocd(url: str, headers: dict[str, str], main_status_code: int, main_len: int, authent: tuple[str, str] | None) -> None:
    req_get = requests.get(url, headers=headers, verify=False, allow_redirects=False, timeout=10)
    if 'geluorigin' in req_get.text:
        print_result(Identify.behavior, "OCD", "GET BODY REFLECTION", url, "PAYLOAD: 'Origin: https://geluorigin.chat'")
        verify_ocd_caching(url, "GET", headers)
    if 'geluorigin' in req_get.headers:
        print_result(Identify.behavior, "OCD", "GET HEADER REFLECTION", url, "PAYLOAD: 'Origin: https://geluorigin.chat'")
        verify_ocd_caching(url, "GET", headers)


def options_ocd(url: str, headers: dict[str, str], main_status_code: int, main_len: int, authent: tuple[str, str] | None) -> None:
    req_options = requests.options(url, headers=headers, verify=False, allow_redirects=False, timeout=10)
    if 'geluorigin' in req_options.text:
        print_result(Identify.behavior, "OCD", "OPTIONS BODY REFLECTION", url, "PAYLOAD: 'Origin: https://geluorigin.chat'")
        verify_ocd_caching(url, "OPTIONS", headers)
    if 'geluorigin' in req_options.headers:
        print_result(Identify.behavior, "OCD", "OPTIONS HEADER REFLECTION", url, "PAYLOAD: 'Origin: https://geluorigin.chat'")
        verify_ocd_caching(url, "OPTIONS", headers)



def OCD(url: str, req_main: requests.Response, authent: tuple[str, str] | None) -> None:
    main_len = len(req_main.content)
    main_status_code = req_main.status_code
    uri = f"{url}{random.randrange(999)}"
    headers = {
        'Origin': 'https://geluorigin.chat'
    }
    get_ocd(uri, headers, main_status_code, main_len, authent)
    options_ocd(uri, headers, main_status_code, main_len, authent)



if __name__ == '__main__':
    url_file = sys.argv[1]
    with open(url_file) as url_file_handle:
        url_list = url_file_handle.read().splitlines()
        for url in url_list:
            url = f"{url}?cb=foo"
            try:
                req_main = requests.get(url, verify=False, headers={"User-Agent": "xxxx"}, timeout=10, allow_redirects=False)
                authent = None
                OCD(url, req_main, authent)
            except KeyboardInterrupt:
                print("Exiting")
                sys.exit()
            except requests.ConnectionError:
                pass
                #print("Error, cannot connect to target")
            except requests.Timeout:
                pass
                #print("Error, request timeout (10s)")
            except Exception as e:
                print(f"Error : {e}")
                pass
            print(f" {url}", end='\r')