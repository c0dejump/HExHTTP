#!/usr/bin/env python3

from utils.style import Colors, Identify
from utils.utils import random, requests, sys

"""
ORIGIN CORS poisoning. 
by Geluchat

"""


def print_result(status: str, vuln: str, reason: str, url: str, payload: str) -> None:
    if payload:
        print(
            f" {status} | {vuln} | {reason} | {Colors.BLUE}{url}{Colors.RESET} |{Colors.THISTLE}{payload}{Colors.RESET}"
        )


def verify_ocd_caching(url: str, method: str, headers: dict[str, str]) -> None:
    for _ in range(5):
        requests.request(
            method,
            url=url,
            headers=headers,
            verify=False,
            allow_redirects=False,
            timeout=10,
        )
    req_main = requests.get(url, verify=False, allow_redirects=False, timeout=10)
    if "geluorigin" in req_main.text:
        print_result(
            Identify.confirmed,
            "OCD",
            f"{method} BODY REFLECTION",
            url,
            "PAYLOAD: 'Origin: https://geluorigin.chat'",
        )
    if "geluorigin" in req_main.headers:
        print_result(
            Identify.confirmed,
            "OCD",
            f"{method} HEADER REFLECTION",
            url,
            "PAYLOAD: 'Origin: https://geluorigin.chat'",
        )


def get_ocd(
    url: str,
    headers: dict[str, str],
    authent: tuple[str, str] | None,
) -> None:
    req_get = requests.get(
        url,
        headers=headers,
        verify=False,
        allow_redirects=False,
        auth=authent,
        timeout=10,
    )
    if "geluorigin" in req_get.text:
        print_result(
            Identify.behavior,
            "OCD",
            "GET BODY REFLECTION",
            url,
            "PAYLOAD: 'Origin: https://geluorigin.chat'",
        )
        verify_ocd_caching(url, "GET", headers)
    if "geluorigin" in req_get.headers:
        print_result(
            Identify.behavior,
            "OCD",
            "GET HEADER REFLECTION",
            url,
            "PAYLOAD: 'Origin: https://geluorigin.chat'",
        )
        verify_ocd_caching(url, "GET", headers)


def options_ocd(
    url: str,
    headers: dict[str, str],
    authent: tuple[str, str] | None,
) -> None:
    req_options = requests.options(
        url,
        headers=headers,
        verify=False,
        allow_redirects=False,
        auth=authent,
        timeout=10,
    )
    if "geluorigin" in req_options.text:
        print_result(
            Identify.behavior,
            "OCD",
            "OPTIONS BODY REFLECTION",
            url,
            "PAYLOAD: 'Origin: https://geluorigin.chat'",
        )
        verify_ocd_caching(url, "OPTIONS", headers)
    if "geluorigin" in req_options.headers:
        print_result(
            Identify.behavior,
            "OCD",
            "OPTIONS HEADER REFLECTION",
            url,
            "PAYLOAD: 'Origin: https://geluorigin.chat'",
        )
        verify_ocd_caching(url, "OPTIONS", headers)


def OCP(url: str, authent: tuple[str, str] | None) -> None:
    headers = {"Origin": "https://geluorigin.chat"}
    get_ocd(f"{url}{random.randrange(999)}", headers, authent)
    options_ocd(f"{url}{random.randrange(999)}", headers, authent)

