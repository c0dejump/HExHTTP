#!/usr/bin/env python3

from utils.style import Colors
from utils.utils import random, requests, sys


def envoy(url: str, s: requests.Session) -> None:
    """
    Envoy:
    X-Envoy-external-adress
    X-Envoy-internal
    X-Envoy-Original-Dst-Host
    X-Echo-Set-Header: X-Foo: value1
    """
    url = f"{url}?cb={random.randint(1, 100)}"
    envoy_header_list = [
        {"X-Envoy-external-adress": "plop123"},
        {"X-Envoy-internal": "plop123"},
        {"X-Envoy-Original-Dst-Host": "plop123"},
        {"X-Echo-Set-Header": "X-Foo: plop123"},
        {"x-envoy-original-path": "/plop123"},
    ]
    for ehl in envoy_header_list:
        x_req = s.get(url, headers=ehl, verify=False, timeout=10)
        print(
            f"   └── {ehl}{'→':^3} {x_req.status_code:>3} [{len(x_req.content)} bytes]"
        )
        if "plop123" in x_req.text or "plop123" in x_req.headers:
            print(
                f"{Colors.YELLOW}   └── INTERESTING BEHAVIOR{Colors.RESET} | HEADER REFLECTION | {Colors.BLUE}{url}{Colors.RESET} | PAYLOAD: {ehl}"
            )


if __name__ == "__main__":

    url = sys.argv[1]
    url = f"{url}?cb={random.randint(1, 100)}"
    s = requests.session()

    envoy(url, s)
