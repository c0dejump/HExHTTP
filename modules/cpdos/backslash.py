#! /usr/bin/env python3

from utils.style import Colors, Identify
from utils.utils import cache_tag_verify, random, requests, urlparse

VULN_NAME = "BACKSLASH "


def parse_path(url_b: str) -> str | None:
    parsed = urlparse(url_b)
    base = f"{parsed.scheme}://{parsed.netloc}"
    segments = parsed.path.split("/")

    if len(segments) > 2:
        new_path = "/" + "\\".join(segments[1:])
    else:
        return None

    result = base + new_path
    result += "?" + parsed.query
    return result


def backslash_test(
    pp: str, url_b: str, req_main: requests.Response, s: requests.Session
) -> None:
    for _ in range(0, 5):
        req_b = s.get(pp, verify=False, timeout=10, allow_redirects=False)
    cache_status = cache_tag_verify(req_b)
    if req_b.status_code != req_main.status_code:
        print(
            f" {Identify.behavior} | {VULN_NAME} {req_main.status_code} > {req_b.status_code} | CACHETAG : {cache_status} | {Colors.BLUE}{url_b}{Colors.RESET} | PAYLOAD: {Colors.THISTLE}{pp}{Colors.RESET}"
        )
        vcp_c = vcp_code(url_b, s, req_b)
        if vcp_c:
            print(
                f" {Identify.confirmed} | {VULN_NAME} {req_main.status_code} > {req_b.status_code} | CACHETAG : {cache_status} | {Colors.BLUE}{url_b}{Colors.RESET} | PAYLOAD: {Colors.THISTLE}{pp}{Colors.RESET}"
            )
    elif len(req_b.content) != len(req_main.content):
        print(
            f" {Identify.behavior} | {VULN_NAME} {len(req_main.content)}b > {len(req_b.content)}b | CACHETAG : {cache_status} | {Colors.BLUE}{url_b}{Colors.RESET} | PAYLOAD: {Colors.THISTLE}{pp}{Colors.RESET}"
        )
        vcp_l = vcp_len(url_b, s, req_b)
        if vcp_l:
            print(
                f" {Identify.confirmed} | {VULN_NAME} {len(req_main.content)}b > {len(req_b.content)}b | CACHETAG : {cache_status} | {Colors.BLUE}{url_b}{Colors.RESET} | PAYLOAD: {Colors.THISTLE}{pp}{Colors.RESET}"
            )


def vcp_code(url_b: str, s: requests.Session, req_b: requests.Response) -> bool:
    req_verify = s.get(
        url_b,
        verify=False,
        headers={"User-agent": "xxxxxxx"},
        timeout=10,
        allow_redirects=False,
    )
    if req_verify.status_code == req_b.status_code:
        print(req_verify.status_code)
        return True
    else:
        return False


def vcp_len(url_b: str, s: requests.Session, req_b: requests.Response) -> bool:
    req_verify = s.get(
        url_b,
        verify=False,
        headers={"User-agent": "xxxxxxx"},
        timeout=10,
        allow_redirects=False,
    )
    if len(req_verify.content) == len(req_b.content):
        print(len(req_verify.content))
        return True
    else:
        return False


def backslash_poisoning(uri: str, s: requests.Session) -> None:
    url_b = f"{uri}?cb={random.randrange(999)}"
    req_main = s.get(url_b, verify=False, timeout=10, allow_redirects=False)
    pp = parse_path(url_b)
    if pp:
        backslash_test(pp, url_b, req_main, s)
