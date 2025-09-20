#!/usr/bin/env python3

"""
Based on Zhero research
https://zhero-web-sec.github.io/research-and-things/nuxt-show-me-your-payload
"""

from modules.cp_cve.unrisk_page import get_unrisk_page
from utils.style import Colors, Identify
from utils.utils import configure_logger, requests, sys

logger = configure_logger(__name__)


def nuxt_check(
    url: str,
    s: requests.Session,
    req_main: requests.Response,
    custom_header: dict,
    authent: tuple[str, str] | None,
) -> None:
    try:
        req = s.get(
            url,
            verify=False,
            auth=authent,
            headers=custom_header,
            timeout=10,
            allow_redirects=False,
        )
        unrisk_page = get_unrisk_page(url, s, req_main)
        if unrisk_page:
            poison_url = (
                f"{unrisk_page}_payload.json"
                if unrisk_page[-1] == "/"
                else f"{unrisk_page}/_payload.json"
            )
            try:
                req_nuxt = s.get(
                    poison_url,
                    verify=False,
                    auth=authent,
                    headers=custom_header,
                    timeout=10,
                    allow_redirects=False,
                )
                try:
                    req_nuxt.json()
                    print(
                        f" {Identify.behavior} | CVE-2025-27415 | TAG OK | {Colors.BLUE}{poison_url}{Colors.RESET}"
                    )
                except requests.exceptions.JSONDecodeError:
                    if "application/json" in req_nuxt.headers.get("Content-Type", ""):
                        print(
                            f" {Identify.behavior} | CVE-2025-27415 | TAG OK | {Colors.BLUE}{poison_url}{Colors.RESET}"
                        )
                    if req_nuxt.status_code != req.status_code:
                        print(
                            f" {Identify.behavior} | CVE-2025-27415 | DIFFERENT RESPONSE {req.status_code} > {req_nuxt.status_code}| {Colors.BLUE}{url}{Colors.RESET}"
                        )
                except Exception as e:
                    logger.exception(e)
                # Check exploit
                req_verify = s.get(
                    unrisk_page,
                    verify=False,
                    auth=authent,
                    headers=custom_header,
                    timeout=10,
                    allow_redirects=False,
                )
                try:
                    req_verify.json()
                    print(
                        f" {Identify.confirmed} | CVE-2025-27415 | TAG OK | {Colors.BLUE}{unrisk_page}{Colors.RESET}"
                    )
                except requests.exceptions.JSONDecodeError:
                    if "application/json" in req_verify.headers.get("Content-Type", ""):
                        print(
                            f" {Identify.confirmed} | CVE-2025-27415 | TAG OK | {Colors.BLUE}{unrisk_page}{Colors.RESET}"
                        )
                    if req_verify.status_code != req.status_code:
                        print(
                            f" {Identify.confirmed} | CVE-2025-27415 | DIFFERENT RESPONSE {req.status_code} > {req_verify.status_code} | {Colors.BLUE}{unrisk_page}{Colors.RESET}"
                        )
                except Exception as e:
                    logger.exception(e)
            except Exception as e:
                logger.exception(e)
        else:
            print(
                " CVE-2025-27415 | [i] It seems that the nuxt.js framework is used, but no risk-free pages have been found. Please do a manual check."
            )

    except requests.Timeout as t:
        logger.error("request timeout", t)
    except KeyboardInterrupt:
        print("Exiting")
        sys.exit()
    except Exception as e:
        logger.exception(e)
