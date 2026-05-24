#!/usr/bin/env python3

"""
https://blog.ostorlab.co/litespeed-cache,cve-2024-47374.html
"""

from utils.style import Colors, Identify
from utils.utils import configure_logger, requests, sys

logger = configure_logger(__name__)

LITESPEED_PAGES = [
    "wp-admin/admin.php?page=lscache-ccss",
    "wp-admin/admin.php?page=lscache",
    "wp-admin/admin.php?page=lscache-purge",
    "wp-admin/admin.php?page=lscache-settings",
    "wp-admin/admin.php?page=lscache-advanced",
]


def detect_wordpress_litespeed(url: str) -> bool:
    try:
        response = requests.get(url, verify=False, timeout=10, allow_redirects=True)
        
        litespeed_headers = [
            "x-litespeed-cache",
            "x-lsadc-cache",
            "x-litespeed-tag",
        ]
        
        for header in litespeed_headers:
            if header in response.headers:
                return True
        
        # Vérification dans le contenu HTML
        if "wp-content" in response.text and "litespeed" in response.text.lower():
            return True
            
        return False
        
    except Exception as e:
        logger.debug(f"Error detecting WordPress/LiteSpeed: {e}")
        return False


def litespeed(base_url: str) -> None:
    """
    Test CVE-2024-47374 (LiteSpeed Cache XSS via X-LSCACHE-VARY-VALUE)
    
    """
    if not detect_wordpress_litespeed(base_url):
        logger.debug("Target doesn't appear to be WordPress with LiteSpeed Cache")
        return
    
    print(f" ├── CVE-2024-47374 WordPress with LiteSpeed Cache detected")
    
    test_marker = "x-cve-2024-47374-test"
    headers = {"X-LSCACHE-VARY-VALUE": f'"{test_marker}'}

    for page in LITESPEED_PAGES:
        target_url = f"{base_url}/{page}"
        
        try:
            response = requests.get(
                target_url,
                headers=headers,
                verify=False,
                timeout=10,
                allow_redirects=False
            )
            
            if test_marker in response.text:
                print(
                    f" {Identify.behavior} | CVE-2024-47374 | {Colors.BLUE}{target_url}{Colors.RESET} | TAG OK | PAYLOAD: {headers}"
                )
                
                for _ in range(3):
                    requests.get(
                        target_url,
                        headers=headers,
                        verify=False,
                        timeout=10,
                        allow_redirects=False
                    )
                
                req_verify = requests.get(
                    target_url,
                    verify=False,
                    timeout=10,
                    allow_redirects=False
                )
                
                if test_marker in req_verify.text:
                    print(
                        f" {Identify.confirmed} | CVE-2024-47374 | {Colors.BLUE}{target_url}{Colors.RESET} | CACHE POISONED"
                    )
                    
        except requests.Timeout as t:
            logger.error(f"request timeout {target_url}: {t}")
        except KeyboardInterrupt:
            print("Exiting")
            sys.exit()
        except Exception as e:
            logger.exception(f"request error {target_url}: {e}")