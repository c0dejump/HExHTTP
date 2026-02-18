#!/usr/bin/env python3

"""
https://blog.ostorlab.co/litespeed-cache,cve-2024-47374.html
"""

from utils.style import Colors, Identify
from utils.utils import configure_logger, requests, sys

logger = configure_logger(__name__)

# Pages WordPress avec LiteSpeed Cache à tester
LITESPEED_PAGES = [
    "wp-admin/admin.php?page=lscache-ccss",
    "wp-admin/admin.php?page=lscache",
    "wp-admin/admin.php?page=lscache-purge",
    "wp-admin/admin.php?page=lscache-settings",
    "wp-admin/admin.php?page=lscache-advanced",
]


def detect_wordpress_litespeed(url: str) -> bool:
    """
    Détecte si la cible est WordPress avec LiteSpeed Cache
    
    Args:
        url: URL de base
        
    Returns:
        True si WordPress + LiteSpeed détecté
    """
    try:
        response = requests.get(url, verify=False, timeout=10, allow_redirects=True)
        
        # Vérification des headers LiteSpeed
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
    Teste CVE-2024-47374 (LiteSpeed Cache XSS via X-LSCACHE-VARY-VALUE)
    
    Args:
        base_url: URL de base de la cible
    """
    # Détection préalable de WordPress + LiteSpeed
    if not detect_wordpress_litespeed(base_url):
        logger.debug("Target doesn't appear to be WordPress with LiteSpeed Cache")
        return
    
    print(f" ├── CVE-2024-47374 WordPress with LiteSpeed Cache detected")
    
    # Utiliser un marqueur unique au lieu d'un payload XSS
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
            
            # Vérifier si le marqueur est reflété dans la réponse
            if test_marker in response.text:
                print(
                    f" {Identify.behavior} | CVE-2024-47374 | {Colors.BLUE}{target_url}{Colors.RESET} | TAG OK | PAYLOAD: {headers}"
                )
                
                # Tester l'empoisonnement du cache
                for _ in range(5):
                    requests.get(
                        target_url,
                        headers=headers,
                        verify=False,
                        timeout=10,
                        allow_redirects=False
                    )
                
                # Vérifier la persistence
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