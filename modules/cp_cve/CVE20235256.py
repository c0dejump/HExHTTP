#!/usr/bin/env python3

"""
https://github.com/elttam/publications/blob/master/writeups/CVE-2023-5256.md
"""

from utils.style import Colors, Identify
from utils.utils import configure_logger, requests

logger = configure_logger(__name__)

# Status codes à exclure de la détection
EXCLUDED_STATUS_CODES = [200, 301, 302, 307, 308, 401, 403, 404]


def drupaljsonapi(url: str, headers: dict) -> None:
    """
    Détecte CVE-2023-5256 (Drupal JSONAPI cache poisoning)
    
    Args:
        url: URL de base de la cible
        headers: Headers personnalisés à inclure dans les requêtes
    """
    payload = "/jsonapi/user/user?filter[a-labex][condition][path]=cachingyourcookie"
    uri = f"{url}{payload}"
    
    try:
        req = requests.get(
            uri,
            headers=headers,
            verify=False,
            timeout=10,
            allow_redirects=False
        )
        
        # Vérification optimisée: d'abord check "jsonapi" (rapide), puis status code
        if "jsonapi" not in req.text:
            return
            
        if req.status_code in EXCLUDED_STATUS_CODES:
            return
        
        # Vérification de réflexion des headers dans le corps de réponse
        headers_reflected = []
        
        # Vérifier si Cookie header est reflété
        if "Cookie" in headers and "Cookie" in req.text:
            # Vérification plus précise: chercher la valeur du cookie, pas juste le mot "Cookie"
            cookie_value = headers.get("Cookie", "")
            if cookie_value and cookie_value in req.text:
                headers_reflected.append("Cookie")
        
        # Vérifier si User-Agent header est reflété
        if "User-Agent" in headers and "User-Agent" in req.text:
            user_agent_value = headers.get("User-Agent", "")
            if user_agent_value and user_agent_value in req.text:
                headers_reflected.append("User-Agent")
        
        # Si les headers sont reflétés, c'est confirmé
        if len(headers_reflected) >= 2:
            print(
                f" {Identify.confirmed} | CVE-2023-5256 | {Colors.BLUE}{uri}{Colors.RESET} | {req.status_code} | Headers reflected: {', '.join(headers_reflected)}"
            )
        elif len(headers_reflected) > 0:
            print(
                f" {Identify.behavior} | CVE-2023-5256 | {Colors.BLUE}{uri}{Colors.RESET} | {req.status_code} | Partial reflection detected"
            )
        else:
            # Comportement anormal même sans réflexion de headers
            print(
                f" {Identify.behavior} | CVE-2023-5256 | {Colors.BLUE}{uri}{Colors.RESET} | {req.status_code} | Abnormal response"
            )
            
    except requests.Timeout as t:
        logger.error(f"request timeout {uri}: {t}")
    except Exception as e:
        logger.exception(f"request error {uri}: {e}")