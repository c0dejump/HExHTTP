#!/usr/bin/env python3

"""
Module pour trouver des pages "sans risque" (mentions légales, CGU, etc.)
utilisées pour tester les vulnérabilités de cache poisoning sans impacter
les pages critiques.
"""

import warnings
from bs4 import BeautifulSoup
from bs4.element import Tag
from bs4 import MarkupResemblesLocatorWarning

# Ignorer les warnings BeautifulSoup pour le markup
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

from utils.utils import re, requests, urljoin

# Chemins communs de pages sans risque
COMMON_PATHS = [
    "releases",
    "referral-program",
    "accessibilite",
    "mentions-legales",
    "mentions",
    "legal",
    "cgu",
    "terms",
    "conditions",
    "terms-of-service",
    "privacy",
    "politique-de-confidentialite",
    "privacy-policy",
    "faq",
    "about",
    "contact",
    "help",
    "support",
]

# Regex pour détecter les pages sans risque dans le contenu
COMMON_REGEX = re.compile(
    r"|".join(re.escape(path).replace("-", r"[-\s]*") for path in COMMON_PATHS),
    re.IGNORECASE,
)

# Cache simple pour éviter de tester plusieurs fois la même URL
_UNRISK_CACHE = {}


def get_unrisk_page(
    base_url: str,
    s: requests.Session,
    response: requests.Response,
    timeout: int = 5,
) -> str | None:
    """
    Trouve une page "sans risque" sur un site (mentions légales, CGU, etc.)
    
    Args:
        base_url: URL de base du site
        s: Session requests à utiliser
        response: Réponse HTTP de la page principale (pour parser les liens)
        timeout: Timeout en secondes pour les requêtes de test
        
    Returns:
        URL de la page sans risque trouvée, ou None
    """
    # Vérifier le cache
    if base_url in _UNRISK_CACHE:
        return _UNRISK_CACHE[base_url]
    
    # Méthode 1: Parser les liens de la page actuelle
    unrisk_url = find_unrisk_in_page(base_url, response)
    if unrisk_url:
        _UNRISK_CACHE[base_url] = unrisk_url
        return unrisk_url
    
    # Méthode 2: Tester les chemins communs
    unrisk_url = test_common_paths(base_url, s, timeout)
    if unrisk_url:
        _UNRISK_CACHE[base_url] = unrisk_url
        return unrisk_url
    
    # Aucune page sans risque trouvée
    _UNRISK_CACHE[base_url] = None
    return None


def find_unrisk_in_page(base_url: str, response: requests.Response) -> str | None:
    """
    Cherche des liens vers des pages sans risque dans le HTML de la page
    
    Args:
        base_url: URL de base
        response: Réponse HTTP contenant le HTML
        
    Returns:
        URL trouvée ou None
    """
    try:
        soup = BeautifulSoup(response.text, "html.parser")
        
        # Recherche dans tous les liens
        for link in soup.find_all("a", href=True):
            href = link.get("href")
            
            if not href or not isinstance(href, str):
                continue
            
            href_lower = href.lower()
            
            # Vérifier si le lien contient un des mots-clés
            if any(keyword in href_lower for keyword in COMMON_PATHS):
                return urljoin(base_url, href)
        
        return None
        
    except Exception:
        return None


def test_common_paths(
    base_url: str,
    s: requests.Session,
    timeout: int,
) -> str | None:
    """
    Teste les chemins communs directement
    
    Args:
        base_url: URL de base
        s: Session requests
        timeout: Timeout pour chaque requête
        
    Returns:
        URL trouvée ou None
    """
    for path in COMMON_PATHS:
        test_url = urljoin(base_url, "/" + path)
        
        try:
            resp = s.get(test_url, timeout=timeout, verify=False, allow_redirects=True)
            
            # Vérifier si la page existe et contient du contenu pertinent
            if resp.status_code == 200 and len(resp.content) > 100:
                # Vérifier que le contenu correspond bien à une page sans risque
                if COMMON_REGEX.search(resp.text):
                    return test_url
                    
        except requests.RequestException:
            continue
    
    return None


def clear_cache() -> None:
    """Vide le cache des pages sans risque"""
    global _UNRISK_CACHE
    _UNRISK_CACHE = {}