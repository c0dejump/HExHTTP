#!/usr/bin/env python3
"""
Attempts to find Cache Poisoning without "DoS"
https://cpdos.org/
"""

import secrets
import utils.proxy as proxy
from modules.lists import payloads_keys, wcp_headers, top_reflected_payloads, REFLECT_MARKER
from utils.style import Identify, Colors
from utils.utils import (
    configure_logger, human_time, requests,
    range_exclusion, random_ua, re,
)
from utils.print_utils import print_results, cache_tag_verify
from utils.collect import add_finding

logger = configure_logger(__name__)

CANARY = "byhexhttpbzh-test-x9z"

# Codes non-exploitables en cache poisoning :
#   400 — valeur de header malformée rejetée upstream (ex: transfer-encoding: garbage)
#   401/403 — auth / WAF block
#   421 — Misdirected Request (host invalide rejeté par le frontal, non mis en cache)
#   429 — WAF rate limit (source fréquente de faux positifs)
NOISE_CODES = {401, 403, 421, 429}


def randomiz_url(url: str) -> str:
    return f"{url}?cphexhttp={secrets.token_hex(8)}"


def print_(
    identify: str,
    vuln_name: str,
    reason: str,
    cachetag: str,
    url: str,
    payload: dict,
    s: requests.Session | None = None,
    initial_response: requests.Response | None = None,
    current_response: requests.Response | None = None,
) -> None:
    print_results(identify, vuln_name, reason, cachetag, url, payload)

    severity = "critical" if identify == Identify.confirmed else "info"
    add_finding(url, {
        "type": "Cache poisoning",
        "severity": severity,
        "title": vuln_name,
        "description": reason,
        "payload": payload,
        "evidence": {
            "status_code": current_response.status_code if current_response else None,
            "response_size": len(current_response.content) if current_response else None,
            "initial_status": initial_response.status_code if initial_response else None,
            "initial_size": len(initial_response.content) if initial_response else None,
            "uri": url,
        }
    })

    if proxy.proxy_enabled and s is not None:
        severity_proxy = "behavior" if "BEHAVIOR" in identify else "confirmed"
        proxy.proxy_request(s, url, "GET", headers=payload, data=None, severity=severity_proxy)


def dvcp(
    uri: str,
    s: requests.Session,
    headers: dict,
    authent: tuple[str, str] | None = None,
) -> requests.Response:
    """
    Empoisonne le cache 3 fois puis retourne la réponse de vérification propre.
    """
    for _ in range(3):
        try:
            s.get(uri, headers=headers, verify=False,
                  allow_redirects=False, timeout=8, auth=authent)
        except requests.exceptions.RequestException as e:
            logger.error("poison request failed %s: %s", uri, e)
            break

    return s.get(uri, verify=False, allow_redirects=False, timeout=8, auth=authent)


def crawl_files(
    url: str,
    s: requests.Session,
    req_main: requests.Response,
    custom_header: dict,
    authent: tuple[str, str] | None,
    human: str,
) -> None:
    try:
        regexp1 = r'(?<=src=")(\/[^\/].+?\.(js|css|html|htm|jsp|svg|txt))(?=")'
        regexp2 = r'(?<=href=")(\/[^\/].+?\.(js|css|html|htm|jsp|svg|txt))(?=")'

        files_url = re.findall(regexp1, req_main.text)
        files_url += re.findall(regexp2, req_main.text)

        # base_url calculée une seule fois, hors boucle
        parts = url.split("/")
        base_url = f"{'/'.join(parts[:3])}/" if len(parts) > 4 else url

        for fu in files_url:
            if "<" in fu[0]:
                continue
            uri = f"{base_url}{fu[0].lstrip('/')}"
            uri = uri.replace("https://", "https://").replace("http://", "https://")

            try:
                req_ext = s.get(uri, verify=False, timeout=6, allow_redirects=False)
                if req_ext.status_code in {200, 301, 302}:
                    port_poisoning(uri, s, req_main, custom_header, authent, human)
                    reflected_cache_poisoning(uri, s, req_main, custom_header, authent, human)
            except requests.exceptions.RequestException as e:
                logger.error("crawl request failed %s: %s", uri, e)

    except Exception as e:
        logger.error("crawl_files error: %s", e)


def _is_status_change_interesting(
    initial_code: int,
    new_code: int,
) -> bool:
    """
    Retourne True uniquement si le changement de status code vaut la peine
    d'être signalé :
      - le nouveau code n'est pas un code de bruit connu (NOISE_CODES)
      - la baseline elle-même n'était pas déjà un code de bruit
        (ex: initial=429 → bypass vers 200 = FP WAF, pas du cache poisoning)
    """
    return (
        new_code != initial_code
        and new_code not in NOISE_CODES
        and initial_code not in NOISE_CODES
    )


def port_poisoning(
    url: str,
    s: requests.Session,
    initial_response: requests.Response,
    custom_header: dict,
    authent: tuple[str, str] | None,
    human: str,
) -> None:
    VULN_NAME = "HPP"

    # Si la baseline est déjà un code de bruit, les comparaisons n'ont pas de sens
    if initial_response.status_code in NOISE_CODES:
        logger.debug("HPP skipped for %s — baseline is %s", url, initial_response.status_code)
        return

    host = url.split("://")[1].split("/")[0]

    pheaders = [
        {"Host": f"{host}:31337"},
        {"X-Forwarded-Port": "31337"},
        {"X-Forwarded-Port": "99999"},
        {"X-Forwarded-Port": "-1"},
        {"X-Forwarded-Port": "abc"},
        {"X-Forwarded-Port": "0x50"},
        {"X-Forwarded-Port": "80 80"},
        {"X-Forwarded-Port": "80@evil.com:443"},
        {"x-forwarded-proto": "31337"},
        {"X-Forwarded-Host": f"{host}:31337"},
        {"X-Host": f"{host}:31337"},
        {"X-HTTP-Host-Override": f"{host}:31337"},
        {"Forwarded": f"host={host}:31337"},
        {"Forwarded": f"for={host}:31337"},
        {"X-URL-Scheme": "https"},
        {"Front-End-Https": "on"},
        {"X-Original-URL": f"{host}:31337"},
        {"X-Rewrite-URL": f"{host}:31337"},
        {"CF-Connecting-IP": f"{host}:31337"},
        {"True-Client-IP": f"{host}:31337"},
        {"X-Real-IP": f"{host}:31337"},
        {"X-ProxyUser-Ip": f"{host}:31337"},
        {"X-Forwarded-Server": f"{host}:31337"},
        {"X-Custom-IP-Authorization": f"{host}:31337"},
    ]

    try:
        for ph in pheaders:
            uri = randomiz_url(url)
            merged = {**ph, **(custom_header or {})}

            try:
                response = s.get(uri, headers=merged, verify=False,
                                 allow_redirects=False, timeout=6, auth=authent)
            except requests.exceptions.RequestException as e:
                logger.error("%s request failed %s: %s", VULN_NAME, uri, e)
                continue

            human_time(human)
            ctv = cache_tag_verify(response)

            # Changement de status code
            if _is_status_change_interesting(initial_response.status_code, response.status_code):
                print_(Identify.behavior, VULN_NAME,
                       f"{initial_response.status_code} > {response.status_code}",
                       ctv, uri, merged, s)
                verif_req = dvcp(uri, s, merged, authent)
                if (
                    verif_req.status_code != initial_response.status_code
                    and verif_req.status_code not in NOISE_CODES
                ):
                    print_(Identify.confirmed, VULN_NAME,
                           f"{initial_response.status_code} > {verif_req.status_code}",
                           ctv, uri, merged, s)

            # Réflexion dans le body
            if "31337" in response.text:
                print_(Identify.behavior, VULN_NAME, "31337 IN BODY", ctv, uri, merged, s)
                verif_req = dvcp(uri, s, merged, authent)
                if "31337" in verif_req.text:
                    print_(Identify.confirmed, VULN_NAME, "31337 IN BODY", ctv, uri, merged, s)

            # Réflexion dans les valeurs de headers (pas les clés)
            if any("31337" in v for v in response.headers.values()):
                print_(Identify.behavior, VULN_NAME, "31337 IN HEADER", ctv, uri, merged, s)
                verif_req = dvcp(uri, s, merged, authent)
                if any("31337" in v for v in verif_req.headers.values()):
                    print_(Identify.confirmed, VULN_NAME, "31337 IN HEADER", ctv, uri, merged, s)

    except Exception as e:
        logger.error("%s error: %s", VULN_NAME, e)


def reflected_cache_poisoning(
    url: str,
    s: requests.Session,
    initial_response: requests.Response,
    custom_header: dict,
    authent: tuple[str, str] | None,
    human: str,
) -> None:
    VULN_NAME = "WCP"

    # Si la baseline est déjà un code de bruit, les comparaisons n'ont pas de sens
    if initial_response.status_code in NOISE_CODES:
        logger.debug("WCP skipped for %s — baseline is %s", url, initial_response.status_code)
        return

    try:
        for pl in wcp_headers:
            header = {pl: CANARY, **(custom_header or {})}
            uri = randomiz_url(url)

            s.headers.update(random_ua())
            try:
                response = s.get(uri, headers=header, verify=False,
                                 allow_redirects=False, timeout=6, auth=authent)
            except requests.exceptions.RequestException as e:
                logger.error("%s request failed %s: %s", VULN_NAME, uri, e)
                continue

            ctv = cache_tag_verify(response)

            # Réflexion dans le body
            if CANARY in response.text:
                print_(Identify.behavior, VULN_NAME, "BODY REFLECTION", ctv, uri, header, s)
                verif_req = dvcp(uri, s, header, authent)
                if CANARY in verif_req.text:
                    print_(Identify.confirmed, VULN_NAME, "BODY REFLECTION", ctv, uri, header, s)

            # Réflexion dans les valeurs de headers
            if any(CANARY in v for v in response.headers.values()):
                print_(Identify.behavior, VULN_NAME, "HEADER REFLECTION", ctv, uri, header, s)
                verif_req = dvcp(uri, s, header, authent)
                if any(CANARY in v for v in verif_req.headers.values()):
                    print_(Identify.confirmed, VULN_NAME, "HEADER REFLECTION", ctv, uri, header, s)

            # Changement de status code
            if _is_status_change_interesting(initial_response.status_code, response.status_code):
                print_(Identify.behavior, VULN_NAME,
                       f"{initial_response.status_code} > {response.status_code}",
                       ctv, uri, header, s)
                verif_req = dvcp(uri, s, header, authent)
                if (
                    verif_req.status_code != initial_response.status_code
                    and verif_req.status_code not in NOISE_CODES
                ):
                    print_(Identify.confirmed, VULN_NAME,
                           f"{initial_response.status_code} > {verif_req.status_code}",
                           ctv, uri, header, s)

            print(f" {Colors.BLUE} {VULN_NAME} : {header}{Colors.RESET}\r", end="")
            print("\033[K", end="")

    except Exception as e:
        logger.error("%s error: %s", VULN_NAME, e)


def check_cache_poisoning(
    url: str,
    s: requests.Session,
    custom_header: dict,
    authent: tuple[str, str] | None,
    human: str,
) -> None:
    try:
        initial_response = s.get(
            randomiz_url(url),
            headers=custom_header,
            verify=False,
            allow_redirects=False,
            timeout=6,
            auth=authent,
        )
    except requests.exceptions.RequestException as e:
        logger.error("baseline request failed %s: %s", url, e)
        return

    # Garde globale : si la baseline est déjà un code de bruit,
    # toute comparaison de status code sera un FP — on abandonne ici.
    if initial_response.status_code in NOISE_CODES:
        logger.debug("Cache poisoning skipped for %s — baseline is %s",
                     url, initial_response.status_code)
        return

    print(f"{Colors.CYAN} ├ Cache poisoning analysis{Colors.RESET}")
    port_poisoning(url, s, initial_response, custom_header, authent, human)
    reflected_cache_poisoning(url, s, initial_response, custom_header, authent, human)
    crawl_files(url, s, initial_response, custom_header, authent, human)