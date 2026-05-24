#!/usr/bin/env python3

"""
Attempts to find Multiple Same Header Cache
"""

import http.client

from modules.lists import wcp_headers
from utils.style import Colors, Identify
from utils.utils import configure_logger, human_time, random, requests, urlparse
from utils.print_utils import print_results, cache_tag_verify

VULN_NAME = "MSH"
EXCLUDE_RESPONSE = [200, 301, 302, 403, 404, 307, 308, 303, 429]

logger = configure_logger(__name__)


def _new_conn(parsed_url) -> http.client.HTTPConnection | http.client.HTTPSConnection:
    host = parsed_url.netloc
    if parsed_url.scheme == "https":
        return http.client.HTTPSConnection(host, timeout=10)
    return http.client.HTTPConnection(host, timeout=10)


def verify_cache_poisoning(
    VULN_TYPE: str,
    parsed_url,
    url: str,
    payload: str,
    main_status_code: int,
    authent: tuple[str, str] | None,
    host: str,
) -> None:
    cb = random.randrange(9999)
    res_status = 0
    try:
        for _ in range(5):
            conn = _new_conn(parsed_url)
            conn.putrequest("GET", f"/?CPDoS={cb}")
            conn.putheader("User-Agent", "xxxx")

            if VULN_TYPE == "RDH":
                conn.putheader("Referer", "xy")
                conn.putheader("Referer", "x")
            elif VULN_TYPE == "HDH":
                conn.putheader("Host", f"{host}")
                conn.putheader("Host", "toto.com")
            elif VULN_TYPE == "XFH":
                conn.putheader("x-forwarded-host", f"{host}")
                conn.putheader("x-forwarded-host", "evil.com")
            else:
                conn.putheader(f"{VULN_TYPE}", "xxxx")
                conn.putheader(f"{VULN_TYPE}", "xxxx")

            conn.endheaders()
            response = conn.getresponse()
            res_status = response.status
            conn.close()

        uri = f"{url}?CPDoS={cb}"
        req = requests.get(uri, auth=authent, verify=False, allow_redirects=False, timeout=10)
        if req.status_code == res_status and res_status != main_status_code:
            reason = f"{main_status_code} > {response.status}"
            cachetag = cache_tag_verify(req)
            print_results(Identify.confirmed, VULN_NAME, reason, cachetag, uri, payload)
    except Exception as e:
        logger.exception(f"{VULN_NAME}: {str(e)}")


def duplicate_headers(
    parsed_url,
    url: str,
    mh: str,
    main_status_code: int,
    authent: tuple[str, str] | None,
) -> tuple:
    """VULN_TYPE =  DH"""
    cb = random.randrange(9999)
    conn = _new_conn(parsed_url)
    try:
        conn.putrequest("GET", f"/?cb={cb}")
        conn.putheader("User-Agent", "xxxx")
        conn.putheader(f"{mh}", "xxxx")
        conn.putheader(f"{mh}", "xxxx")
        conn.endheaders()

        response = conn.getresponse()

        if (
            response.status != main_status_code
            and response.status not in EXCLUDE_RESPONSE
        ):
            logger.debug(
                f"[{url}?cb={cb}] Statut : {response.status}, Raison : {response.reason}"
            )
            for rh in response.headers:
                if "age" in rh.lower() or "hit" in rh.lower():
                    return response, cb

        return None, cb

    except KeyboardInterrupt:
        conn.close()
        raise
    except Exception as e:
        return None, cb
    finally:
        try:
            conn.close()
        except Exception:
            pass


def referer_duplicate_headers(
    parsed_url,
    url: str,
    main_status_code: int,
    authent: tuple[str, str] | None,
) -> tuple:
    """VULN_TYPE = RDH"""
    cb = random.randrange(9999)
    conn = _new_conn(parsed_url)
    try:
        conn.putrequest("GET", f"/?cb={cb}")
        conn.putheader("User-Agent", "xxxx")
        conn.putheader("Referer", "xy")
        conn.putheader("Referer", "x")
        conn.endheaders()

        response = conn.getresponse()
        if (
            response.status != main_status_code
            and response.status not in EXCLUDE_RESPONSE
        ):
            logger.debug(
                f"[{url}?cb={cb}] Statut : {response.status}, Raison : {response.reason}"
            )
            for rh in response.headers:
                if "age" in rh.lower() or "hit" in rh.lower():
                    return response, cb

        return None, cb

    except Exception:
        return None, cb
    finally:
        try:
            conn.close()
        except Exception:
            pass


def host_duplicate_headers(
    parsed_url,
    host: str,
    url: str,
    main_status_code: int,
    authent: tuple[str, str] | None,
) -> tuple:
    """VULN_TYPE = HDH"""
    cb = random.randrange(9999)
    conn = _new_conn(parsed_url)
    try:
        conn.putrequest("GET", f"/?cb={cb}")
        conn.putheader("User-Agent", "xxxx")
        conn.putheader("Host", f"{host}")
        conn.putheader("Host", "toto.com")
        conn.endheaders()

        response = conn.getresponse()
        if (
            response.status != main_status_code
            and response.status not in EXCLUDE_RESPONSE
        ):
            logger.debug(
                f"[{url}?cb={cb}] Statut : {response.status}, Raison : {response.reason}"
            )
            for rh in response.headers:
                if "age" in rh.lower() or "hit" in rh.lower():
                    return response, cb

        return None, cb

    except Exception:
        return None, cb
    finally:
        try:
            conn.close()
        except Exception:
            pass


def xforwardedhost_duplicate_headers(
    parsed_url,
    host: str,
    url: str,
    main_status_code: int,
    authent: tuple[str, str] | None,
) -> tuple:
    """VULN_TYPE = XFH"""
    cb = random.randrange(9999)
    conn = _new_conn(parsed_url)
    try:
        conn.putrequest("GET", f"/?cb={cb}")
        conn.putheader("User-Agent", "xxxx")
        conn.putheader("x-forwarded-host", f"{host}")
        conn.putheader("x-forwarded-host", "toto.com")
        conn.endheaders()

        response = conn.getresponse()
        if (
            response.status != main_status_code
            and response.status not in EXCLUDE_RESPONSE
        ):
            logger.debug(
                f"[{url}?cb={cb}] Statut : {response.status}, Raison : {response.reason}"
            )
            for rh in response.headers:
                if "age" in rh.lower() or "hit" in rh.lower():
                    return response, cb

        return None, cb

    except Exception:
        return None, cb
    finally:
        try:
            conn.close()
        except Exception:
            pass


def MSH(
    url: str, req_main: requests.Response, authent: tuple[str, str] | None, human: str
) -> None:

    main_status_code = req_main.status_code
    try:
        parsed_url = urlparse(url)
        host = parsed_url.netloc

        RDH = referer_duplicate_headers(parsed_url, url, main_status_code, authent)
        HDH = host_duplicate_headers(parsed_url, host, url, main_status_code, authent)
        XFH = xforwardedhost_duplicate_headers(parsed_url, host, url, main_status_code, authent)

        for vuln_type, vuln_type_res in [("RDH", RDH), ("HDH", HDH), ("XFH", XFH)]:
            print(f" {Colors.BLUE} {VULN_NAME} : {url}{Colors.RESET}\r", end="")
            print("\033[K", end="")
            if (
                vuln_type_res
                and vuln_type_res[0] is not None
                and isinstance(vuln_type_res, tuple)
            ):
                reason = f"{main_status_code} > {vuln_type_res[0].status}"
                cachetag = cache_tag_verify(req_main)

                if vuln_type == "RDH":
                    payload = "[Referer: xy, Referer: x]"
                elif vuln_type == "HDH":
                    payload = f"[Host: {host}, Host: toto.com]"
                elif vuln_type == "XFH":
                    payload = f"[x-forwarded-host: {host}, x-forwarded-host: evil.com]"
                else:
                    payload = f"[{vuln_type}: xxxx, {vuln_type}: xxxx]"

                print_results(Identify.behavior, VULN_NAME, reason, cachetag, f"{url}?cb={vuln_type_res[1]}", payload)
                verify_cache_poisoning(
                    vuln_type, parsed_url, url, payload, main_status_code, authent, host
                )

        m_heads = wcp_headers
        for mh in m_heads:
            DH = duplicate_headers(parsed_url, url, mh, main_status_code, authent)
            if DH and DH[0] is not None and isinstance(DH, tuple):
                reason = f"DIFFERENT STATUS-CODE  {main_status_code} > {DH[0].status}"
                cachetag = cache_tag_verify(req_main)
                payload = f"[{mh}: xxxx, {mh}: xxxx]"

                print_results(Identify.behavior, VULN_NAME, reason, cachetag, f"{url}?cb={DH[1]}", payload)
                verify_cache_poisoning(
                    mh, parsed_url, url, payload, main_status_code, authent, host
                )
            human_time(human)
            print(f" {Colors.BLUE} {VULN_NAME} : {mh}{Colors.RESET}\r", end="")
            print("\033[K", end="")

    except requests.Timeout as t:
        pass
    except Exception as e:
        logger.exception(f"{VULN_NAME}: {str(e)}")