import http.client

from modules.lists import header_list
from utils.style import Colors, Identify
from utils.utils import configure_logger, human_time, random, requests, urlparse

VULN_NAME = "Multiple Headers"
EXCLUDE_RESPONSE = [200, 301, 302, 403, 404, 307, 308, 303, 429]

logger = configure_logger(__name__)


def verify_cache_poisoning(
    VULN_TYPE: str,
    conn: http.client.HTTPConnection | http.client.HTTPSConnection,
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
            conn.putrequest(
                "GET", f"/?CPDoS={cb}"
            )  #  discrepancy between conn and req : url endpoint isn't reflected in the putrequest
            conn.putheader("User-Agent", "xxxx")

            if VULN_TYPE == "RDH":
                conn.putheader("Referer", "xy")
                conn.putheader("Referer", "x")

            elif VULN_TYPE == "HDH":
                conn.putheader("Host", f"{host}")
                conn.putheader("Host", "toto.com")

            else:
                conn.putheader(f"{VULN_TYPE}", "xxxx")
                conn.putheader(f"{VULN_TYPE}", "xxxx")

            conn.endheaders()
            response = conn.getresponse()
            res_status = response.status
            conn.close()

        uri = f"{url}?CPDoS={cb}"
        req = requests.get(uri, auth=authent, timeout=10)
        if req.status_code == res_status and res_status != main_status_code:
            reason = f"DIFFERENT STATUS-CODE  {main_status_code} > {response.status}"
            print(
                f" {Identify.confirmed} | {VULN_NAME} | {Colors.BLUE}{uri}{Colors.RESET} | {reason} | PAYLOAD: {Colors.THISTLE}{payload}{Colors.RESET}"
            )
    except Exception as e:
        logger.exception(e)


def duplicate_headers(
    conn: http.client.HTTPConnection | http.client.HTTPSConnection,
    url: str,
    mh: str,
    main_status_code: int,
    authent: tuple[str, str] | None,
) -> tuple:
    """VULN_TYPE =  DH"""
    cb = random.randrange(9999)

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

    except Exception:
        conn.close()
        return tuple()
    finally:
        conn.close()
        return tuple()


def referer_duplicate_headers(
    conn: http.client.HTTPConnection | http.client.HTTPSConnection,
    url: str,
    main_status_code: int,
    authent: tuple[str, str] | None,
) -> tuple:
    """VULN_TYPE = RDH"""
    cb = random.randrange(9999)

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
    except Exception:
        conn.close()
        return tuple()
    finally:
        conn.close()
        return tuple()


def host_duplicate_headers(
    conn: http.client.HTTPConnection | http.client.HTTPSConnection,
    host: str,
    url: str,
    main_status_code: int,
    authent: tuple[str, str] | None,
) -> tuple:
    """VULN_TYPE = HDH"""
    cb = random.randrange(9999)

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
    except Exception:
        conn.close()
        return tuple()
    finally:
        conn.close()
        return tuple()


def MHC(
    url: str, req_main: requests.Response, authent: tuple[str, str] | None, human: str
) -> None:
    main_status_code = req_main.status_code
    try:
        parsed_url = urlparse(url)
        host = parsed_url.netloc
        conn: http.client.HTTPConnection | http.client.HTTPSConnection
        if parsed_url.scheme == "https":
            conn = http.client.HTTPSConnection(host, timeout=10)
        else:
            conn = http.client.HTTPConnection(host, timeout=10)

        RDH = referer_duplicate_headers(conn, url, main_status_code, authent)
        HDH = host_duplicate_headers(conn, host, url, main_status_code, authent)

        mhc_res = ["RDH", "HDH"]

        for vuln_type in mhc_res:
            vuln_type_res = locals()[vuln_type]
            print(f" {Colors.BLUE} {VULN_NAME} : {url}{Colors.RESET}\r", end="")
            print("\033[K", end="")
            if (
                vuln_type_res
                and vuln_type_res is not None
                and isinstance(vuln_type_res, tuple)
            ):
                behavior = f"DIFFERENT STATUS-CODE  {main_status_code} > {vuln_type_res[0].status}"

                if vuln_type == "RDH":
                    payload = "[Referer: xy, Referer: x]"
                elif vuln_type == "HDH":
                    payload = f"[Host: {host}, Host: toto.com]"

                print(
                    f" {Identify.behavior} | {VULN_NAME} | {Colors.BLUE}{url}?cb={vuln_type_res[1]}{Colors.RESET} | {behavior} | PAYLOAD: {Colors.THISTLE}{payload}{Colors.RESET}"
                )
                conn.close()
                verify_cache_poisoning(
                    vuln_type, conn, url, payload, main_status_code, authent, host
                )

        # m_heads = ["Authorization", "Accept", "Content-Type", "Cookie", "X-Requested-With", "user-agent"]
        m_heads = header_list
        for mh in m_heads:
            DH = duplicate_headers(conn, url, mh, main_status_code, authent)
            if DH and DH is not None and isinstance(DH, tuple):
                behavior = f"DIFFERENT STATUS-CODE  {main_status_code} > {DH[0].status}"

                payload = f"[{mh}: xxxx, {mh}: xxxx]"

                print(
                    f" {Identify.behavior} | {VULN_NAME} | {Colors.BLUE}{url}?cb={DH[1]}{Colors.RESET} | {behavior} | PAYLOAD: {Colors.THISTLE}{payload}{Colors.RESET}"
                )
                conn.close()
                verify_cache_poisoning(
                    mh, conn, url, payload, main_status_code, authent, host
                )
            human_time(human)
            print(f" {Colors.BLUE} {VULN_NAME} : {mh}{Colors.RESET}\r", end="")
            print("\033[K", end="")

    except Exception as e:
        logger.exception(e)
