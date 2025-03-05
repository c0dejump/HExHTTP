import http.client
from urllib.parse import urlparse
from modules.utils import requests, configure_logger, random, human_time, Identify
from modules.lists import header_list

VULN_NAME = "Multiple Headers"
EXCLUDE_RESPONSE = [200, 301, 302, 403, 404, 307, 308, 303, 429]

logger = configure_logger(__name__)

def verify_cache_poisoning(VULN_TYPE, conn, url, payload, main_status_code, authent, host):
    cb = random.randrange(9999)
    res_status = 0
    try:
        for _ in range(5):
            conn.putrequest("GET", "/?CPDoS={}".format(cb))
            conn.putheader("User-Agent", "xxxx")

            if VULN_TYPE == "RDH":
                conn.putheader("Referer", "xy")
                conn.putheader("Referer", "x")

            elif VULN_TYPE == "HDH":
                conn.putheader("Host", "{}".format(host))
                conn.putheader("Host", "toto.com")

            else:
                conn.putheader(f"{VULN_TYPE}", "xxxx")
                conn.putheader(f"{VULN_TYPE}", "xxxx")

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
                f" {Identify.confirmed} | {VULN_NAME} | \033[34m{uri}\033[0m | {reason} | PAYLOAD: {payload}"
            )
    except Exception as e:
        logger.exception(e)


def duplicate_headers(conn, url, mh, main_status_code, authent):
    #VULN_TYPE = "DH"
    cb = random.randrange(9999)

    try:
        conn.putrequest("GET", f"/?cb={cb}")
        conn.putheader("User-Agent", "xxxx")
        conn.putheader(f"{mh}", "xxxx")
        conn.putheader(f"{mh}", "xxxx")
        conn.endheaders()

        response = conn.getresponse()

        if response.status != main_status_code and response.status not in EXCLUDE_RESPONSE:
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
    #VULN_TYPE = "RDH"
    cb = random.randrange(9999)

    try:
        conn.putrequest("GET", "/?cb={}".format(cb))
        conn.putheader("User-Agent", "xxxx")
        conn.putheader("Referer", "xy")
        conn.putheader("Referer", "x")
        conn.endheaders()

        response = conn.getresponse()
        if response.status != main_status_code and response.status not in EXCLUDE_RESPONSE:
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
    #VULN_TYPE = "HDH"
    cb = random.randrange(9999)

    try:
        conn.putrequest("GET", "/?cb={}".format(cb))
        conn.putheader("User-Agent", "xxxx")
        conn.putheader("Host", "{}".format(host))
        conn.putheader("Host", "toto.com")
        conn.endheaders()

        response = conn.getresponse()
        if response.status != main_status_code and response.status not in EXCLUDE_RESPONSE:
            #print(f"[{url}?cb={cb}] Statut : {response.status}, Raison : {response.reason}")
            for rh in response.headers:
                if "age" in rh.lower() or "hit" in rh.lower():
                    return response, cb
        else:
            conn.close()
            return False
    except Exception as e:
        return False
        


def MHC(url, req_main, authent, human):
    main_status_code = req_main.status_code
    try:
        parsed_url = urlparse(url)
        host = parsed_url.netloc
        if parsed_url.scheme == "https":
            conn = http.client.HTTPSConnection(host, timeout=10)
        else:
            conn = http.client.HTTPConnection(host, timeout=10)

        RDH = referer_duplicate_headers(conn, url, main_status_code, authent)
        HDH = host_duplicate_headers(conn, host, url, main_status_code, authent)

        mhc_res = ["RDH", "HDH"]

        for vuln_type in mhc_res:
            vuln_type_res = locals()[vuln_type]
            print(f" \033[34m {VULN_NAME} : {url}\033[0m\r", end="")
            print("\033[K", end="")
            if vuln_type_res != False and vuln_type_res != None:
                behavior = f"DIFFERENT STATUS-CODE  {main_status_code} > {vuln_type_res[0].status}"

                if vuln_type == "RDH":
                    payload = f"[Referer: xy, Referer: x]"
                elif vuln_type == "HDH":
                    payload = f"[Host: {host}, Host: toto.com]"

                print(
                        f" {Identify.behavior} | {VULN_NAME} | \033[34m{url}?cb={vuln_type_res[1]}\033[0m | {behavior} | PAYLOAD: {payload}"
                    )
                conn.close()
                verify_cache_poisoning(vuln_type, conn, url, payload, main_status_code, authent, host)

        #m_heads = ["Authorization", "Accept", "Content-Type", "Cookie", "X-Requested-With", "user-agent"]
        m_heads = header_list
        for mh in m_heads:
            DH = duplicate_headers(conn, url, mh, main_status_code, authent)
            if DH != False and DH != None:
                behavior = f"DIFFERENT STATUS-CODE  {main_status_code} > {DH[0].status}"

                payload = f"[{mh}: xxxx, {mh}: xxxx]"

                print(
                        f" {Identify.behavior} | {VULN_NAME} | \033[34m{url}?cb={DH[1]}\033[0m | {behavior} | PAYLOAD: {payload}"
                    )
                conn.close()
                verify_cache_poisoning(mh, conn, url, payload, main_status_code, authent, host)
            human_time(human)
            print(f" \033[34m {VULN_NAME} : {mh}\033[0m\r", end="")
            print("\033[K", end="")

    except Exception as e:
        logger.exception(e)
