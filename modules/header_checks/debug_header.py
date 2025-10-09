#!/usr/bin/env python3
"""
http debug check
"""

from utils.style import Colors
from utils.utils import configure_logger, requests, random, CONTENT_DELTA_RANGE, BIG_CONTENT_DELTA_RANGE, traceback, sys, human_time
from modules.lists.debug_list import DEBUG_HEADERS


def check_http_debug(url, s, main_status_code, main_len, main_head, authent, human):
    print(f"{Colors.CYAN} ├ Debug Headers check{Colors.RESET}")

    range_exlusion = (
        range(main_len - CONTENT_DELTA_RANGE, main_len + CONTENT_DELTA_RANGE)
        if main_len < 10000
        else range(
            main_len - BIG_CONTENT_DELTA_RANGE,
            main_len + BIG_CONTENT_DELTA_RANGE,
        )
    )


    for dh in DEBUG_HEADERS:
        try:
            uri = f"{url}?cb={random.randrange(999)}"
            human_time(human)
            req_dh = s.get(uri, headers=dh, allow_redirects=False, verify=False)
            if req_dh.status_code != main_status_code and req_dh.status_code not in [403, 401, 429]:
                print(f"\033[33m └── [INTERESTING BEHAVIOR]\033[0m | {main_status_code} > {req_dh.status_code} | \033[34m{uri}\033[0m | PAYLOAD: {dh}")
            elif len(req_dh.content) not in range_exlusion and req_dh.status_code not in [403, 401, 429]:
                print(f"\033[33m └── [INTERESTING BEHAVIOR]\033[0m | BODY: {main_len}b > {len(req_dh.content)}b | \033[34m{uri}\033[0m | PAYLOAD: {dh}")
            elif len(req_dh.headers) != len(main_head) and len(req_dh.headers) not in range(len(main_head) - 10, len(main_head) + 10) and req_dh.status_code not in [403, 401, 429]:
                print(f"\033[33m └── [INTERESTING BEHAVIOR]\033[0m | HEADER: {len(main_head)}b > {len(req_dh.headers)}b | \033[34m{uri}\033[0m | PAYLOAD: {dh}")
        except Exception as e:
            if "got more than 100 headers" in str(e):
                print(f"\033[33m └── [WARNING]\033[0m | Server returned >100 headers | \033[34m{uri}\033[0m | PAYLOAD: {dh}")
            elif "Connection aborted" in str(e):
                print(f"\033[33m └── [WARNING]\033[0m | Connection aborted | \033[34m{uri}\033[0m | PAYLOAD: {dh}")
            # Continuer avec le prochain header
            continue

if __name__ == '__main__':
    url_file = sys.argv[1]
    s = requests.Session()
    s.headers.update(
                {
                    "User-agent": "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko",
                }
            )
    #check_http_debug(url)
    with open(url_file, "r") as urls:
        urls = urls.read().splitlines()
        for url in urls:
            url = f"{url}?cb=foo"
            try:
                req_main = s.get(url, verify=False, timeout=10, allow_redirects=False)
                main_len = len(req_main.content)
                main_status_code = req_main.status_code
                authent = False
                check_http_debug(url, s, main_len, main_status_code, authent)
            except KeyboardInterrupt:
                print("Exiting")
                sys.exit()
            except requests.ConnectionError:
                print("Error, cannot connect to target")
            except requests.Timeout:
                print("Error, request timeout (10s)")
            except requests.exceptions.MissingSchema:
                print("Error, missing http:// or https:// schema")
            except Exception as e:
                print(f"Error : {e}")
            print(f" {url}", end='\r')