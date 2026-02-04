#!/usr/bin/env python3
"""
http debug check
"""
from utils.style import Colors
from utils.utils import configure_logger, requests, random, range_exclusion, traceback, sys, human_time, random_ua
from modules.lists.debug_list import DEBUG_HEADERS

def check_http_debug(url, s, main_status_code, main_len, main_head, authent, human):
    print(f"{Colors.CYAN} ├ Debug Headers analysis{Colors.RESET}")
    rel = range_exclusion(main_len)
    
    behavior_groups = {}
    
    for dh in DEBUG_HEADERS:
        try:
            uri = f"{url}?cb={random.randrange(999)}"
            s.headers.update(random_ua())
            human_time(human)
            req_dh = s.get(uri, headers=dh, allow_redirects=False, verify=False)
            
            behavior_key = None
            behavior_msg = None
            
            if req_dh.status_code != main_status_code and req_dh.status_code not in [403, 401, 429]:
                status_range = (req_dh.status_code // 10) * 10
                behavior_key = f"STATUS_{main_status_code}_{status_range}"
                behavior_msg = f"INTERESTING BEHAVIOR | {main_status_code} > {req_dh.status_code}"
                
            elif len(req_dh.content) not in rel and req_dh.status_code not in [403, 401, 429]:
                size_range = (len(req_dh.content) // 1000) * 1000
                behavior_key = f"BODY_{main_len}_{size_range}"
                behavior_msg = f"INTERESTING BEHAVIOR | BODY: {main_len}b > {len(req_dh.content)}b"
                
            elif len(req_dh.headers) != len(main_head) and len(req_dh.headers) not in range(len(main_head) - 10, len(main_head) + 10) and req_dh.status_code not in [403, 401, 429]:
                behavior_key = f"HEADER_{len(main_head)}_{len(req_dh.headers)}"
                behavior_msg = f"INTERESTING BEHAVIOR | HEADER: {len(main_head)}b > {len(req_dh.headers)}b"
            
            if behavior_key:
                if behavior_key not in behavior_groups:
                    behavior_groups[behavior_key] = {
                        'msg': behavior_msg,
                        'url': uri,
                        'count': 0,
                        'payloads': []
                    }
                behavior_groups[behavior_key]['count'] += 1
                behavior_groups[behavior_key]['payloads'].append(str(dh))
                
        except Exception as e:
            if "got more than 100 headers" in str(e):
                print(f"\033[33m   └── [WARNING]\033[0m | Server returned >100 headers | \033[34m{uri}\033[0m | PAYLOAD: {dh}")
            elif "Connection aborted" in str(e):
                print(f"\033[33m   └── [WARNING]\033[0m | Connection aborted | \033[34m{uri}\033[0m | PAYLOAD: {dh}")
            else:
                pass
                #print(e)
            continue
        if len(list(dh.values())[0]) < 50 and len(list(dh.keys())[0]) < 50:
                sys.stdout.write(f"{Colors.BLUE}{dh} :: {req_dh.status_code}{Colors.RESET}\r")
                sys.stdout.write("\033[K")
    
    for key, data in behavior_groups.items():
        if data['count'] <= 3:
            print(f"\033[32m └──   [DEBUG CONFIRMED]\033[0m | {data['msg'].replace('[INTERESTING BEHAVIOR]', '').strip()} | \033[34m{data['url']}\033[0m | PAYLOAD: {data['payloads'][0]}")
        else:
            similar_text = f" (+{data['count']-1} similar)"
            payload_count = f"with {data['count']} payloads"
            print(f"\033[33m └──   {data['msg']}\033[0m | \033[34m{data['url']}\033[0m{similar_text} {payload_count}")