#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Attempts to find Cache Poisoning Denial of Service (CpDoS) error based
https://cpdos.org/
"""

from modules.lists import payloads_keys
from modules.utils import requests, random, sys, configure_logger, human_time, Identify

logger = configure_logger(__name__)


def check_cached_status(url, s, pk, main_status_code, authent):
    behavior = False
    confirmed = False
    cache_status = False

    for _ in range(0, 5):
        req = s.get(
            url,
            headers=pk,
            verify=False,
            allow_redirects=False,
            auth=authent,
            timeout=10,
        )
    req_verify = s.get(
        url, verify=False, allow_redirects=False, auth=authent, timeout=10
    )
    # print(f"{req.status_code} :: {req_verify.status_code}")
    if (
        req.status_code == req_verify.status_code
        and req.status_code not in [429, 200, 304, 303]
        or req_verify.status_code not in [429, 200, 304, 303]
        and req_verify.status_code != main_status_code
    ):
        behavior = True
        for rh in req_verify.headers:
            if "age" in rh.lower() or "hit" in req_verify.headers[rh].lower():
                confirmed = True
                cache_status = True
    elif req.status_code != req_verify.status_code and req.status_code == 304:
        for rh in req_verify.headers:
            if "age" in rh.lower() or "hit" in req_verify.headers[rh].lower():
                behavior = True
                cache_status = True
    elif req.status_code != req_verify.status_code and req.status_code not in [
        429,
        304,
    ]:
        for rh in req_verify.headers:
            if "age" in rh.lower() or "hit" in req_verify.headers[rh].lower():
                behavior = True
                cache_status = True

    cache_status = (
        f"\033[31m{cache_status}\033[0m"
        if not cache_status
        else f"\033[32m{cache_status}\033[0m"
    )
    if confirmed:
        #print(headers)
        print(
            f" {Identify.confirmed} | CPDoSError {main_status_code} > {req.status_code} | CACHETAG : {cache_status} | \033[34m{url}\033[0m | PAYLOAD: {pk}"
        )
        behavior = False
        confirmed = False
    elif behavior:
        print(
            f" {Identify.behavior} | CPDoSError {main_status_code} > {req.status_code} | CACHETAG : {cache_status} | \033[34m{url}\033[0m | PAYLOAD: {pk if len(pk) < 60 else pk[0:60]}"
        )


def check_cached_len(url, s, pk, main_len, authent):
    behavior = False
    confirmed = False
    cache_status = False

    for _ in range(0, 5):
        req = s.get(
            url,
            headers=pk,
            verify=False,
            allow_redirects=False,
            auth=authent,
            timeout=10,
        )
    req_verify = s.get(
        url, verify=False, allow_redirects=False, auth=authent, timeout=10
    )
    # print(f"{req.status_code} :: {req_verify.status_code}")
    if (
        len(req.content) == len(req_verify.content)
        and len(req_verify.content) != main_len
    ):
        behavior = True
        for rh in req_verify.headers:
            if "age" in rh.lower() or "hit" in req_verify.headers[rh].lower():
                confirmed = True
                cache_status = True
    elif len(req.content) != len(req_verify.content):
        for rh in req_verify.headers:
            if "age" in rh.lower():
                behavior = True
                cache_status = True
            else:
                behavior = True
                cache_status = False

    cache_status = (
        f"\033[31m {cache_status} \033[0m"
        if not cache_status
        else f"\033[32m {cache_status} \033[0m"
    )
    if confirmed:
        print(
            f" {Identify.confirmed} | CPDoSError {main_len}b > {len(req.content)}b | CACHETAG : {cache_status} | \033[34m{url}\033[0m | PAYLOAD: {pk}"
        )
        behavior = False
    elif behavior:
        print(
            f" {Identify.behavior} | CPDoSError {main_len}b > {len(req.content)}b | CACHETAG : {cache_status} | \033[34m{url}\033[0m | PAYLOAD: {pk if len(pk) < 60 else pk[0:60]}"
        )


def cpdos_main(url, s, initial_response, authent, human):
    main_status_code = initial_response.status_code
    main_len = len(initial_response.content)

    blocked = 0
    for pk in payloads_keys:
        # pk = pk.encode(encoding='UTF-8')
        uri = f"{url}{random.randrange(99999)}"
        try:
            req = s.get(
                uri,
                headers=pk,
                verify=False,
                auth=authent,
                timeout=10,
                allow_redirects=False,
            )
            len_req = len(req.content)

            if req.status_code == 888:
                print(
                    f" {Identify.behavior} | CPDoSError 888 response | CACHETAG: N/A | \033[34m{url}\033[0m | PAYLOAD: {pk}"
                )
                check_cached_status(uri, s, pk, main_status_code, authent)
            elif req.status_code == 403 or req.status_code == 429:
                uri_403 = f"{url}{random.randrange(999)}"
                req_403_test = requests.get(
                    uri_403,
                    verify=False,
                    auth=authent,
                    timeout=10,
                    allow_redirects=False,
                )
                if req_403_test.status_code == 403 or req_403_test.status_code == 429:
                    blocked += 1

            elif (
                blocked < 3
                and req.status_code != 200
                and main_status_code not in [403, 401]
                and req.status_code != main_status_code
            ):
                # print(f"[{main_status_code}>{req.status_code}] [{len(main_status_code.headers)}b>{len(req.headers)}b] [{len(main_status_code.content)}b>{len(req.content)}b] {url} :: {pk}")
                check_cached_status(uri, s, pk, main_status_code, authent)
            elif blocked < 3 and req.status_code == main_status_code:
                if len(str(main_len)) <= 5 and main_len not in range(
                    len_req - 1000, len_req + 1000
                ):
                    check_cached_len(uri, s, pk, main_len, authent)
                elif len(str(main_len)) > 5 and main_len not in range(
                    len_req - 10000, len_req + 10000
                ):
                    check_cached_len(uri, s, pk, main_len, authent)
            human_time(human)
            
            if len(list(pk.values())[0]) < 50 and len(list(pk.keys())[0]) < 50:
                sys.stdout.write(f"\033[34m {pk}\033[0m\r")
                sys.stdout.write("\033[K")
        except KeyboardInterrupt:
            print("Exiting")
            sys.exit()
        except Exception as e:
            logger.exception(e)
        uri = url
