#! /usr/bin/env python3
# -*- coding: utf-8 -*-
from modules.proxies.apache import apache
from modules.proxies.nginx import nginx
from modules.proxies.envoy import envoy
from modules.proxies.akamai import akamai
from modules.proxies.fastly import fastly

class technology:
    """
    forwarded:
        nginx:
            X-Real-IP
            Forwarded
        apache:
            X-Forwarded-Server
            X-Real-IP
            Max-Forwards
    Unkeyed Query Exploitation:
        Apache: // | //?"><script>
        Nginx: /%2F | /%2F?"><u>
        PHP: /index.php/xyz
        .NET: /(A(xyz))/
    """

    def apache(self, url, s):
        print("\033[36m --├ Apache analyse\033[0m")
        apache(url, s)

    def nginx(self, url, s):
        # Unkeyed Query Exploitation:
        print("\033[36m --├ Nginx analyse\033[0m")
        nginx(url, s)

    def envoy(self, url, s):
        print("\033[36m --├ Envoy analyse\033[0m")
        envoy(url, s)

    def akamai(self, url, s):
        print("\033[36m --├ Akamai analyse\033[0m")
        akamai(url, s)

    def fastly(self, url, s):
        print("\033[36m --├ Fastly analyse\033[0m")
        fastly(url, s)


