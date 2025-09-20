#!/usr/bin/env python3


from modules.technos.akamai import akamai
from modules.technos.apache import apache
from modules.technos.cloudflare import cloudflare
from modules.technos.envoy import envoy
from modules.technos.fastly import fastly
from modules.technos.imperva import imperva
from modules.technos.nginx import nginx
from modules.technos.vercel import vercel
from utils.style import Colors
from utils.utils import requests


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

    def apache(self, url: str, s: requests.Session) -> None:
        print(f"{Colors.CYAN} ├── Apache analysis{Colors.RESET}")
        apache(url, s)

    def nginx(self, url: str, s: requests.Session) -> None:
        # Unkeyed Query Exploitation:
        print(f"{Colors.CYAN} ├── Nginx analysis{Colors.RESET}")
        nginx(url, s)

    def envoy(self, url: str, s: requests.Session) -> None:
        print(f"{Colors.CYAN} ├── Envoy analysis{Colors.RESET}")
        envoy(url, s)

    def akamai(self, url: str, s: requests.Session) -> None:
        print(f"{Colors.CYAN} ├── Akamai analysis{Colors.RESET}")
        akamai(url, s)

    def fastly(self, url: str, s: requests.Session) -> None:
        print(f"{Colors.CYAN} ├── Fastly analysis{Colors.RESET}")
        fastly(url, s)

    def cloudflare(self, url: str, s: requests.Session) -> None:
        print(f"{Colors.CYAN} ├── Cloudflare analysis{Colors.RESET}")
        cloudflare(url, s)

    def imperva(self, url: str, s: requests.Session) -> None:
        print(f"{Colors.CYAN} ├── Imperva analysis{Colors.RESET}")
        imperva(url, s)

    def vercel(self, url: str, s: requests.Session) -> None:
        print(f"{Colors.CYAN} ├── Vercel analysis{Colors.RESET}")
        vercel(url, s)
