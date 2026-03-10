#!/usr/bin/env python3


from modules.technos.akamai import akamai
from modules.technos.apache import apache
from modules.technos.azure import azure
from modules.technos.cloudflare import cloudflare
from modules.technos.cloudfront import cloudfront
from modules.technos.envoy import envoy
from modules.technos.fastly import fastly
from modules.technos.gcp import gcp
from modules.technos.imperva import imperva
from modules.technos.nginx import nginx
from modules.technos.varnish import varnish
from modules.technos.vercel import vercel
from utils.style import Colors
from utils.utils import requests


class Technology:
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

    def cloudfront(self, url: str, s: requests.Session) -> None:
        print(f"{Colors.CYAN} ├── CloudFront analysis{Colors.RESET}")
        cloudfront(url, s)

    def imperva(self, url: str, s: requests.Session) -> None:
        print(f"{Colors.CYAN} ├── Imperva analysis{Colors.RESET}")
        imperva(url, s)

    def varnish(self, url: str, s: requests.Session) -> None:
        print(f"{Colors.CYAN} ├── Varnish analysis{Colors.RESET}")
        varnish(url, s)

    def azure(self, url: str, s: requests.Session) -> None:
        print(f"{Colors.CYAN} ├── Azure Front Door analysis{Colors.RESET}")
        azure(url, s)

    def gcp(self, url: str, s: requests.Session) -> None:
        print(f"{Colors.CYAN} ├── GCP CDN analysis{Colors.RESET}")
        gcp(url, s)

    def vercel(self, url: str, s: requests.Session) -> None:
        print(f"{Colors.CYAN} ├── Vercel analysis{Colors.RESET}")
        vercel(url, s)



def get_technos(
    url: str, s: requests.Session, req_main: requests.Response, a_tech: Technology
) -> None:
    """
    Check what is the reverse proxy/WAF/cached server... and test based on the result.
    #TODO Cloudfoundry => https://hackerone.com/reports/728664
    """
    print(f"{Colors.CYAN} ├ Techno analysis{Colors.RESET}")
    technos = {
        "apache": ["apache", "tomcat"],
        "nginx": ["nginx"],
        "envoy": ["envoy"],
        "akamai": [
            "akamai",
            "x-akamai",
            "x-akamai-transformed",
            "akamaighost",
            "akamaiedge",
            "edgesuite",
        ],
        "imperva": ["imperva"],
        "fastly": ["fastly"],
        "cloudflare": ["cf-ray", "cloudflare", "cf-cache-status", "cf-ray"],
        "cloudfront": ["x-amz-cf", "cloudfront", "x-amz-request-id"],
        "vercel": ["vercel"],
        "varnish": ["x-varnish", "varnish"],
        "azure": ["x-azure-ref", "x-fd-", "x-msedge-ref", "x-azure-fdid"],
        "gcp": ["x-google-cache", "x-gfe", "x-goog-", "google frontend", "x-cloud-trace"],
        # "cloudfoundry": ["cf-app"]
    }

    technologies_detected = False
    for t in technos:
        tech_hit: str | bool = False
        for v in technos[t]:
            for rt in req_main.headers:
                # case-insensitive comparison
                if (
                    v.lower() in req_main.text.lower()
                    or v.lower() in req_main.headers[rt].lower()
                    or v.lower() in rt.lower()
                ):
                    tech_hit = t
                    break  # Exit inner loops once we find a match
            if tech_hit:
                break
        if tech_hit and isinstance(tech_hit, str):
            getattr(a_tech, tech_hit)(url, s)
            technologies_detected = True
            tech_hit = False
            return tech_hit

    if not technologies_detected:
        print(
            f"{Colors.YELLOW} │ └── No specific technologies detected{Colors.RESET}"
        )