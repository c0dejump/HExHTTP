#!/usr/bin/env python3

"""
CVE-2021-27577 Detection Script
Apache Traffic Server URL Fragment Cache Poisoning Vulnerability
Affects: Apache Traffic Server 7.0.0-7.1.12, 8.0.0-8.1.1, 9.0.0-9.0.1
youst.in/posts/cache-poisoning-at-scale/
"""

from typing import Any

from utils.style import Colors
from utils.utils import configure_logger, random, requests, string, time

logger = configure_logger(__name__)


class CVE202127577Checker:
    """Détecteur pour CVE-2021-27577 (Apache Traffic Server fragment cache poisoning)"""
    
    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })

    def generate_random_string(self, length: int = 8) -> str:
        """Génère une chaîne aléatoire pour les identifiants uniques"""
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))

    def detect_apache_traffic_server(self, url: str) -> tuple[bool, str]:
        """Détecte si la cible utilise Apache Traffic Server"""
        try:
            response = self.session.get(url, timeout=10)

            # Vérification du header Server
            server_header = response.headers.get("Server", "").lower()
            if "ats" in server_header or "apache traffic server" in server_header:
                return True, f"Server header: {response.headers.get('Server')}"

            # Vérification des headers spécifiques à ATS
            ats_headers = [
                "X-Cache-Status",
                "X-Cache-Key",
                "X-Cache-Generation",
                "ATS-Internal",
                "X-ATS-Cache-Status",
            ]

            for header in ats_headers:
                if header in response.headers:
                    return True, f"ATS header detected: {header}"

            # Vérification du header Via pour signature ATS
            via_header = response.headers.get("Via", "").lower()
            if "ats" in via_header or "apache traffic server" in via_header:
                return True, f"Via header: {response.headers.get('Via')}"

            return False, "No ATS indicators found"

        except Exception as e:
            logger.exception(f"Error detecting ATS: {e}")
            return False, "Error detecting ATS"

    def test_fragment_cache_poisoning(self, url: str) -> list[dict]:
        """Teste la vulnérabilité de cache poisoning via fragments d'URL"""
        results = []
        base_path = "/test_" + self.generate_random_string()

        # Cas de test avec différents types de fragments
        test_cases = [
            {
                "name": "Basic Fragment Test",
                "url1": f"{url}{base_path}",
                "url2": f"{url}{base_path}#fragment",
                "description": "Test if fragments affect cache keys",
            },
            {
                "name": "Fragment with Cache-Busting",
                "url1": f"{url}{base_path}?v=1",
                "url2": f"{url}{base_path}?v=1#cachebust",
                "description": "Test fragment impact on parameterized URLs",
            },
            {
                "name": "Fragment Injection",
                "url1": f"{url}{base_path}",
                "url2": f"{url}{base_path}#/../admin",
                "description": "Test path traversal via fragments",
            },
            {
                "name": "Fragment with Special Characters",
                "url1": f"{url}{base_path}",
                "url2": f"{url}{base_path}#%2F..%2F",
                "description": "Test encoded characters in fragments",
            },
            {
                "name": "Fragment Cache Key Confusion",
                "url1": f"{url}{base_path}?cache=normal",
                "url2": f"{url}{base_path}?cache=normal#admin",
                "description": "Test if fragments create different cache entries",
            },
        ]

        for test_case in test_cases:
            try:
                result = self.execute_fragment_test(test_case)
                results.append(result)
                time.sleep(0.5)
            except Exception as e:
                logger.exception(f"Error in test {test_case['name']}: {e}")

        return results

    def execute_fragment_test(self, test_case: dict[str, str]) -> dict:
        """Exécute un test individuel de cache poisoning par fragment"""
        try:
            # Étape 1: Prime cache avec première URL
            resp1 = self.session.get(test_case["url1"], timeout=10)
            time.sleep(0.1)

            # Étape 2: Requête avec fragment
            resp2 = self.session.get(test_case["url2"], timeout=10)
            time.sleep(0.1)

            # Étape 3: Vérification du comportement du cache
            resp3 = self.session.get(test_case["url1"], timeout=10)

            # Analyse des réponses
            analysis = self.analyze_fragment_responses(resp1, resp2, resp3, test_case)
            return analysis

        except Exception as e:
            logger.exception(f"Error executing fragment test: {e}")
            return {
                "test_name": test_case["name"],
                "vulnerable": False,
                "error": str(e),
                "description": test_case["description"],
            }

    def analyze_fragment_responses(
        self,
        resp1: requests.Response,
        resp2: requests.Response,
        resp3: requests.Response,
        test_case: dict[str, str],
    ) -> dict:
        """Analyse les réponses pour détecter les indicateurs de cache poisoning"""
        details: dict[str, Any] = {}
        result: dict[str, Any] = {
            "test_name": test_case["name"],
            "vulnerable": False,
            "confidence": "Low",
            "details": details,
            "description": test_case["description"],
        }

        # Vérification des status codes
        statuses = [resp1.status_code, resp2.status_code, resp3.status_code]
        details["status_codes"] = statuses

        # Vérification des content lengths
        lengths = [len(resp1.content), len(resp2.content), len(resp3.content)]
        details["content_lengths"] = lengths

        # Extraction des headers de cache
        cache_headers_1 = self.extract_cache_headers(resp1)
        cache_headers_2 = self.extract_cache_headers(resp2)
        cache_headers_3 = self.extract_cache_headers(resp3)

        details["cache_headers"] = {
            "resp1": cache_headers_1,
            "resp2": cache_headers_2,
            "resp3": cache_headers_3,
        }

        # Indicateurs de vulnérabilité
        indicators = []

        # Indicateur 1: Status de cache différent pour URLs avec/sans fragments
        if (
            cache_headers_1.get("cache_status") != cache_headers_2.get("cache_status")
            and cache_headers_1.get("cache_status")
            and cache_headers_2.get("cache_status")
        ):
            indicators.append("Different cache status for fragment URLs")
            result["vulnerable"] = True

        # Indicateur 2: Fragment affectant la génération de cache key
        if (
            cache_headers_1.get("cache_key") != cache_headers_2.get("cache_key")
            and cache_headers_1.get("cache_key")
            and cache_headers_2.get("cache_key")
        ):
            indicators.append("Fragments affecting cache key generation")
            result["vulnerable"] = True

        # Indicateur 3: Différences de réponse indiquant confusion de cache
        if (
            resp1.status_code == resp2.status_code == resp3.status_code
            and len(resp1.content) != len(resp2.content)
            and abs(len(resp1.content) - len(resp2.content)) > 100
        ):
            indicators.append("Content length differences suggest cache confusion")
            result["vulnerable"] = True

        # Indicateur 4: Pattern anormal de cache hit/miss
        cache_pattern = [
            cache_headers_1.get("cache_hit", False),
            cache_headers_2.get("cache_hit", False),
            cache_headers_3.get("cache_hit", False),
        ]

        if cache_pattern == [False, False, True] or cache_pattern == [False, True, False]:
            indicators.append("Abnormal cache hit/miss pattern")
            result["vulnerable"] = True

        # Indicateur 5: Incohérences dans le header Age
        ages = [
            cache_headers_1.get("age"),
            cache_headers_2.get("age"),
            cache_headers_3.get("age"),
        ]

        if (
            ages[0] is not None
            and ages[1] is not None
            and isinstance(ages[0], int)
            and isinstance(ages[1], int)
            and abs(ages[0] - ages[1]) > 5
        ):
            indicators.append("Age header inconsistencies")
            result["vulnerable"] = True

        result["indicators"] = indicators

        # Niveau de confiance
        if len(indicators) >= 3:
            result["confidence"] = "High"
        elif len(indicators) >= 2:
            result["confidence"] = "Medium"
        elif len(indicators) >= 1:
            result["confidence"] = "Low"

        return result

    def extract_cache_headers(self, response: requests.Response) -> dict[str, Any]:
        """Extrait les headers liés au cache de la réponse"""
        cache_info: dict[str, Any] = {}

        # Headers de status de cache
        cache_status_headers = [
            "X-Cache-Status",
            "X-Cache",
            "CF-Cache-Status",
            "X-Served-By",
            "X-Cache-Lookup",
            "X-ATS-Cache-Status",
        ]

        for header in cache_status_headers:
            if header in response.headers:
                cache_info["cache_status"] = response.headers[header]
                # Correction: retourner un booléen, pas une string
                cache_info["cache_hit"] = "hit" in response.headers[header].lower()
                break

        # Cache key
        if "X-Cache-Key" in response.headers:
            cache_info["cache_key"] = response.headers["X-Cache-Key"]

        # Header Age
        if "Age" in response.headers:
            try:
                cache_info["age"] = int(response.headers["Age"])
            except (ValueError, TypeError):
                cache_info["age"] = None

        # Header Via pour détection de proxy
        if "Via" in response.headers:
            cache_info["via"] = response.headers["Via"]

        return cache_info

    def test_version_fingerprinting(self, url: str) -> list[str]:
        """Tente de fingerprinter la version d'Apache Traffic Server"""
        try:
            test_headers = {"X-Forwarded-For": "127.0.0.1", "Connection": "close"}
            response = self.session.get(url, headers=test_headers, timeout=10)

            version_indicators = []

            # Vérification du header Server pour la version
            server = response.headers.get("Server", "")
            if "Apache Traffic Server" in server or "ATS" in server:
                version_indicators.append(f"Server: {server}")

            # Vérification du header Via pour info de version
            via = response.headers.get("Via", "")
            if "ATS" in via:
                version_indicators.append(f"Via: {via}")

            return version_indicators

        except Exception as e:
            logger.exception(f"Error fingerprinting version: {e}")
            return []


def apache_cp(url: str, authent: tuple[str, str] | None = None) -> bool:
    """
    Fonction principale pour vérifier CVE-2021-27577
    
    Args:
        url: URL cible
        authent: Credentials HTTP Basic (non utilisé pour cette CVE)
        
    Returns:
        True si vulnérable, False sinon
    """
    checker = CVE202127577Checker()

    # Étape 1: Détection d'Apache Traffic Server
    is_ats, ats_info = checker.detect_apache_traffic_server(url)

    if not is_ats:
        return False

    print(f" ├── {Colors.GREEN}Apache Traffic Server detected{Colors.RESET}")
    print(f" │   └─ {ats_info}")

    # Étape 2: Fingerprinting de version
    version_info = checker.test_version_fingerprinting(url)
    if version_info:
        print(" ├── Version indicators:")
        for info in version_info:
            print(f" │   └─ {info}")

    # Étape 3: Test de cache poisoning par fragment d'URL
    print(" ├── Testing URL fragment cache poisoning...")

    test_results = checker.test_fragment_cache_poisoning(url)

    vulnerable_tests = [r for r in test_results if r.get("vulnerable", False)]

    if vulnerable_tests:
        print(f" ├── {Colors.RED}VULNERABLE to CVE-2021-27577{Colors.RESET}")
        print(
            f" │   └─ {len(vulnerable_tests)}/{len(test_results)} tests indicate vulnerability"
        )

        for result in vulnerable_tests:
            print(
                f" ├── {Colors.RED}[{result['confidence']}]{Colors.RESET} {result['test_name']}"
            )
            for indicator in result.get("indicators", []):
                print(f" │   └─ {indicator}")

        return True
    else:
        print(f" └── {Colors.GREEN}Not vulnerable{Colors.RESET}")
        return False


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python CVE202127577.py <URL>")
        sys.exit(1)

    target_url = sys.argv[1]
    apache_cp(target_url)