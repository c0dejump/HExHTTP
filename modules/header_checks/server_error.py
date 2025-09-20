#!/usr/bin/env python3
"""
Enhanced server error analysis focused on server-side errors with improved pattern detection
"""
from typing import Any

from utils.style import Colors
from utils.utils import configure_logger, re, requests, time

logger = configure_logger(__name__)


class ServerErrorAnalyzer:

    def __init__(self) -> None:
        # Payloads plus variés et ciblés
        self.payloads_error = [
            "%2a",
            "%EXT%",
            "%ff",
            "%0A",
            "..%3B/",
            "..%3B",
            "%2e",
            "~",
            ".bak",
            ".old",
            ".tmp",
            "%00",
            "%0D",
            "A" * 100,
            "%2f",
            "%5c",
            "%c0%af",
            "%c1%9c",
            "%252e%252e%252f",
            "..%252f",
            "%u0000",
            "%u002e",
            "%u005c",
            "%%32%65",
            "..\\",
            "../",
            "....//",
            ".htaccess",
            ".git/",
            ".env",
            ".config",
            "web.config",
            "phpinfo()",
            "' OR '1'='1",
            "<script>",
            "${7*7}",
            "{{7*7}}",
            "<%=7*7%>",
            "${{7*7}}",
            "eval(1)",
            "system('id')",
            "|whoami",
            ";cat /etc/passwd",
            "../../etc/passwd",
        ]

        # Patterns d'erreur considérablement améliorés
        self.error_patterns = {
            # Divulgation de chemins système
            "path_disclosure": {
                "patterns": [
                    r'([A-Za-z]:\\(?:[^<>\s"\']*\\)*[^<>\s"\']*\.(php|asp|aspx|jsp|py|pl|cgi|txt|ini|conf))',
                    r'(/(?:var/www|home|usr|opt|etc)/[^<>\s"\']*\.(php|asp|aspx|jsp|py|pl|cgi|txt|ini|conf))',
                    r"(/(?:home|root)/[a-zA-Z0-9_\-/]*)",
                    r'(C:\\(?:inetpub|Windows|Program Files)[^<>\s"\']*)',
                    r'(/etc/(?:passwd|shadow|hosts|apache2?|nginx)[^<>\s"\']*)',
                    r'(\\(?:xampp|wamp|mamp)\\[^<>\s"\']*)',
                    r'(/var/log/[^<>\s"\']*)',
                    r'(/tmp/[^<>\s"\']*\.(tmp|log|txt))',
                ],
                "severity": "HIGH",
            },
            # Erreurs de base de données
            "database_error": {
                "patterns": [
                    r"(MySQL server version for the right syntax)",
                    r"(You have an error in your SQL syntax)",
                    r"(mysql_fetch_array\(\)|mysql_query\(\))",
                    r"(Warning: pg_connect\(\)|ERROR: syntax error at or near)",
                    r"(Microsoft OLE DB Provider for ODBC Drivers)",
                    r"(Oracle error|ORA-\d+)",
                    r"(SQLServer JDBC Driver|com\.microsoft\.sqlserver)",
                    r"(sqlite3\.|SQLITE_ERROR)",
                    r"(PostgreSQL query failed|pg_exec\(\))",
                    r"(Table \'[^\']*\' doesn\'t exist)",
                    r"(Unknown column \'[^\']*\' in \'field list\')",
                    r"(Duplicate entry \'[^\']*\' for key)",
                    r"(Access denied for user \'[^\']*\'@\'[^\']*\')",
                    r"(Connection refused.*\d+)",
                    r"(\[SQL Server\]|\[MySQL\]|\[PostgreSQL\]|\[Oracle\])",
                ],
                "severity": "HIGH",
            },
            # Traces de pile et exceptions
            "stack_trace": {
                "patterns": [
                    r"(Traceback \(most recent call last\):)",
                    r"(at [a-zA-Z0-9_\.]+\.[a-zA-Z0-9_]+\([^)]*\)\s*~\s*line\s+\d+)",
                    r'(Exception in thread "[^"]*")',
                    r"(java\.lang\.[a-zA-Z]*Exception)",
                    r"(System\.Exception:|System\.[a-zA-Z]*Exception)",
                    r"(Fatal error:.*line\s+\d+)",
                    r"(Warning:.*line\s+\d+)",
                    r"(Notice:.*line\s+\d+)",
                    r"(Call to undefined function.*line\s+\d+)",
                    r"(Parse error:.*line\s+\d+)",
                    r"(stack trace:|call stack:)",
                    r"(\s+at\s+[^\s]+\([^\)]*\))",
                    r"(Caused by: [a-zA-Z\.]+Exception)",
                    r"(Error \d+: [^<>\n]+)",
                    r"(UnhandledException|ArgumentException|NullReferenceException)",
                ],
                "severity": "MEDIUM",
            },
            # Mode debug actif
            "debug_mode": {
                "patterns": [
                    r"(DEBUG = True|debug.*=.*true)",
                    r"(<title>.*Debug.*</title>)",
                    r"(development.*mode|debug.*mode)",
                    r"(\$_GET\[|\$_POST\[|\$_SESSION\[)",
                    r"(var_dump\(|print_r\()",
                    r"(console\.log\(|console\.error\()",
                    r"(xdebug|X-Debug)",
                    r"(WP_DEBUG|SCRIPT_DEBUG)",
                    r"(Flask.*Debug|Django.*Debug)",
                    r"(<pre>.*\$[a-zA-Z_].*</pre>)",
                    r"(RAILS_ENV.*development)",
                    r"(NODE_ENV.*development)",
                ],
                "severity": "MEDIUM",
            },
            # Adresses IP internes
            "internal_ip": {
                "patterns": [
                    r"(\b(?:192\.168|10\.|172\.(?:1[6-9]|2[0-9]|3[01]))\.[0-9]{1,3}\.[0-9]{1,3}\b)",
                    r"(\b127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b)",
                    r"(\blocalhost\b)",
                    r"(\b0\.0\.0\.0\b)",
                    r"(\b::1\b)",
                    r"(\bfc00::[a-fA-F0-9:]+\b)",
                    r"(\bfe80::[a-fA-F0-9:]+\b)",
                ],
                "severity": "LOW",
            },
            # Informations sensibles
            "sensitive_info": {
                "patterns": [
                    r'(password\s*[=:]\s*["\'][^"\']{3,}["\'])',
                    r'(api[_\-]?key\s*[=:]\s*["\'][^"\']{10,}["\'])',
                    r'(secret[_\-]?key\s*[=:]\s*["\'][^"\']{10,}["\'])',
                    r'(private[_\-]?key\s*[=:]\s*["\'][^"\']{10,}["\'])',
                    r'(connection[_\-]?string\s*[=:]\s*["\'][^"\']{10,}["\'])',
                    r'(database[_\-]?url\s*[=:]\s*["\'][^"\']{10,}["\'])',
                    r'(smtp[_\-]?password\s*[=:]\s*["\'][^"\']{3,}["\'])',
                    r"(\b[A-Za-z0-9]{32,}\b)",  # Tokens/Hashes potentiels
                    r"(-----BEGIN [A-Z ]+-----)",  # Clés cryptographiques
                ],
                "severity": "HIGH",
            },
            # Énumération de fichiers/dossiers
            "directory_listing": {
                "patterns": [
                    r"(<title>Index of /)",
                    r"(Directory Listing|Directory Contents)",
                    r"(\[DIR\]|\[FILE\])",
                    r'(<a href="[^"]*/">.*</a>.*\d{2}-\w{3}-\d{4})',
                    r"(Parent Directory)",
                    r"(<h1>Index of [^<]*</h1>)",
                    r"(Apache/.* Server at .* Port)",
                ],
                "severity": "MEDIUM",
            },
            # Serveurs et versions
            "server_info": {
                "patterns": [
                    r"(Server:\s*([^\r\n]+))",
                    r"(X-Powered-By:\s*([^\r\n]+))",
                    r"(Apache/[\d\.]+ \([^)]+\))",
                    r"(nginx/[\d\.]+)",
                    r"(Microsoft-IIS/[\d\.]+)",
                    r"(PHP/[\d\.]+)",
                    r"(Python/[\d\.]+)",
                    r"(OpenSSL/[\d\.]+[a-z]?)",
                    r"(mod_ssl/[\d\.]+)",
                ],
                "severity": "LOW",
            },
            # Configuration exposée
            "config_exposure": {
                "patterns": [
                    r"(\[database\]|\[mysql\]|\[postgresql\])",
                    r"(host\s*=.*\nuser\s*=)",
                    r"(DB_HOST|DB_USER|DB_PASS)",
                    r"(MYSQL_ROOT_PASSWORD)",
                    r"(database.*host.*user.*password)",
                    r"(<configuration>.*<connectionStrings>)",
                    r"(web\.config|app\.config)",
                    r"(\.htaccess|\.htpasswd)",
                    r"(phpMyAdmin|Adminer|phpPgAdmin)",
                ],
                "severity": "HIGH",
            },
        }

        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.timeout = 10

    def _make_request(
        self, url: str, authent: tuple[str, str] | None = None
    ) -> tuple[requests.Response, float] | None:
        try:
            start_time = time.time()
            headers = {
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "close",
            }

            response = requests.get(
                url,
                verify=False,
                headers=headers,
                timeout=self.timeout,
                auth=authent,
                allow_redirects=False,
            )
            response_time = time.time() - start_time
            return response, response_time
        except requests.RequestException as e:
            logger.debug(f"Request failed for {url}: {e}")
            return None

    def _find_error_patterns(
        self, content: str, headers: dict[str, str]
    ) -> dict[str, dict[str, Any]]:
        """Recherche améliorée des patterns avec scoring et contexte"""
        findings = {}

        # Analyse séparée du contenu et des headers
        for category, patterns in self.error_patterns.items():
            matches = []
            confidence_scores = []
            header_sources = []  # Track which headers contained matches

            for pattern in patterns:
                try:
                    # Recherche dans le contenu
                    content_matches = re.findall(
                        pattern, content, re.IGNORECASE | re.MULTILINE
                    )
                    if content_matches:
                        confidence = self._calculate_confidence(
                            pattern, content_matches, category
                        )
                        for match in content_matches[:3]:
                            if isinstance(match, tuple):
                                match = match[0] if match[0] else str(match)
                            matches.append(str(match)[:100])
                            confidence_scores.append(confidence)
                            header_sources.append("content")

                    # Recherche dans les headers individuellement
                    for header_name, header_value in headers.items():
                        header_matches = re.findall(
                            pattern, header_value, re.IGNORECASE | re.MULTILINE
                        )
                        if header_matches:
                            confidence = self._calculate_confidence(
                                pattern, header_matches, category
                            )
                            for match in header_matches[:3]:
                                if isinstance(match, tuple):
                                    match = match[0] if match[0] else str(match)
                                matches.append(str(match)[:100])
                                confidence_scores.append(confidence)
                                header_sources.append(f"header:{header_name}")

                except re.error as e:
                    logger.warning(f"Invalid regex pattern {pattern}: {e}")
                    continue

            if matches:
                findings[category] = {
                    "matches": list(set(matches)),  # Supprime les doublons
                    "confidence": max(confidence_scores) if confidence_scores else 0.5,
                    "count": len(matches),
                    "sources": header_sources,  # Ajoute les sources des matches
                }

        return findings

    def _calculate_confidence(
        self, pattern: str, matches: list[Any], category: str
    ) -> float:
        """Calcule un score de confiance pour un match"""
        base_confidence = 0.7

        # Patterns très spécifiques = haute confiance
        specific_indicators = [
            "mysql_fetch_array",
            "Traceback",
            "Fatal error",
            "Exception in thread",
        ]
        if any(indicator in pattern for indicator in specific_indicators):
            base_confidence = 0.9

        # Patterns génériques = confiance plus faible
        generic_indicators = [r"\w+", r"[^<>]*", r".*"]
        if any(indicator in pattern for indicator in generic_indicators):
            base_confidence -= 0.1

        # Ajustement basé sur le nombre de matches
        if len(matches) > 3:
            base_confidence += 0.1
        elif len(matches) == 1:
            base_confidence -= 0.1

        return min(1.0, max(0.1, base_confidence))

    def _analyze_error_response(
        self, payload: str, response: requests.Response, response_time: float
    ) -> dict[str, Any]:
        """Analyse améliorée de la réponse d'erreur"""
        content = ""
        headers = {}

        try:
            content = response.text[:5000] if hasattr(response, "text") else ""
            headers = dict(response.headers) if hasattr(response, "headers") else {}
        except Exception as e:
            logger.warning(f"Error reading response: {e}")
            return {}

        print(
            f" ├─ {response.status_code} error with '{payload}' [{len(response.content)} bytes, {response_time:.2f}s]"
        )

        # Analyse des patterns d'erreur
        error_findings = self._find_error_patterns(content, headers)

        if error_findings:
            for category, findings in error_findings.items():
                confidence = findings["confidence"]
                count = findings["count"]
                sources = findings.get("sources", [])

                print(
                    f"   📍 {category.replace('_', ' ').title()} "
                    f"[Confidence: {confidence:.2f}, Count: {count}]"
                )

                # Affiche les matches trouvés avec leur source
                match_index = 0
                for i, match in enumerate(findings["matches"][:2], 1):
                    clean_match = re.sub(r"<[^>]+>", "", str(match)).strip()
                    if clean_match and len(clean_match) > 3:
                        # Trouve la source correspondante
                        source = (
                            sources[match_index]
                            if match_index < len(sources)
                            else "unknown"
                        )
                        if source.startswith("header:"):
                            header_name = source.split(":", 1)[1]
                            print(
                                f"     └─ Match {i} [Header: {header_name}]: {clean_match[:60]}{'...' if len(clean_match) > 60 else ''}"
                            )
                        else:
                            print(
                                f"     └─ Match {i} [Content]: {clean_match[:80]}{'...' if len(clean_match) > 80 else ''}"
                            )
                        match_index += 1

        # Analyse additionnelle
        self._additional_analysis(payload, response, response_time, content)

        return {
            "status_code": response.status_code,
            "payload": payload,
            "findings": error_findings,
            "response_time": response_time,
            "content_length": len(content),
        }

    def _additional_analysis(
        self,
        payload: str,
        response: requests.Response,
        response_time: float,
        content: str,
    ) -> None:
        """Analyses supplémentaires"""

        # Détection de comportement anormal
        if response_time > 5.0:
            print(f"   ⏱️  Très lent ({response_time:.2f}s) - potentiel vecteur DoS")

        # Analyse de la taille de réponse
        content_length = len(content)
        if content_length > 10000:
            print(f"   📊 Réponse volumineuse ({content_length:,} chars)")
        elif content_length == 0:
            print("   🕳️  Réponse vide")

        # Détection de redirections suspectes
        if 300 <= response.status_code < 400:
            location = response.headers.get("Location", "")
            if location:
                print(f"   🔄 Redirection vers: {location[:100]}")

    def analyze_server_errors(
        self,
        url: str,
        authent: tuple[str, str] | None = None,
    ) -> dict[str, Any]:
        """Analyse principale des erreurs serveur"""
        print(f"{Colors.CYAN} ├ Server error analysis {Colors.RESET}")

        results: dict = {
            "total_tests": len(self.payloads_error),
            "errors_found": 0,
            "findings_by_category": {},
            "detailed_results": [],
        }

        for i, payload in enumerate(self.payloads_error, 1):
            # Construction de l'URL de test
            if url.endswith("/"):
                error_url = f"{url}{payload}"
            else:
                error_url = f"{url}/{payload}"

            # print(f" ├─ Testing payload {i}/{len(self.payloads_error)}: {payload}")

            # Exécution de la requête
            result = self._make_request(error_url, authent)
            if not result:
                print(f" │  ❌ Request failed for {payload}")
                continue

            response, response_time = result

            # Analyse si erreur détectée
            if response.status_code in [400, 500, 501, 502, 503, 504]:
                results["errors_found"] += 1
                analysis = self._analyze_error_response(
                    payload, response, response_time
                )
                results["detailed_results"].append(analysis)

                # Comptabilisation par catégorie
                if "findings" in analysis:
                    for category, findings in analysis["findings"].items():
                        if category not in results["findings_by_category"]:
                            results["findings_by_category"][category] = 0
                        results["findings_by_category"][category] += findings["count"]

        return results


def get_server_error(
    url: str, authent: tuple[str, str] | None = None
) -> dict[str, Any]:
    """Function wrapper pour compatibilité"""
    analyzer = ServerErrorAnalyzer()
    return analyzer.analyze_server_errors(url, authent)
