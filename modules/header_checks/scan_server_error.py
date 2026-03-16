#!/usr/bin/env python3
"""
Enhanced server error analysis with compact grouped display
"""
from typing import Any
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.style import Colors
from utils.utils import configure_logger, re, requests, time

logger = configure_logger(__name__)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0"
)

MAX_RESPONSE_SIZE = 1024 * 1024  # 1 MB
MAX_CONTENT_SCAN = 200_000  # 200K chars for regex analysis
MAX_WORKERS = 10


class ServerErrorAnalyzer:

    def __init__(self) -> None:
        self.payloads_error = [
            # Encoding tricks
            "%2a", "%EXT%", "%ff", "%0A", "%2e", "%0D", "%00",
            "%2f", "%5c", "%c0%af", "%c1%9c", "%c0%80", "%e0%80%80",
            "%f0%80%80%80", "%252e%252e%252f", "..%252f", "..%255c",
            "%u0000", "%u002e", "%u005c", "%%32%65",
            "%27", "%27--",
            "%ff%ff%ff%ff", "%80%81%82%83", "%fe%ff", "%ff%fe",

            # Overflow / CRLF
            "A" * 100,
            "%20" * 50,
            "%0d%0a" * 10,
            "/#fragment" * 50,

            # Path traversal
            "..\\", "../", "....//", "...//", "..../", ".../",
            "..\\..\\", "..%5c..%5c",
            "..%3B/", "..%3B", "..;/", "..;",

            # Path bypass
            "/.;/", "/;/", "/%2e/", "/./", "//", "///", "/...;/",

            # Null byte injection
            "%00.jsp", "test.php%00.jpg", "test.jsp%00.png", ".%00",

            # Backup / sensitive files
            "~", ".bak", ".old", ".tmp",
            ".htaccess", ".git/", ".git/config", ".git/HEAD",
            ".svn/entries", ".env", ".env.local", ".env.production",
            ".config", "web.config", "config.json", "appsettings.json",
            "application.properties", "wp-config.php.bak",
            "settings.py", "database.yml",
            ".well-known/", "robots.txt.bak",

            # Framework extensions
            ".action", ".do", ".jsp", ".aspx",
            ".php.bak", ".php~", ".php.old", ".php.swp", ".php.inc",
            "favicon.ico.php",

            # Template injection
            "${7*7}", "{{7*7}}", "<%=7*7%>", "${{7*7}}",
            "#set($x=7*7)$x", "@(7*7)",
            "eval(1)", "phpinfo()",

            # Command injection
            "|id", ";id", "`id`", "$(id)", "&id", "||id",
            "|whoami", ";cat /etc/passwd", "../../etc/passwd",
            "|ls -la", ";ls -la",
            "system('id')",

            # SQL injection
            "'", "''", "'--",
            "' OR '1'='1", "' OR '1'='1'--",
            "admin'--",
            "1' AND '1'='1", "1' AND '1'='2",
            "\\'",

            # XML/DTD
            "<!DOCTYPE>", "<?xml", "<![CDATA[",

            # Regex / validation
            "test$.jsp", "test^.php", "test[.asp",
            "test].aspx", "test(.jsp)", "test).php",
            "/?[]", "/?{}}",  "/?<>",

            # GraphQL / API
            "/graphql?query={__schema{types{name}}}",
            "/../graphql", "/api/../debug",

            # Spring Boot actuator
            "/trace", "/actuator", "/actuator/env",
            "/actuator/heapdump", "/manage/heapdump",

           # ── CMS / framework / API discovery ───────────────────
            "/?q[]=x",
            "/user/1",
            "/?XDEBUG_SESSION_START=1",
            "/wp-json/",
            "/wp-json/wp/v2/users",
            "/api/v1/",
            "/api/v2/",
            "/swagger.json",
            "/openapi.json",
            "/v2/api-docs",
            "/api-docs",
            "/.DS_Store",

            # ── HTTP method override (via query) ──────────────────
            "?_method=PUT",
            "?_method=DELETE",
            "?_method=TRACE",

            # ── CRLF (encoded, subtle) ────────────────────────────
            "%0d%0aX-Injected:true",
            "%0aX-Injected:true",

            # ── Cache key manipulation (benign) ───────────────────
            "?cb=1",
            "?cachebust=test",
             # ── Debug / actuator / monitoring endpoints ───────────
            "/trace",
            "/actuator",
            "/actuator/env",
            "/actuator/health",
            "/actuator/info",
            "/actuator/mappings",
            "/actuator/heapdump",
            "/manage/heapdump",
            "/debug/vars",
            "/debug/pprof/",
            "/_debug",
            "/_status",
            "/_health",
            "/server-status",
            "/server-info",
            "/status",
            "/info",
            "/metrics",
            "/jolokia",
            "/console",
        ]

        self.error_patterns = self._build_error_patterns()

        self.user_agent = DEFAULT_USER_AGENT
        self.timeout = (5, 10)  # (connect, read)
        self.response_groups: dict[tuple[int, int], list[dict]] = defaultdict(list)
        self.baseline_response: dict[str, int] | None = None
        self._compiled_patterns: dict[str, list[tuple[re.Pattern, str]]] = {}
        self._compile_patterns()

    @staticmethod
    def _build_error_patterns() -> dict[str, dict[str, Any]]:
        return {
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
                    r"(core/modules/[a-z_]+/src/[^\s)]+\.php)",
                    r"(sites/[a-z0-9_\-/]+\.php)",
                    r"(vendor/[a-z0-9_\-/]+\.php)",
                ],
                "severity": "HIGH",
            },
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
                    r"(Table '[^']*' doesn't exist)",
                    r"(Unknown column '[^']*' in 'field list')",
                    r"(Duplicate entry '[^']*' for key)",
                    r"(Access denied for user '[^']*'@'[^']*')",
                    r"(Connection refused.*\d+)",
                    r"(\[SQL Server\]|\[MySQL\]|\[PostgreSQL\]|\[Oracle\])",
                    r"(SQLSTATE\[[A-Z0-9]+\]:[^\n]+)",
                    r"(DatabaseException\w*:[^\n]+)",
                    r"(Illegal mix of collations)",
                    r"(General error: \d+)",
                    r"(\bSELECT\s+[^\n]{20,200}\s+FROM\s+)",
                    r"(Array\s*\(\s*\[:[^\]]+\]\s*=>)",
                ],
                "severity": "HIGH",
            },
            "stack_trace": {
                "patterns": [
                    r"(Traceback \(most recent call last\):)",
                    r"(at [a-zA-Z0-9_.]+\.[a-zA-Z0-9_]+\([^)]*\)\s*~\s*line\s+\d+)",
                    r'(Exception in thread "[^"]*")',
                    r"(java\.lang\.\w*Exception)",
                    r"(System\.Exception:|System\.\w*Exception)",
                    r"(Fatal error:.*line\s+\d+)",
                    r"(Warning:.*line\s+\d+)",
                    r"(Notice:.*line\s+\d+)",
                    r"(Call to undefined function.*line\s+\d+)",
                    r"(Parse error:.*line\s+\d+)",
                    r"(stack trace:|call stack:)",
                    r"(Caused by: [a-zA-Z.]+Exception)",
                    r"(UnhandledException|ArgumentException|NullReferenceException)",
                    r"([A-Za-z]+\\[A-Za-z\\]+::[a-zA-Z_]+\(\))",
                ],
                "severity": "MEDIUM",
            },
            "debug_mode": {
                "patterns": [
                    r"(DEBUG\s*=\s*True|debug\s*=\s*true)",
                    r"(<title>.*Debug.*</title>)",
                    r"(development\s+mode|debug\s+mode)",
                    r"(\$_GET\[|\$_POST\[|\$_SESSION\[)",
                    r"(var_dump\(|print_r\()",
                    r"(WP_DEBUG|SCRIPT_DEBUG)",
                    r"(Flask.*Debug|Django.*Debug)",
                    r"(RAILS_ENV.*development)",
                    r"(NODE_ENV.*development)",
                ],
                "severity": "MEDIUM",
            },
            "internal_ip": {
                "patterns": [
                    r"(\b(?:192\.168|10\.|172\.(?:1[6-9]|2[0-9]|3[01]))\.\d{1,3}\.\d{1,3}\b)",
                    r"(\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)",
                    r"(\blocalhost\b)",
                    r"(\b0\.0\.0\.0\b)",
                    r"(\b::1\b)",
                    r"(\bfc00::[a-fA-F0-9:]+\b)",
                    r"(\bfe80::[a-fA-F0-9:]+\b)",
                ],
                "severity": "LOW",
            },
            "sensitive_info": {
                "patterns": [
                    r'(password\s*[=:]\s*["\'][^"\']{3,}["\'])',
                    r'(api[_-]?key\s*[=:]\s*["\'][^"\']{10,}["\'])',
                    r'(secret[_-]?key\s*[=:]\s*["\'][^"\']{10,}["\'])',
                    r'(private[_-]?key\s*[=:]\s*["\'][^"\']{10,}["\'])',
                    r'(connection[_-]?string\s*[=:]\s*["\'][^"\']{10,}["\'])',
                    r'(database[_-]?url\s*[=:]\s*["\'][^"\']{10,}["\'])',
                    r'(smtp[_-]?password\s*[=:]\s*["\'][^"\']{3,}["\'])',
                    r"(-----BEGIN [A-Z ]+-----)",
                ],
                "severity": "HIGH",
            },
            "directory_listing": {
                "patterns": [
                    r"(<title>Index of /)",
                    r"(Directory Listing|Directory Contents)",
                    r"(\[DIR\]|\[FILE\])",
                    r"(Parent Directory)",
                    r"(<h1>Index of [^<]*</h1>)",
                    r"(Apache/.* Server at .* Port)",
                ],
                "severity": "MEDIUM",
            },
            "server_info": {
                "patterns": [
                    r"(Apache/[\d.]+ \([^)]+\))",
                    r"(nginx/[\d.]+)",
                    r"(Microsoft-IIS/[\d.]+)",
                    r"(PHP/[\d.]+)",
                    r"(Python/[\d.]+)",
                    r"(OpenSSL/[\d.]+[a-z]?)",
                ],
                "severity": "LOW",
            },
            "config_exposure": {
                "patterns": [
                    r"(\[database\]|\[mysql\]|\[postgresql\])",
                    r"(host\s*=.*\nuser\s*=)",
                    r"(DB_HOST|DB_USER|DB_PASS)",
                    r"(MYSQL_ROOT_PASSWORD)",
                    r"(<configuration>.*<connectionStrings>)",
                    r"(phpMyAdmin|Adminer|phpPgAdmin)",
                ],
                "severity": "HIGH",
            },
            "framework_error": {
                "patterns": [
                    r"(Spring Framework|org\.springframework)",
                    r"(Django|django\.core\.exceptions)",
                    r"(Laravel|Illuminate\\)",
                    r"(Express\.js|at [^\s]+\.js:\d+:\d+)",
                    r"(Rails|ActionController::)",
                    r"(Flask|werkzeug\.exceptions)",
                    r"(ASP\.NET|System\.Web\.HttpException)",
                    r"(Tomcat|org\.apache\.catalina)",
                    r"(JBoss|org\.jboss\.)",
                    r"(WebLogic|weblogic\.servlet)",
                    r"(Struts|org\.apache\.struts)",
                ],
                "severity": "MEDIUM",
            },
            "version_exposure": {
                "patterns": [
                    r"(Apache/[\d.]+ \([^)]+\) Server at)",
                    r"(PHP/[\d.]+ Development Server)",
                    r"(Python/[\d.]+.*Werkzeug/[\d.]+)",
                    r"(Microsoft-IIS/[\d.]+ ASP\.NET Version:[\d.]+)",
                    r"(Rails [\d.]+)",
                    r"(Laravel Framework [\d.]+)",
                    r"(Django/[\d.]+)",
                    r"(Node\.js/v[\d.]+)",
                ],
                "severity": "LOW",
            },
            "graphql_error": {
                "patterns": [
                    r"(GraphQL\.ExecutionError)",
                    r"(GraphQLError:)",
                    r"(Query validation error)",
                    r"(Cannot query field)",
                    r"(Syntax Error: Expected)",
                ],
                "severity": "MEDIUM",
            },
            "jwt_error": {
                "patterns": [
                    r"(JWT.*expired|JWT.*invalid)",
                    r"(JsonWebToken.*Error)",
                    r"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+)",
                    r"(invalid.*signature)",
                    r"(token.*malformed)",
                ],
                "severity": "HIGH",
            },
            "deserialization_error": {
                "patterns": [
                    r"(java\.io\.ObjectInputStream)",
                    r"(unserialize\(\))",
                    r"(pickle\.loads)",
                    r"(__wakeup|__destruct)",
                    r"(Serialization.*Exception)",
                ],
                "severity": "HIGH",
            },
        }

    def _compile_patterns(self) -> None:
        """Pre-compile all regex patterns for performance"""
        for category, data in self.error_patterns.items():
            compiled = []
            for pattern in data["patterns"]:
                try:
                    compiled.append(
                        (re.compile(pattern, re.IGNORECASE | re.MULTILINE), pattern)
                    )
                except re.error as e:
                    logger.warning(f"Invalid regex pattern {pattern}: {e}")
            self._compiled_patterns[category] = compiled

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
                stream=True,
            )

            # Read response with size limit to avoid hanging on huge bodies
            content = b""
            for chunk in response.iter_content(chunk_size=8192):
                content += chunk
                if len(content) >= MAX_RESPONSE_SIZE:
                    logger.debug(f"Response truncated at {MAX_RESPONSE_SIZE} bytes: {url}")
                    break
            response._content = content
            response.close()

            response_time = time.time() - start_time
            return response, response_time
        except UnicodeDecodeError as e:
            logger.debug(f"Unicode decode error for {url}: {e}")
            return None
        except requests.RequestException as e:
            logger.debug(f"Request failed for {url}: {e}")
            return None

    def _establish_baseline(self, url: str, authent: tuple[str, str] | None = None) -> None:
        """Establish baseline response for comparison"""
        result = self._make_request(url, authent)
        if result:
            response, _ = result
            self.baseline_response = {
                "status_code": response.status_code,
                "content_length": len(response.content),
            }

    @staticmethod
    def _get_size_range(size: int, tolerance: int = 100) -> int:
        return (size // tolerance) * tolerance

    def _is_response_interesting(self, status_code: int, content_length: int) -> bool:
        """Check if response is different from baseline"""
        if not self.baseline_response:
            return True

        if status_code != self.baseline_response["status_code"]:
            return True

        baseline_size = self.baseline_response["content_length"]
        if baseline_size > 0:
            size_diff_ratio = abs(content_length - baseline_size) / baseline_size
            if size_diff_ratio > 0.2:
                return True

        if content_length < 100 or content_length > 50000:
            return True

        return False

    def _find_error_patterns(
        self, content: str, headers: dict[str, str]
    ) -> dict[str, dict[str, Any]]:
        findings: dict[str, dict[str, Any]] = {}

        # Truncate content to avoid catastrophic backtracking
        truncated = content[:MAX_CONTENT_SCAN]

        for category, compiled_list in self._compiled_patterns.items():
            matches: list[str] = []
            confidence_scores: list[float] = []
            header_sources: list[str] = []

            for compiled_re, raw_pattern in compiled_list:
                # Search in body
                content_matches = compiled_re.findall(truncated)
                if content_matches:
                    confidence = self._calculate_confidence(raw_pattern, content_matches, category)
                    for match in content_matches[:3]:
                        if isinstance(match, tuple):
                            match = match[0] if match[0] else str(match)
                        matches.append(str(match)[:100])
                        confidence_scores.append(confidence)
                        header_sources.append("content")

                # Search in headers
                for header_name, header_value in headers.items():
                    header_matches = compiled_re.findall(header_value)
                    if header_matches:
                        confidence = self._calculate_confidence(raw_pattern, header_matches, category)
                        for match in header_matches[:3]:
                            if isinstance(match, tuple):
                                match = match[0] if match[0] else str(match)
                            matches.append(str(match)[:100])
                            confidence_scores.append(confidence)
                            header_sources.append(f"header:{header_name}")

            if matches:
                findings[category] = {
                    "matches": list(set(matches)),
                    "confidence": max(confidence_scores),
                    "count": len(matches),
                    "sources": header_sources,
                    "severity": self.error_patterns[category]["severity"],
                }

        return findings

    @staticmethod
    def _calculate_confidence(
        pattern: str, matches: list[Any], category: str
    ) -> float:
        base_confidence = 0.7

        specific_indicators = [
            "mysql_fetch_array", "Traceback", "Fatal error", "Exception in thread",
            "SQLSTATE", "GraphQLError", "JWT", "ObjectInputStream",
        ]
        if any(ind in pattern for ind in specific_indicators):
            base_confidence = 0.9

        generic_indicators = [r"\w+", r"[^<>]*", r".*"]
        if any(ind in pattern for ind in generic_indicators):
            base_confidence -= 0.1

        if len(matches) > 3:
            base_confidence += 0.1
        elif len(matches) == 1:
            base_confidence -= 0.1

        return min(1.0, max(0.1, base_confidence))

    @staticmethod
    def _get_status_text(status_code: int) -> str:
        status_map = {
            200: "OK", 301: "Moved Permanently", 302: "Found",
            304: "Not Modified", 400: "Bad Request", 401: "Unauthorized",
            403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
            413: "Payload Too Large", 414: "URI Too Long",
            429: "Too Many Requests",
            500: "Internal Server Error", 501: "Not Implemented",
            502: "Bad Gateway", 503: "Service Unavailable",
            504: "Gateway Timeout", 520: "Unknown Error",
        }
        return status_map.get(status_code, str(status_code))

    @staticmethod
    def _format_payload_display(payload: str, max_len: int = 30) -> str:
        if len(payload) <= max_len:
            return payload
        return payload[: max_len - 3] + "..."

    def _analyze_response_behavior(
        self,
        payload: str,
        response: requests.Response,
        response_time: float,
    ) -> dict[str, Any] | None:
        try:
            content = response.text if hasattr(response, "text") else ""
            headers = dict(response.headers) if hasattr(response, "headers") else {}
        except Exception as e:
            logger.warning(f"Error reading response: {e}")
            return None

        error_findings = self._find_error_patterns(content, headers)
        is_interesting = self._is_response_interesting(response.status_code, len(content))

        if not error_findings and not is_interesting:
            return None

        size_range = self._get_size_range(len(content))
        group_key = (response.status_code, size_range)

        analysis = {
            "status_code": response.status_code,
            "payload": payload,
            "findings": error_findings,
            "response_time": response_time,
            "content_length": len(content),
            "group_key": group_key,
            "is_interesting": is_interesting,
        }

        self.response_groups[group_key].append(analysis)
        return analysis

    # ── Display helpers ────────────────────────────────────────────────

    def _print_finding_matches(self, findings: dict[str, dict[str, Any]]) -> None:
        """Print sub-lines for finding matches"""
        for category, finding in list(findings.items())[:2]:
            for match in finding["matches"][:1]:
                clean = re.sub(r"<[^>]+>", "", str(match)).strip()
                if clean and len(clean) > 3:
                    display = clean[:70] + "..." if len(clean) > 70 else clean
                    print(f" │       └─ {display}")

    def _build_indicators(self, findings: dict[str, dict[str, Any]]) -> str:
        indicators = []
        for category in list(findings)[:2]:
            cat_name = category.replace("_", " ").title()
            indicators.append(f"[{cat_name}]")
        return f" {' '.join(indicators)}" if indicators else ""

    @staticmethod
    def _status_color(status_code: int) -> str:
        if status_code >= 500:
            return Colors.RED
        if status_code >= 400:
            return Colors.YELLOW
        if status_code >= 300:
            return Colors.BLUE
        return Colors.GREEN

    def _print_single_result(self, analysis: dict[str, Any]) -> None:
        sc = analysis["status_code"]
        payload_display = self._format_payload_display(analysis["payload"], 35)
        status_text = self._get_status_text(sc)
        color = self._status_color(sc)
        indicators = self._build_indicators(analysis.get("findings", {}))

        print(
            f" ├── Payload: {payload_display:<35} → "
            f"{color}{sc} {status_text}{Colors.RESET} "
            f"[{analysis['content_length']} bytes]{indicators}"
        )

        if analysis.get("findings"):
            self._print_finding_matches(analysis["findings"])

    def _print_results_inline(self) -> None:
        if not self.response_groups:
            return

        sorted_groups = sorted(
            self.response_groups.items(), key=lambda x: (x[0][0], x[0][1])
        )

        for (status_code, _size_range), analyses in sorted_groups:
            if len(analyses) < 3:
                for analysis in analyses:
                    self._print_single_result(analysis)
            else:
                first = analyses[0]
                payload_display = self._format_payload_display(first["payload"], 35)
                status_text = self._get_status_text(status_code)
                color = self._status_color(status_code)
                indicators = self._build_indicators(first.get("findings", {}))
                similar = len(analyses) - 1

                print(
                    f" ├── Payload: {payload_display:<35} → "
                    f"{color}{status_code} {status_text}{Colors.RESET} "
                    f"[{first['content_length']} bytes] (+{similar} similar){indicators}"
                )

                if first.get("findings"):
                    self._print_finding_matches(first["findings"])

    # ── Main entry point ───────────────────────────────────────────────

    def _test_payload(
        self, url: str, payload: str, authent: tuple[str, str] | None
    ) -> dict[str, Any] | None:
        """Test a single payload (used by thread pool)"""
        sep = "" if url.endswith("/") else "/"
        error_url = f"{url}{sep}{payload}"

        result = self._make_request(error_url, authent)
        if not result:
            return None

        response, response_time = result
        return self._analyze_response_behavior(payload, response, response_time)

    def analyze_server_errors(
        self,
        url: str,
        authent: tuple[str, str] | None = None,
        threads: int = MAX_WORKERS,
    ) -> dict[str, Any]:
        print(f"{Colors.CYAN} ├ Server error analysis{Colors.RESET}")

        self._establish_baseline(url, authent)

        results: dict[str, Any] = {
            "total_tests": len(self.payloads_error),
            "findings_count": 0,
            "detailed_results": [],
        }

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self._test_payload, url, payload, authent): payload
                for payload in self.payloads_error
            }

            for future in as_completed(futures):
                try:
                    analysis = future.result()
                    if analysis:
                        results["findings_count"] += 1
                        results["detailed_results"].append(analysis)
                except Exception as e:
                    logger.debug(f"Payload test error: {e}")

        self._print_results_inline()
        return results


def check_server_error(
    url: str, authent: tuple[str, str] | None = None
) -> dict[str, Any]:
    analyzer = ServerErrorAnalyzer()
    return analyzer.analyze_server_errors(url, authent)