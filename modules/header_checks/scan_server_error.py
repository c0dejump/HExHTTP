#!/usr/bin/env python3
"""
Enhanced server error analysis with compact grouped display
"""
from typing import Any
from collections import defaultdict

from utils.style import Colors
from utils.utils import configure_logger, re, requests, time

logger = configure_logger(__name__)

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0"
)


class ServerErrorAnalyzer:

    def __init__(self) -> None:
        self.payloads_error = [
            # Payloads originaux
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
            "@",
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
            
            # Nouveaux payloads - Encoding/Parsing errors
            "%c0%80",
            "%e0%80%80",
            "%f0%80%80%80",
            "%20" * 50,
            "%0d%0a" * 10,
            
            # Path traversal avancé
            "..;/",
            "..;",
            "...//",
            "..../",
            ".../",
            "..\\..\\",
            "..%5c..%5c",
            "..%255c",
            
            # Invalid syntax
            "/?[]",
            "/?{}}",
            "/?<>",
            "/#fragment" * 50,
            
            # Framework specific
            ".action",
            ".do",
            ".jsp",
            ".aspx",
            ".php.bak",
            ".php~",
            ".php.old",
            ".php.swp",
            ".php.inc",
            
            # Template injection
            "#set($x=7*7)$x",
            "@(7*7)",
            
            # Command injection
            "|id",
            ";id",
            "`id`",
            "$(id)",
            "&id",
            "||id",
            ";ls -la",
            "|ls -la",
            
            # SQL injection
            "'",
            "''",
            "'--",
            "' OR '1'='1'--",
            "' UNION SELECT NULL--",
            "admin'--",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "\\'",
            "%27",
            "%27--",
            
            # XML/DTD
            "<!DOCTYPE>",
            "<?xml",
            "<![CDATA[",
            
            # Path bypass
            "/.;/",
            "/;/",
            "/%2e/",
            "/./",
            "//",
            "///",
            "/...;/",
            
            # Config files
            ".git/config",
            ".git/HEAD",
            ".svn/entries",
            ".env.local",
            ".env.production",
            "config.json",
            "appsettings.json",
            "application.properties",
            "wp-config.php.bak",
            "settings.py",
            "database.yml",
            
            # Null byte injection
            "%00.jsp",
            "test.php%00.jpg",
            "test.jsp%00.png",
            ".%00",
            
            # Regex/validation errors
            "test$.jsp",
            "test^.php",
            "test[.asp",
            "test].aspx",
            "test(.jsp)",
            "test).php",
            
            # GraphQL/API
            "/graphql?query={__schema{types{name}}}",
            "/../graphql",
            "/api/../debug",
            
            # Charset errors
            "%ff%ff%ff%ff",
            "%80%81%82%83",
            "%fe%ff",
            "%ff%fe",
            
            # Spring Boot
            "/trace",
            "/actuator",
            "/actuator/env",
            "/actuator/heapdump",
            "/manage/heapdump",
            
            # CMS specific
            "/?q[]=x",
            "/user/1",
            "/?XDEBUG_SESSION_START=1",
            "/?PHPSTORM_DEBUG=1",
            
            # Cache/CDN
            "/.well-known/",
            "/favicon.ico.php",
            "/robots.txt.bak",
        ]

        self.error_patterns = {
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
                    r"(core/modules/[a-z_]+/src/[^\s\)]+\.php)",
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
                    r"(Table \'[^\']*\' doesn\'t exist)",
                    r"(Unknown column \'[^\']*\' in \'field list\')",
                    r"(Duplicate entry \'[^\']*\' for key)",
                    r"(Access denied for user \'[^\']*\'@\'[^\']*\')",
                    r"(Connection refused.*\d+)",
                    r"(\[SQL Server\]|\[MySQL\]|\[PostgreSQL\]|\[Oracle\])",
                    r"(SQLSTATE\[\w+\]:[^\n]+)",
                    r"(DatabaseException\w*:[^\n]+)",
                    r"(SQL syntax[^\n]+)",
                    r"(Illegal mix of collations)",
                    r"(General error: \d+)",
                    r"(\bSELECT\s+[^\n]{20,200}\s+FROM\s+)",
                    r"(Array\s*\(\s*\[:[^\]]+\]\s*=>)",
                    r"(SQLSTATE\[[A-Z0-9]+\]:)",
                    r"(DatabaseException\w*)",
                ],
                "severity": "HIGH",
            },
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
                    r"([A-Za-z]+\\[A-Za-z\\]+::[a-zA-Z_]+\(\))",
                ],
                "severity": "MEDIUM",
            },
            "debug_mode": {
                "patterns": [
                    r"(DEBUG = True|debug.*=.*true)",
                    r"(<title>.*Debug.*</title>)",
                    r"(development.*mode|debug.*mode)",
                    r"(\$_GET\[|\$_POST\[|\$_SESSION\[)",
                    r"(var_dump\(|print_r\()",
                    r"(xdebug|X-Debug)",
                    r"(WP_DEBUG|SCRIPT_DEBUG)",
                    r"(Flask.*Debug|Django.*Debug)",
                    r"(<pre>.*\$[a-zA-Z_].*</pre>)",
                    r"(RAILS_ENV.*development)",
                    r"(NODE_ENV.*development)",
                ],
                "severity": "MEDIUM",
            },
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
            "sensitive_info": {
                "patterns": [
                    r'(password\s*[=:]\s*["\'][^"\']{3,}["\'])',
                    r'(api[_\-]?key\s*[=:]\s*["\'][^"\']{10,}["\'])',
                    r'(secret[_\-]?key\s*[=:]\s*["\'][^"\']{10,}["\'])',
                    r'(private[_\-]?key\s*[=:]\s*["\'][^"\']{10,}["\'])',
                    r'(connection[_\-]?string\s*[=:]\s*["\'][^"\']{10,}["\'])',
                    r'(database[_\-]?url\s*[=:]\s*["\'][^"\']{10,}["\'])',
                    r'(smtp[_\-]?password\s*[=:]\s*["\'][^"\']{3,}["\'])',
                    r"(-----BEGIN [A-Z ]+-----)",
                ],
                "severity": "HIGH",
            },
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
                    r"(Play Framework|play\.api\.)",
                ],
                "severity": "MEDIUM",
            },
            "version_exposure": {
                "patterns": [
                    r"(Apache/[\d\.]+ \([^)]+\) Server at)",
                    r"(nginx/[\d\.]+ \(Ubuntu\))",
                    r"(PHP/[\d\.]+ Development Server)",
                    r"(Python/[\d\.]+.*Werkzeug/[\d\.]+)",
                    r"(Microsoft-IIS/[\d\.]+ ASP\.NET Version:[\d\.]+)",
                    r"(Rails [\d\.]+)",
                    r"(Laravel Framework [\d\.]+)",
                    r"(Django/[\d\.]+)",
                    r"(Express/[\d\.]+)",
                    r"(Node\.js/v[\d\.]+)",
                ],
                "severity": "LOW",
            },
            "graphql_error": {
                "patterns": [
                    r"(GraphQL\.ExecutionError)",
                    r"(GraphQLError:)",
                    r"(Query validation error)",
                    r"(graphql\.error\.)",
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
                    r"(Bearer.*[A-Za-z0-9_-]{20,})",
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
                    r"(readObject|writeObject)",
                ],
                "severity": "HIGH",
            },
        }

        self.user_agent = DEFAULT_USER_AGENT
        self.timeout = 10
        self.response_groups: dict[tuple[int, int], list[dict]] = defaultdict(list)
        self.baseline_response = None

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

    def _get_size_range(self, size: int, tolerance: int = 100) -> int:
        return (size // tolerance) * tolerance

    def _is_response_interesting(self, status_code: int, content_length: int) -> bool:
        """Check if response is different from baseline"""
        if not self.baseline_response:
            return True
        
        # Different status code
        if status_code != self.baseline_response["status_code"]:
            return True
        
        baseline_size = self.baseline_response["content_length"]
        if baseline_size > 0:
            size_diff_ratio = abs(content_length - baseline_size) / baseline_size
            if size_diff_ratio > 0.2:  # More than 20% difference
                return True
        
        # Very small or very large responses
        if content_length < 100 or content_length > 50000:
            return True
        
        return False

    def _find_error_patterns(
        self, content: str, headers: dict[str, str]
    ) -> dict[str, dict[str, Any]]:
        findings = {}

        for category, category_data in self.error_patterns.items():
            matches = []
            confidence_scores = []
            header_sources = []

            for pattern in category_data["patterns"]:
                try:
                    # Search in content
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

                    # Search in headers
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
                    "matches": list(set(matches)),
                    "confidence": max(confidence_scores) if confidence_scores else 0.5,
                    "count": len(matches),
                    "sources": header_sources,
                    "severity": category_data["severity"],
                }

        return findings

    def _calculate_confidence(
        self, pattern: str, matches: list[Any], category: str
    ) -> float:
        base_confidence = 0.7

        # High confidence indicators
        specific_indicators = [
            "mysql_fetch_array", "Traceback", "Fatal error", "Exception in thread",
            "SQLSTATE", "GraphQLError", "JWT", "ObjectInputStream"
        ]
        if any(indicator in pattern for indicator in specific_indicators):
            base_confidence = 0.9

        # Lower confidence for generic patterns
        generic_indicators = [r"\w+", r"[^<>]*", r".*"]
        if any(indicator in pattern for indicator in generic_indicators):
            base_confidence -= 0.1

        # Adjust based on match count
        if len(matches) > 3:
            base_confidence += 0.1
        elif len(matches) == 1:
            base_confidence -= 0.1

        return min(1.0, max(0.1, base_confidence))

    def _get_status_text(self, status_code: int) -> str:
        """Get human-readable status text"""
        status_map = {
            200: "OK",
            301: "Moved Permanently",
            302: "Found",
            304: "Not Modified",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            405: "Method Not Allowed",
            500: "Internal Server Error",
            501: "Not Implemented",
            502: "Bad Gateway",
            503: "Service Unavailable",
            504: "Gateway Timeout",
        }
        return status_map.get(status_code, str(status_code))

    def _format_payload_display(self, payload: str, max_len: int = 30) -> str:
        """Format payload for display"""
        if len(payload) <= max_len:
            return payload
        return payload[:max_len-3] + "..."

    def _analyze_response_behavior(
        self, 
        payload: str, 
        response: requests.Response, 
        response_time: float
    ) -> dict[str, Any] | None:
        """Analyze response and group similar ones"""
        content = ""
        headers = {}
        
        try:
            content = response.text if hasattr(response, "text") else ""
            headers = dict(response.headers) if hasattr(response, "headers") else {}
        except Exception as e:
            logger.warning(f"Error reading response: {e}")
            return None

        # Check for error patterns
        error_findings = self._find_error_patterns(content, headers)
        
        # Check if response is interesting (different from baseline)
        is_interesting = self._is_response_interesting(response.status_code, len(content))
        
        # Only keep responses with findings OR interesting behavior
        if not error_findings and not is_interesting:
            return None
        
        # Group by status code and size range
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

        # Add to group
        self.response_groups[group_key].append(analysis)

        return analysis

    def _print_single_result(self, analysis: dict[str, Any]) -> None:
        """Print a single result line"""
        status_code = analysis["status_code"]
        payload = analysis["payload"]
        exact_size = analysis["content_length"]
        
        # Color based on status code
        if status_code >= 500:
            status_color = Colors.RED
        elif status_code >= 400:
            status_color = Colors.YELLOW
        elif status_code >= 300:
            status_color = Colors.BLUE
        else:
            status_color = Colors.GREEN
        
        # Format payload display (max 35 chars)
        payload_display = self._format_payload_display(payload, 35)
        
        # Format status text
        status_text = self._get_status_text(status_code)
        
        # Build findings indicators
        indicators = []
        if analysis.get("findings"):
            for category, finding in analysis["findings"].items():
                cat_name = category.replace("_", " ").title()
                indicators.append(f"[{cat_name}]")
        
        indicators_text = f" {' '.join(indicators[:2])}" if indicators else ""
        
        # Print the one-liner
        print(f" ├── Payload: {payload_display:<35} → {status_color}{status_code} {status_text}{Colors.RESET} [{exact_size} bytes]{indicators_text}")
        
        # If there are findings with matches, show them on sub-lines
        if analysis.get("findings"):
            for category, finding in list(analysis["findings"].items())[:2]:  # Max 2 categories
                for match in finding["matches"][:1]:  # Max 1 match per category
                    clean_match = re.sub(r"<[^>]+>", "", str(match)).strip()
                    if clean_match and len(clean_match) > 3:
                        match_display = clean_match[:70] + "..." if len(clean_match) > 70 else clean_match
                        print(f" │       └─ {match_display}")

    def _print_results_inline(self) -> None:
        """Print results in one-liner format, grouping only if 3+ similar"""
        if not self.response_groups:
            return
        
        # Sort groups by status code, then by size
        sorted_groups = sorted(self.response_groups.items(), key=lambda x: (x[0][0], x[0][1]))
        
        for group_key, analyses in sorted_groups:
            status_code, size_range = group_key
            
            # If less than 3 responses in this group, print individually
            if len(analyses) < 3:
                for analysis in analyses:
                    self._print_single_result(analysis)
            else:
                # Group display for 3+ similar responses
                first_analysis = analyses[0]
                first_payload = first_analysis["payload"]
                
                # Color based on status code
                if status_code >= 500:
                    status_color = Colors.RED
                elif status_code >= 400:
                    status_color = Colors.YELLOW
                elif status_code >= 300:
                    status_color = Colors.BLUE
                else:
                    status_color = Colors.GREEN
                
                # Format payload display (max 35 chars)
                payload_display = self._format_payload_display(first_payload, 35)
                
                # Format status text
                status_text = self._get_status_text(status_code)
                
                # Build the line
                similar_count = len(analyses) - 1
                similar_text = f" (+{similar_count} similar)"
                
                # Get exact size from first response
                exact_size = first_analysis["content_length"]
                
                # Build findings indicators
                indicators = []
                if first_analysis.get("findings"):
                    for category, finding in first_analysis["findings"].items():
                        cat_name = category.replace("_", " ").title()
                        indicators.append(f"[{cat_name}]")
                
                indicators_text = f" {' '.join(indicators[:2])}" if indicators else ""
                
                # Print the one-liner
                print(f" ├── Payload: {payload_display:<35} → {status_color}{status_code} {status_text}{Colors.RESET} [{exact_size} bytes]{similar_text}{indicators_text}")
                
                # If there are findings with matches, show them on sub-lines
                if first_analysis.get("findings"):
                    for category, finding in list(first_analysis["findings"].items())[:2]:  # Max 2 categories
                        for match in finding["matches"][:1]:  # Max 1 match per category
                            clean_match = re.sub(r"<[^>]+>", "", str(match)).strip()
                            if clean_match and len(clean_match) > 3:
                                match_display = clean_match[:70] + "..." if len(clean_match) > 70 else clean_match
                                print(f" │       └─ {match_display}")

    def analyze_server_errors(
        self,
        url: str,
        authent: tuple[str, str] | None = None,
    ) -> dict[str, Any]:
        print(f"{Colors.CYAN} ├ Server error analysis{Colors.RESET}")
        
        # Establish baseline
        self._establish_baseline(url, authent)

        results: dict = {
            "total_tests": len(self.payloads_error),
            "findings_count": 0,
            "detailed_results": [],
        }

        for i, payload in enumerate(self.payloads_error, 1):
            if url.endswith("/"):
                error_url = f"{url}{payload}"
            else:
                error_url = f"{url}/{payload}"

            result = self._make_request(error_url, authent)
            if not result:
                continue

            response, response_time = result
            
            analysis = self._analyze_response_behavior(payload, response, response_time)
            
            if analysis:
                results["findings_count"] += 1
                results["detailed_results"].append(analysis)

        # Print results inline
        self._print_results_inline()

        return results


def check_server_error(
    url: str, authent: tuple[str, str] | None = None
) -> dict[str, Any]:
    analyzer = ServerErrorAnalyzer()
    return analyzer.analyze_server_errors(url, authent)