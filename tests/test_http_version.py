#!/usr/bin/env python3
"""
Test suite for the http_version module.

This test suite covers HTTP version detection, protocol analysis,
and security vulnerability testing functions.
"""

from collections.abc import Generator
from unittest.mock import Mock, patch

import pytest

from modules.header_checks.http_version import (
    analyze_response_headers,
    check_http_version,
    classify_version_token,
    detect_http_version_support,
    first_line_and_code,
    is_likely_http09_response,
    make_tls_socket,
    parse_target,
    risk_badge,
    sanitize_first_line,
    validate_vulnerability_response,
)


class TestParseTarget:
    """Test URL parsing functionality."""

    def test_parse_http_url(self) -> None:
        """Test parsing basic HTTP URL."""
        scheme, host, port, path = parse_target("http://example.com/path")
        assert scheme == "http"
        assert host == "example.com"
        assert port == 80
        assert path == "/path"

    def test_parse_https_url(self) -> None:
        """Test parsing HTTPS URL."""
        scheme, host, port, path = parse_target("https://example.com/path")
        assert scheme == "https"
        assert host == "example.com"
        assert port == 443
        assert path == "/path"

    def test_parse_url_with_port(self) -> None:
        """Test parsing URL with custom port."""
        scheme, host, port, path = parse_target("http://example.com:8080/path")
        assert scheme == "http"
        assert host == "example.com"
        assert port == 8080
        assert path == "/path"

    def test_parse_url_with_query(self) -> None:
        """Test parsing URL with query parameters."""
        scheme, host, port, path = parse_target("http://example.com/path?param=value")
        assert scheme == "http"
        assert host == "example.com"
        assert port == 80
        assert path == "/path?param=value"

    def test_parse_url_no_scheme(self) -> None:
        """Test parsing URL without scheme - urlparse treats it as path."""
        scheme, host, port, path = parse_target("example.com/path")
        assert scheme == "http"
        assert host is None  # urlparse treats this as path, not hostname
        assert port == 80
        assert path == "example.com/path"

    def test_parse_url_root_path(self) -> None:
        """Test parsing URL with root path."""
        scheme, host, port, path = parse_target("http://example.com")
        assert scheme == "http"
        assert host == "example.com"
        assert port == 80
        assert path == "/"


class TestDetectHttpVersionSupport:
    """Test HTTP version detection via ALPN."""

    @patch("modules.header_checks.http_version.socket.create_connection")
    @patch("modules.header_checks.http_version.ssl.create_default_context")
    def test_detect_http2_support(
        self, mock_ssl_context: Mock, mock_socket: Mock
    ) -> None:
        """Test detection of HTTP/2 support."""
        # Mock SSL socket with HTTP/2 support
        mock_ssl_socket = Mock()
        mock_ssl_socket.selected_alpn_protocol.return_value = "h2"

        mock_context = Mock()
        mock_context.wrap_socket.return_value = mock_ssl_socket
        mock_ssl_context.return_value = mock_context

        result = detect_http_version_support("https://example.com")
        assert result == ["h2"]
        mock_ssl_socket.close.assert_called_once()

    @patch("modules.header_checks.http_version.socket.create_connection")
    @patch("modules.header_checks.http_version.ssl.create_default_context")
    def test_detect_http11_support(
        self, mock_ssl_context: Mock, mock_socket: Mock
    ) -> None:
        """Test detection of HTTP/1.1 support."""
        mock_ssl_socket = Mock()
        mock_ssl_socket.selected_alpn_protocol.return_value = "http/1.1"

        mock_context = Mock()
        mock_context.wrap_socket.return_value = mock_ssl_socket
        mock_ssl_context.return_value = mock_context

        result = detect_http_version_support("https://example.com")
        assert result == ["http/1.1"]

    def test_detect_non_https_returns_empty(self) -> None:
        """Test that non-HTTPS URLs return empty list."""
        result = detect_http_version_support("http://example.com")
        assert result == []

    @patch("modules.header_checks.http_version.socket.create_connection")
    def test_detect_connection_error(self, mock_socket: Mock) -> None:
        """Test handling of connection errors."""
        mock_socket.side_effect = ConnectionError("Connection failed")
        result = detect_http_version_support("https://example.com")
        assert result == []


class TestAnalyzeResponseHeaders:
    """Test HTTP response header analysis."""

    def test_analyze_valid_response(self) -> None:
        """Test analysis of valid HTTP response headers."""
        response = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\nConnection: close\r\n\r\nBody content"

        result = analyze_response_headers(response)
        assert result["server"] == "nginx/1.18.0"
        assert result["content_type"] == "text/html"
        assert result["connection"] == "close"

    def test_analyze_response_with_encoding(self) -> None:
        """Test analysis of response with content encoding."""
        response = b"HTTP/1.1 200 OK\r\nServer: Apache\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\nBody"

        result = analyze_response_headers(response)
        assert result["server"] == "Apache"
        assert result["content_encoding"] == "gzip"
        assert result["transfer_encoding"] == "chunked"

    def test_analyze_malformed_response(self) -> None:
        """Test handling of malformed response."""
        response = b"Not a valid HTTP response"
        result = analyze_response_headers(response)
        assert result == {}

    def test_analyze_response_no_headers(self) -> None:
        """Test response without proper header termination."""
        response = b"HTTP/1.1 200 OK\r\nServer: test"
        result = analyze_response_headers(response)
        assert result == {}


class TestFirstLineAndCode:
    """Test HTTP response first line parsing."""

    def test_parse_valid_response(self) -> None:
        """Test parsing valid HTTP response."""
        response = b"HTTP/1.1 200 OK\r\nServer: test\r\n\r\n"
        line, code = first_line_and_code(response)
        assert line == "HTTP/1.1 200 OK"
        assert code == 200

    def test_parse_error_response(self) -> None:
        """Test parsing HTTP error response."""
        response = b"HTTP/1.1 404 Not Found\r\nServer: test\r\n\r\n"
        line, code = first_line_and_code(response)
        assert line == "HTTP/1.1 404 Not Found"
        assert code == 404

    def test_parse_malformed_response(self) -> None:
        """Test parsing malformed response."""
        response = b"Not a valid response"
        line, code = first_line_and_code(response)
        assert "Not a valid response" in line
        assert code is None

    def test_parse_long_response(self) -> None:
        """Test parsing response with long first line."""
        long_line = b"HTTP/1.1 200 OK" + b"A" * 300
        response = long_line + b"\r\nServer: test\r\n\r\n"
        line, code = first_line_and_code(response)
        assert len(line) <= 200  # Should be truncated
        assert code == 200


class TestSanitizeFirstLine:
    """Test first line sanitization."""

    def test_sanitize_valid_http_response(self) -> None:
        """Test sanitizing valid HTTP response."""
        result = sanitize_first_line("HTTP/1.1 200 OK")
        assert result == "HTTP/1.1 200 OK"

    def test_sanitize_html_response(self) -> None:
        """Test sanitizing HTML response."""
        result = sanitize_first_line("<!DOCTYPE html>")
        assert result == "Error"

    def test_sanitize_binary_response(self) -> None:
        """Test sanitizing binary response."""
        result = sanitize_first_line("Binary�data")
        assert result == "Binary/Unknown"

    def test_sanitize_xml_response(self) -> None:
        """Test sanitizing XML response."""
        result = sanitize_first_line("<xml>data</xml>")
        assert result == "Error"

    def test_sanitize_non_string_input(self) -> None:
        """Test sanitizing non-string input."""
        result = sanitize_first_line(123)
        assert result == "123"

    def test_sanitize_conversion_error(self) -> None:
        """Test handling conversion errors."""

        class UnconvertibleObject:
            def __str__(self) -> str:
                raise Exception("Cannot convert")

        result = sanitize_first_line(UnconvertibleObject())
        assert result == "Error"


class TestClassifyVersionToken:
    """Test HTTP version token classification."""

    def test_classify_valid_version(self) -> None:
        """Test classification of valid HTTP version."""
        result = classify_version_token("HTTP/1.1")
        assert result == []

    def test_classify_empty_version(self) -> None:
        """Test classification of empty version."""
        result = classify_version_token("")
        assert "empty_version" in result

    def test_classify_leading_space(self) -> None:
        """Test classification of version with leading space."""
        result = classify_version_token(" HTTP/1.1")
        assert "leading_space" in result

    def test_classify_trailing_space(self) -> None:
        """Test classification of version with trailing space."""
        result = classify_version_token("HTTP/1.1 ")
        assert "trailing_space" in result

    def test_classify_malformed_version(self) -> None:
        """Test classification of malformed version with control characters."""
        result = classify_version_token("HTTP/1.1\t")
        assert "malformed" in result

    def test_classify_mixed_case(self) -> None:
        """Test classification of mixed case version."""
        result = classify_version_token("Http/1.1")
        assert "mixed_case" in result

    def test_classify_invalid_token(self) -> None:
        """Test classification of invalid version token."""
        result = classify_version_token("HTTP/99.9")
        assert "invalid_token" in result


class TestIsLikelyHttp09Response:
    """Test HTTP/0.9 response detection."""

    def test_detect_html_response(self) -> None:
        """Test detection of HTML response (likely HTTP/0.9)."""
        response = b"<!DOCTYPE html><html><head><title>Test</title></head></html>"
        assert is_likely_http09_response(response) is True

    def test_detect_plain_text_response(self) -> None:
        """Test detection of plain text response."""
        response = b"This is plain text content without HTTP headers"
        assert is_likely_http09_response(response) is True

    def test_reject_http11_response(self) -> None:
        """Test rejection of HTTP/1.1 response."""
        response = b"HTTP/1.1 200 OK\r\nServer: test\r\n\r\nContent"
        assert is_likely_http09_response(response) is False

    def test_reject_response_with_headers(self) -> None:
        """Test rejection of response with HTTP headers."""
        response = b"Content-Type: text/html\r\n\r\n<html>content</html>"
        assert is_likely_http09_response(response) is False

    def test_handle_empty_response(self) -> None:
        """Test handling of empty response."""
        assert is_likely_http09_response(b"") is False
        # Note: The function expects bytes, so we test with empty bytes instead of None


class TestValidateVulnerabilityResponse:
    """Test vulnerability response validation."""

    def test_validate_successful_desync(self) -> None:
        """Test validation of successful desync injection."""
        response = b"HTTP/1.1 200 OK\r\nServer: test\r\n\r\n" + b"A" * 200
        is_vuln, reason = validate_vulnerability_response(response, "desync_injection")
        assert is_vuln is True
        assert "successful" in reason.lower()

    def test_validate_failed_desync(self) -> None:
        """Test validation of failed desync injection."""
        response = b"HTTP/1.1 400 Bad Request\r\n\r\nBad Request"
        is_vuln, reason = validate_vulnerability_response(response, "desync_injection")
        assert is_vuln is False
        assert "false positive" in reason.lower()

    def test_validate_pipeline_vulnerability(self) -> None:
        """Test validation of pipeline vulnerability."""
        response = b"HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 200 OK\r\n\r\n"
        is_vuln, reason = validate_vulnerability_response(response, "pipeline_possible")
        assert is_vuln is True
        assert "multiple" in reason.lower()

    def test_validate_empty_response(self) -> None:
        """Test validation of empty response."""
        is_vuln, reason = validate_vulnerability_response(b"", "desync_injection")
        assert is_vuln is False
        assert "empty" in reason.lower()


class TestRiskBadge:
    """Test risk badge generation."""

    def test_risk_badge_for_risky_item(self) -> None:
        """Test risk badge for potentially risky version."""
        item = {"accepted": True, "flags": ["empty_version", "invalid_token"]}
        badge = risk_badge(item)
        assert "⚠️" in badge

    def test_risk_badge_for_safe_item(self) -> None:
        """Test risk badge for safe version."""
        item = {"accepted": True, "flags": []}
        badge = risk_badge(item)
        assert badge == ""

    def test_risk_badge_for_rejected_item(self) -> None:
        """Test risk badge for rejected version."""
        item = {"accepted": False, "flags": ["invalid_token"]}
        badge = risk_badge(item)
        assert badge == ""


class TestIntegrationMockServer:
    """Integration tests using mock server."""

    @pytest.fixture
    def mock_http_server(self) -> Generator[str, None, None]:
        """Create a simple mock HTTP server for testing."""
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class MockHTTPHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path == "/http09":
                    # Simulate HTTP/0.9 response (no status line)
                    self.wfile.write(b"<html><body>HTTP/0.9 response</body></html>")
                else:
                    # Normal HTTP/1.1 response
                    self.send_response(200)
                    self.send_header("Server", "MockServer/1.0")
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<html><body>Normal response</body></html>")

            def log_message(self, format: str, *args: str) -> None:
                # Suppress log messages
                pass

        server = HTTPServer(("127.0.0.1", 0), MockHTTPHandler)
        port = server.server_address[1]

        def run_server() -> None:
            server.serve_forever()

        thread = threading.Thread(target=run_server, daemon=True)
        thread.start()

        yield f"http://127.0.0.1:{port}"
        server.shutdown()

    def test_integration_parse_and_analyze(self, mock_http_server: str) -> None:
        """Test integration of parsing and analysis functions."""
        url = f"{mock_http_server}/test"

        # Test URL parsing
        scheme, host, port, path = parse_target(url)
        assert scheme == "http"
        assert host == "127.0.0.1"
        assert path == "/test"

        # This would require actual network requests in a real integration test
        # For now, we just verify the parsing works
        assert port > 0


class TestErrorHandling:
    """Test error handling in various functions."""

    @patch("modules.header_checks.http_version.socket.create_connection")
    def test_make_tls_socket_connection_error(self, mock_socket: Mock) -> None:
        """Test TLS socket creation with connection error."""
        mock_socket.side_effect = ConnectionError("Connection failed")

        with pytest.raises(ConnectionError):
            make_tls_socket("example.com", 443)

    @patch("modules.header_checks.http_version.requests.get")
    def test_check_http_version_network_error(
        self, mock_requests: Mock, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Test check_http_version with network error."""
        mock_requests.side_effect = ConnectionError("Network error")

        # Should not raise exception, but print error
        check_http_version("http://example.com")

        captured = capsys.readouterr()
        assert "error" in captured.out.lower()


class TestPerformanceAndLimits:
    """Test performance characteristics and limits."""

    def test_large_response_handling(self) -> None:
        """Test handling of large HTTP responses."""
        # Create a large response (10MB)
        large_response = b"HTTP/1.1 200 OK\r\nServer: test\r\n\r\n" + b"A" * (
            10 * 1024 * 1024
        )

        # Should handle without memory issues
        line, code = first_line_and_code(large_response)
        assert code == 200

        # Should still parse headers correctly
        info = analyze_response_headers(large_response)
        assert info["server"] == "test"

    def test_version_classification_performance(self) -> None:
        """Test performance of version classification."""
        import time

        versions = ["HTTP/1.1", "HTTP/2", "HTTP/0.9", "INVALID"] * 100

        start_time = time.time()
        for version in versions:
            classify_version_token(version)
        end_time = time.time()

        # Should complete quickly (less than 1 second for 400 classifications)
        assert end_time - start_time < 1.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
