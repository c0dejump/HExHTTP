#!/usr/bin/env python3
"""
Mock HTTP server for testing HExHTTP functionality.

This server simulates various web technologies and vulnerabilities
to provide controlled testing scenarios for regression tests.
"""

import threading
import time

from flask import Flask, Response, jsonify, request


class MockServer:
    """Mock HTTP server for testing HExHTTP."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8888) -> None:
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        self.server_thread: threading.Thread | None = None
        self._setup_routes()

    def _setup_routes(self) -> None:
        """Set up all mock endpoints."""

        # Apache simulation
        @self.app.route("/apache/")
        @self.app.route("/apache/<path:path>")
        def apache_endpoint(path: str = "") -> Response:
            """Simulate Apache server responses."""
            headers = {
                "Server": "Apache/2.4.41 (Ubuntu)",
                "X-Powered-By": "PHP/7.4.3",
                "Cache-Control": "no-cache, must-revalidate",
                "Pragma": "no-cache",
                "Content-Type": "text/html; charset=UTF-8",
            }
            content = """
            <!DOCTYPE html>
            <html>
            <head><title>Apache Test Server</title></head>
            <body>
                <h1>Apache Server Simulation</h1>
                <p>This is a mock Apache server for testing.</p>
                <p>Server: Apache/2.4.41</p>
            </body>
            </html>
            """
            return Response(content, headers=headers)

        # Nginx simulation
        @self.app.route("/nginx/")
        @self.app.route("/nginx/<path:path>")
        def nginx_endpoint(path: str = "") -> Response:
            """Simulate Nginx server responses."""
            headers = {
                "Server": "nginx/1.18.0",
                "X-Frame-Options": "SAMEORIGIN",
                "X-Content-Type-Options": "nosniff",
                "Content-Type": "text/html; charset=UTF-8",
            }
            content = """
            <!DOCTYPE html>
            <html>
            <head><title>Nginx Test Server</title></head>
            <body>
                <h1>Nginx Server Simulation</h1>
                <p>This is a mock Nginx server for testing.</p>
                <p>Server: nginx/1.18.0</p>
            </body>
            </html>
            """
            return Response(content, headers=headers)

        # Cloudflare simulation
        @self.app.route("/cloudflare/")
        @self.app.route("/cloudflare/<path:path>")
        def cloudflare_endpoint(path: str = "") -> Response:
            """Simulate Cloudflare-protected responses."""
            headers = {
                "Server": "cloudflare",
                "CF-RAY": "7d4b8c9e5f2a1b3c-LAX",
                "CF-Cache-Status": "HIT",
                "Cache-Control": "public, max-age=3600",
                "Content-Type": "text/html; charset=UTF-8",
            }
            content = """
            <!DOCTYPE html>
            <html>
            <head><title>Cloudflare Protected Site</title></head>
            <body>
                <h1>Cloudflare Protected Site</h1>
                <p>This site is protected by Cloudflare.</p>
                <p>CF-RAY: 7d4b8c9e5f2a1b3c-LAX</p>
            </body>
            </html>
            """
            return Response(content, headers=headers)

        # HHO (HTTP Header Oversize) vulnerability simulation
        @self.app.route("/vulnerable/hho")
        def hho_vulnerable() -> Response:
            """Simulate HHO cache poisoning vulnerability."""
            # Check for oversized headers that might indicate HHO attack
            oversized_header = None
            for header_name, header_value in request.headers:
                if len(header_value) > 8000:  # Typical threshold
                    oversized_header = header_name
                    break

            headers = {
                "Server": "nginx/1.18.0",
                "Cache-Control": "public, max-age=300",
                "Content-Type": "text/html; charset=UTF-8",
            }

            if oversized_header:
                # Vulnerable behavior: reflect the oversized header
                headers["X-Reflected-Header"] = (
                    request.headers.get(oversized_header, "")[:100] + "..."
                )
                content = f"""
                <!DOCTYPE html>
                <html>
                <head><title>HHO Vulnerable Endpoint</title></head>
                <body>
                    <h1>HHO Vulnerable Response</h1>
                    <p>Oversized header detected: {oversized_header}</p>
                    <p>This endpoint is vulnerable to HTTP Header Oversize attacks.</p>
                </body>
                </html>
                """
            else:
                content = """
                <!DOCTYPE html>
                <html>
                <head><title>HHO Test Endpoint</title></head>
                <body>
                    <h1>HHO Test Endpoint</h1>
                    <p>Send an oversized header to test HHO vulnerability.</p>
                </body>
                </html>
                """

            return Response(content, headers=headers)

        # Safe endpoint (should not trigger any alerts)
        @self.app.route("/safe/")
        @self.app.route("/safe/<path:path>")
        def safe_endpoint(path: str = "") -> Response:
            """Safe endpoint that should not trigger any vulnerability alerts."""
            headers = {
                "Server": "TestServer/1.0",
                "Content-Type": "text/html; charset=UTF-8",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
            }
            content = """
            <!DOCTYPE html>
            <html>
            <head><title>Safe Test Endpoint</title></head>
            <body>
                <h1>Safe Test Endpoint</h1>
                <p>This endpoint should not trigger any vulnerability alerts.</p>
                <p>It represents a properly configured, secure server.</p>
            </body>
            </html>
            """
            return Response(content, headers=headers)

        # Cacheable resources for cache file detection
        @self.app.route("/cache/static.css")
        def cacheable_css() -> Response:
            """Simulate cacheable CSS resource."""
            headers = {
                "Content-Type": "text/css",
                "Cache-Control": "public, max-age=86400",
                "ETag": '"abc123"',
                "Last-Modified": "Wed, 21 Oct 2015 07:28:00 GMT",
            }
            content = "body { background-color: #f0f0f0; }"
            return Response(content, headers=headers)

        @self.app.route("/cache/script.js")
        def cacheable_js() -> Response:
            """Simulate cacheable JavaScript resource."""
            headers = {
                "Content-Type": "application/javascript",
                "Cache-Control": "public, max-age=86400",
                "ETag": '"def456"',
            }
            content = "console.log('Test script loaded');"
            return Response(content, headers=headers)

        # Uncommon headers endpoint
        @self.app.route("/headers/uncommon")
        def uncommon_headers() -> Response:
            """Endpoint with uncommon/interesting headers."""
            headers = {
                "Server": "CustomServer/1.0",
                "X-Debug-Mode": "enabled",
                "X-Internal-IP": "192.168.1.100",
                "X-Admin-Panel": "/secret-admin",
                "X-Version": "2.1.3-beta",
                "X-Cache-Backend": "redis-cluster",
                "Content-Type": "text/html; charset=UTF-8",
            }
            content = """
            <!DOCTYPE html>
            <html>
            <head><title>Uncommon Headers Test</title></head>
            <body>
                <h1>Uncommon Headers Test</h1>
                <p>This endpoint returns several uncommon headers for testing.</p>
            </body>
            </html>
            """
            return Response(content, headers=headers)

        # Error simulation endpoints
        @self.app.route("/errors/500")
        def server_error() -> Response:
            """Simulate server error."""
            return Response("Internal Server Error", status=500)

        @self.app.route("/errors/404")
        def not_found() -> Response:
            """Simulate not found error."""
            return Response("Not Found", status=404)

        @self.app.route("/errors/403")
        def forbidden() -> Response:
            """Simulate forbidden error."""
            return Response("Forbidden", status=403)

        # Health check endpoint
        @self.app.route("/health")
        def health_check() -> Response:
            """Health check endpoint for testing server availability."""
            response: Response = jsonify(
                {
                    "status": "healthy",
                    "server": "mock-server",
                    "endpoints": [
                        "/apache/",
                        "/nginx/",
                        "/cloudflare/",
                        "/vulnerable/hho",
                        "/safe/",
                        "/cache/static.css",
                        "/cache/script.js",
                        "/headers/uncommon",
                        "/errors/500",
                    ],
                }
            )
            return response

    def start(self) -> None:
        """Start the mock server in a separate thread."""
        if self.server_thread and self.server_thread.is_alive():
            return

        self.server_thread = threading.Thread(target=self._run_server, daemon=True)
        self.server_thread.start()

        # Wait for server to start
        max_attempts = 10
        for _ in range(max_attempts):
            try:
                import requests

                response = requests.get(
                    f"http://{self.host}:{self.port}/health", timeout=1
                )
                if response.status_code == 200:
                    break
            except Exception:
                pass
            time.sleep(0.1)
        else:
            raise RuntimeError("Failed to start mock server")

    def stop(self) -> None:
        """Stop the mock server."""
        if self.server_thread and self.server_thread.is_alive():
            # Flask doesn't have a clean shutdown method in development mode
            # In a real scenario, you'd use a production WSGI server
            pass

    def _run_server(self) -> None:
        """Run the Flask server."""
        self.app.run(
            host=self.host,
            port=self.port,
            debug=False,
            use_reloader=False,
            threaded=True,
        )

    @property
    def base_url(self) -> str:
        """Get the base URL of the mock server."""
        return f"http://{self.host}:{self.port}"


# Convenience function for tests
def create_mock_server(host: str = "127.0.0.1", port: int = 8888) -> MockServer:
    """Create and return a mock server instance."""
    return MockServer(host, port)


if __name__ == "__main__":
    # Run the mock server standalone for manual testing
    server = create_mock_server()
    print(f"Starting mock server at {server.base_url}")
    print("Available endpoints:")
    print("  /apache/ - Apache server simulation")
    print("  /nginx/ - Nginx server simulation")
    print("  /cloudflare/ - Cloudflare protected site")
    print("  /vulnerable/hho - HHO vulnerability test")
    print("  /safe/ - Safe endpoint")
    print("  /cache/static.css - Cacheable CSS")
    print("  /headers/uncommon - Uncommon headers")
    print("  /errors/500 - Server error")
    print("  /health - Health check")
    print("\nPress Ctrl+C to stop")

    try:
        server.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping mock server...")
        server.stop()
