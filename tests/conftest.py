#!/usr/bin/env python3
"""
Pytest configuration and fixtures for HExHTTP tests.
"""

import os
import subprocess
import sys
import time
from collections.abc import Callable, Generator
from typing import Any

import pytest
import requests

from tests.mock_server import MockServer, create_mock_server


def is_ci_environment() -> bool:
    """Check if tests are running in a CI environment."""
    ci_indicators = [
        "CI",
        "CONTINUOUS_INTEGRATION",
        "GITHUB_ACTIONS",
        "TRAVIS",
        "CIRCLECI",
        "JENKINS_URL",
        "GITLAB_CI",
    ]
    return any(os.getenv(var) for var in ci_indicators)


@pytest.fixture(scope="session")
def mock_server() -> Generator[MockServer, None, None]:
    """
    Session-scoped fixture that provides a running mock server.

    The server is started once at the beginning of the test session
    and stopped at the end.
    """
    server = create_mock_server(host="127.0.0.1", port=8888)

    try:
        server.start()
        yield server
    finally:
        server.stop()


@pytest.fixture
def mock_server_url(mock_server: MockServer) -> str:
    """Fixture that provides the base URL of the mock server."""
    return str(mock_server.base_url)


@pytest.fixture
def hexhttp_command() -> Callable[..., dict[str, Any]]:
    """
    Fixture that provides a function to run hexhttp commands.

    Returns a function that can be called with arguments to run hexhttp
    and capture its output.
    """

    def run_hexhttp(
        *args: str,
        timeout: int = 30,
        input_data: str | None = None,
        quick_scan: bool = False,
    ) -> dict[str, Any]:
        """
        Run hexhttp command with given arguments.

        Args:
            *args: Command line arguments for hexhttp
            timeout: Maximum time to wait for command completion
            input_data: Optional input data to send to stdin
            quick_scan: If True, adds --quick flag for faster testing

        Returns:
            dict: Contains 'returncode', 'stdout', 'stderr'
        """
        # Convert args to list and add quick scan flag if requested
        cmd_args = list(args)
        if quick_scan:
            cmd_args.extend(["--quick"])

        cmd = [sys.executable, "-m", "hexhttp"] + cmd_args

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, input=input_data
            )
            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "success": result.returncode == 0,
            }
        except subprocess.TimeoutExpired:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": "Command timed out",
                "success": False,
            }
        except Exception as e:
            return {"returncode": -1, "stdout": "", "stderr": str(e), "success": False}

    return run_hexhttp


@pytest.fixture
def ci_timeout_config() -> dict[str, int]:
    """Fixture that provides CI-aware timeout configurations."""
    if is_ci_environment():
        return {
            "short": 45,  # For single URL tests
            "medium": 60,  # For multi-URL tests
            "long": 90,  # For integration tests
        }
    else:
        return {
            "short": 30,  # For single URL tests
            "medium": 45,  # For multi-URL tests
            "long": 60,  # For integration tests
        }


@pytest.fixture
def test_urls(mock_server_url: str) -> dict[str, str]:
    """Fixture that provides test URLs for different scenarios."""
    return {
        "apache": f"{mock_server_url}/apache/",
        "nginx": f"{mock_server_url}/nginx/",
        "cloudflare": f"{mock_server_url}/cloudflare/",
        "hho_vulnerable": f"{mock_server_url}/vulnerable/hho",
        "safe": f"{mock_server_url}/safe/",
        "cacheable_css": f"{mock_server_url}/cache/static.css",
        "cacheable_js": f"{mock_server_url}/cache/script.js",
        "uncommon_headers": f"{mock_server_url}/headers/uncommon",
        "server_error": f"{mock_server_url}/errors/500",
        "not_found": f"{mock_server_url}/errors/404",
        "health": f"{mock_server_url}/health",
    }


@pytest.fixture
def temp_url_file(tmp_path: Any, test_urls: dict[str, str]) -> str:
    """
    Fixture that creates a temporary file with test URLs.

    This is useful for testing file input functionality.
    """
    url_file = tmp_path / "test_urls.txt"
    urls = [test_urls["apache"], test_urls["nginx"], test_urls["safe"]]
    url_file.write_text("\n".join(urls))
    return str(url_file)


@pytest.fixture
def wait_for_server(mock_server_url: str) -> bool:
    """
    Fixture that ensures the mock server is ready before tests run.
    """
    max_attempts = 20
    for attempt in range(max_attempts):
        try:
            response = requests.get(f"{mock_server_url}/health", timeout=1)
            if response.status_code == 200:
                return True
        except Exception:
            if attempt < max_attempts - 1:
                time.sleep(0.1)
            else:
                raise RuntimeError("Mock server not responding")
    return False


@pytest.fixture(autouse=True)
def ensure_server_ready(wait_for_server: bool) -> None:
    """
    Auto-use fixture that ensures server is ready before each test.
    """
    pass


# Test markers for categorizing tests
def pytest_configure(config: Any) -> None:
    """Configure custom pytest markers."""
    config.addinivalue_line(
        "markers", "priority1: Priority 1 tests (critical functionality)"
    )
    config.addinivalue_line(
        "markers", "priority2: Priority 2 tests (important features)"
    )
    config.addinivalue_line(
        "markers", "priority3: Priority 3 tests (advanced features)"
    )
    config.addinivalue_line("markers", "slow: Tests that take longer to run")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "unit: Unit tests")


# Helper functions for tests
def assert_technology_detected(output: str, technology: str) -> bool:
    """
    Helper function to assert that a specific technology was detected.

    Args:
        output: The stdout from hexhttp command
        technology: The technology name to check for (e.g., 'apache', 'nginx')
    """
    output_lower = output.lower()
    tech_lower = technology.lower()

    # Check for various ways the technology might be mentioned
    indicators = [
        tech_lower,
        f"detected: {tech_lower}",
        f"technology: {tech_lower}",
        f"server: {tech_lower}",
    ]

    for indicator in indicators:
        if indicator in output_lower:
            return True

    return False


def assert_vulnerability_detected(output: str, vulnerability_type: str) -> bool:
    """
    Helper function to assert that a vulnerability was detected.

    Args:
        output: The stdout from hexhttp command
        vulnerability_type: The vulnerability type to check for
    """
    output_lower = output.lower()
    vuln_lower = vulnerability_type.lower()

    # Check for vulnerability indicators
    indicators = [
        vuln_lower,
        "vulnerable",
        "vulnerability",
        "potential issue",
        "security issue",
    ]

    for indicator in indicators:
        if indicator in output_lower:
            return True

    return False


def assert_no_false_positives(output: str) -> bool:
    """
    Helper function to assert that no false positive alerts were generated.

    Args:
        output: The stdout from hexhttp command
    """
    output_lower = output.lower()

    # These terms should not appear for safe endpoints
    false_positive_indicators = [
        "vulnerable",
        "vulnerability",
        "security issue",
        "potential attack",
        "cache poisoning detected",
    ]

    for indicator in false_positive_indicators:
        if indicator in output_lower:
            return False

    return True
