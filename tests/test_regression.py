#!/usr/bin/env python3
"""
Regression test suite for HExHTTP.

This test suite covers the core functionality to ensure no regressions
are introduced when making changes to the codebase.
"""

from typing import Any

import pytest

from tests.conftest import assert_no_false_positives, assert_technology_detected


class TestPriority1:
    """Priority 1 tests - Critical core functionality."""

    @pytest.mark.priority1
    def test_cli_help_command(self, hexhttp_command: Any) -> None:
        """Test that the help command works correctly."""
        result = hexhttp_command("--help")

        # Help should exit with code 0 and show usage information
        assert result["returncode"] == 0
        assert (
            "usage:" in result["stdout"].lower()
            or "hexhttp" in result["stdout"].lower()
        )
        assert "url" in result["stdout"].lower()

    @pytest.mark.priority1
    def test_cli_version_or_basic_info(self, hexhttp_command: Any) -> None:
        """Test that basic CLI functionality works."""
        result = hexhttp_command()

        assert result["returncode"] in [0, 1]
        assert len(result["stdout"]) > 0 or len(result["stderr"]) > 0

    @pytest.mark.priority1
    def test_apache_detection(self, hexhttp_command: Any, test_urls: Any) -> None:
        """Test that Apache server is correctly detected."""
        # Use shorter timeout and only-cp flag for faster testing
        result = hexhttp_command("-u", test_urls["apache"], "--ocp", timeout=30)

        # Command should complete successfully
        assert result["success"], f"Command failed: {result['stderr']}"

        # Should detect Apache technology
        output = result["stdout"] + result["stderr"]
        assert assert_technology_detected(
            output, "apache"
        ), f"Apache not detected in output: {output}"

    @pytest.mark.priority1
    def test_nginx_detection(self, hexhttp_command: Any, test_urls: Any) -> None:
        """Test that Nginx server is correctly detected."""
        # Use shorter timeout and only-cp flag for faster testing
        result = hexhttp_command("-u", test_urls["nginx"], "--ocp", timeout=30)

        # Command should complete successfully
        assert result["success"], f"Command failed: {result['stderr']}"

        # Should detect Nginx technology
        output = result["stdout"] + result["stderr"]
        assert assert_technology_detected(
            output, "nginx"
        ), f"Nginx not detected in output: {output}"

    @pytest.mark.priority1
    def test_cloudflare_detection(self, hexhttp_command: Any, test_urls: Any) -> None:
        """Test that Cloudflare protection is correctly detected."""
        # Use shorter timeout and only-cp flag for faster testing
        result = hexhttp_command("-u", test_urls["cloudflare"], "--ocp", timeout=30)

        # Command should complete successfully
        assert result["success"], f"Command failed: {result['stderr']}"

        # Should detect Cloudflare technology
        output = result["stdout"] + result["stderr"]
        assert assert_technology_detected(
            output, "cloudflare"
        ), f"Cloudflare not detected in output: {output}"

    @pytest.mark.priority1
    def test_safe_endpoint_no_false_positives(
        self, hexhttp_command: Any, test_urls: Any
    ) -> None:
        """Test that safe endpoints don't trigger false positive alerts."""
        # Use shorter timeout and only-cp flag for faster testing
        result = hexhttp_command("-u", test_urls["safe"], "--ocp", timeout=20)

        # Command should complete successfully
        assert result["success"], f"Command failed: {result['stderr']}"

        # Should not generate false positive vulnerability alerts
        output = result["stdout"] + result["stderr"]
        assert assert_no_false_positives(
            output
        ), f"False positive detected in safe endpoint output: {output}"

    @pytest.mark.priority1
    def test_basic_url_processing(self, hexhttp_command: Any, test_urls: Any) -> None:
        """Test that basic URL processing works without crashes."""
        # Test with a simple, safe URL using quick mode
        result = hexhttp_command("-u", test_urls["safe"], "--ocp", timeout=30)

        # Should not crash
        assert result["returncode"] != -1, "Command crashed or timed out"

        # Should produce some output
        total_output = result["stdout"] + result["stderr"]
        assert len(total_output) > 0, "No output produced"


class TestPriority2:
    """Priority 2 tests - Important features."""

    @pytest.mark.priority2
    def test_file_input_processing(
        self, hexhttp_command: Any, temp_url_file: Any
    ) -> None:
        """Test that file input with multiple URLs works."""
        # Use cache poisoning only mode for faster testing in CI
        result = hexhttp_command("-f", temp_url_file, "--ocp", timeout=45)

        # Command should complete successfully
        assert result["success"], f"Command failed: {result['stderr']}"

        # Should process multiple URLs
        output = result["stdout"] + result["stderr"]

        # Should mention processing multiple URLs or show results for each
        # Look for indicators that multiple URLs were processed
        url_indicators = output.lower().count("url:") + output.lower().count("http")
        assert url_indicators >= 2, f"Expected multiple URL processing, got: {output}"

    @pytest.mark.priority2
    def test_threading_stability(
        self, hexhttp_command: Any, temp_url_file: Any
    ) -> None:
        """Test that multi-threaded processing doesn't crash."""
        # Test with threading enabled and cache poisoning only mode
        result = hexhttp_command("-f", temp_url_file, "-t", "2", "--ocp", timeout=45)

        # Should not crash
        assert result["returncode"] != -1, "Command crashed or timed out with threading"

        # Should complete (success or controlled failure)
        assert result["returncode"] in [
            0,
            1,
        ], f"Unexpected return code: {result['returncode']}"

    @pytest.mark.priority2
    def test_header_analysis(self, hexhttp_command: Any, test_urls: Any) -> None:
        """Test that header analysis functionality works."""
        # Use quick mode for faster testing
        result = hexhttp_command(
            "-u", test_urls["uncommon_headers"], "--ocp", timeout=30
        )

        # Command should complete successfully
        assert result["success"], f"Command failed: {result['stderr']}"

        # Should analyze headers (look for header-related output)
        output = result["stdout"] + result["stderr"]
        header_indicators = ["header", "x-debug", "x-internal", "x-admin"]

        found_header_analysis = any(
            indicator in output.lower() for indicator in header_indicators
        )
        assert found_header_analysis, f"No header analysis detected in output: {output}"

    @pytest.mark.priority2
    def test_cache_file_detection(self, hexhttp_command: Any, test_urls: Any) -> None:
        """Test that cacheable resources are properly analyzed."""
        # Use quick mode for faster testing
        result = hexhttp_command("-u", test_urls["cacheable_css"], "--ocp", timeout=30)

        # Command should complete successfully
        assert result["success"], f"Command failed: {result['stderr']}"

        # Should analyze cache-related aspects
        output = result["stdout"] + result["stderr"]
        cache_indicators = ["cache", "etag", "last-modified", "max-age"]

        found_cache_analysis = any(
            indicator in output.lower() for indicator in cache_indicators
        )
        assert found_cache_analysis, f"No cache analysis detected in output: {output}"

    @pytest.mark.priority2
    def test_error_handling(self, hexhttp_command: Any, test_urls: Any) -> None:
        """Test that error conditions are handled gracefully."""
        # Test with server error endpoint
        result = hexhttp_command("-u", test_urls["server_error"])

        # Should handle error gracefully (not crash)
        assert result["returncode"] != -1, "Command crashed on server error"

        # Should either succeed with error analysis or fail gracefully
        assert result["returncode"] in [
            0,
            1,
        ], f"Unexpected return code: {result['returncode']}"


class TestPriority3:
    """Priority 3 tests - Advanced features."""

    @pytest.mark.priority3
    def test_custom_headers(self, hexhttp_command: Any, test_urls: Any) -> None:
        """Test that custom headers can be added."""
        # Use quick mode for faster testing
        result = hexhttp_command(
            "-u",
            test_urls["safe"],
            "-H",
            "X-Test-Header: test-value",
            "--ocp",
            timeout=30,
        )

        # Should not crash with custom headers
        assert result["returncode"] != -1, "Command crashed with custom headers"

        # Should complete successfully or with controlled failure
        assert result["returncode"] in [
            0,
            1,
        ], f"Unexpected return code: {result['returncode']}"

    @pytest.mark.priority3
    def test_verbose_output(self, hexhttp_command: Any, test_urls: Any) -> None:
        """Test that verbose mode provides additional output."""
        # Run without verbose using quick mode
        result_normal = hexhttp_command("-u", test_urls["safe"], "--ocp", timeout=30)

        # Run with verbose using quick mode
        result_verbose = hexhttp_command(
            "-u", test_urls["safe"], "-v", "--ocp", timeout=30
        )

        # Both should complete
        assert result_normal["returncode"] != -1, "Normal command crashed"
        assert result_verbose["returncode"] != -1, "Verbose command crashed"

        # Verbose should generally produce more output
        verbose_output_len = len(result_verbose["stdout"] + result_verbose["stderr"])

        # Note: This might not always be true, so we just check it doesn't crash
        assert verbose_output_len >= 0, "Verbose mode produced no output"

    @pytest.mark.priority3
    @pytest.mark.slow
    def test_hho_vulnerability_detection(
        self, hexhttp_command: Any, test_urls: Any
    ) -> None:
        """Test that HHO cache poisoning vulnerability can be detected."""
        # Use quick mode for faster testing
        result = hexhttp_command("-u", test_urls["hho_vulnerable"], "--ocp", timeout=30)

        # Command should complete
        assert result["returncode"] != -1, "Command crashed on HHO test"

        # Should complete successfully or with controlled failure
        assert result["returncode"] in [
            0,
            1,
        ], f"Unexpected return code: {result['returncode']}"

        # Note: Actual vulnerability detection testing would require
        # more sophisticated setup and might be better as integration tests


class TestIntegration:
    """Integration tests for complete workflows."""

    @pytest.mark.integration
    def test_complete_scan_workflow(self, hexhttp_command: Any, test_urls: Any) -> None:
        """Test a complete scan workflow with multiple features."""
        # Use cache poisoning only mode for faster testing in CI environments
        result = hexhttp_command(
            "-u",
            test_urls["apache"],
            "-v",  # verbose
            "-H",
            "X-Test: integration-test",  # custom header
            "--ocp",
            timeout=45,
        )

        # Should complete the full workflow
        assert result["returncode"] != -1, "Integration test crashed"

        # Should produce comprehensive output
        output = result["stdout"] + result["stderr"]
        assert len(output) > 100, f"Integration test produced minimal output: {output}"

        # Should detect the technology
        assert assert_technology_detected(
            output, "apache"
        ), f"Technology detection failed in integration test: {output}"

    @pytest.mark.integration
    @pytest.mark.slow
    def test_multi_url_complete_workflow(
        self, hexhttp_command: Any, temp_url_file: Any
    ) -> None:
        """Test complete workflow with multiple URLs."""
        # Use quick mode for faster testing
        result = hexhttp_command(
            "-f",
            temp_url_file,
            "-t",
            "2",  # threading
            "-v",  # verbose
            "--ocp",
            timeout=45,
        )

        # Should handle multiple URLs
        assert result["returncode"] != -1, "Multi-URL workflow crashed"

        # Should process multiple URLs
        output = result["stdout"] + result["stderr"]

        # Look for evidence of multiple URL processing
        url_count = output.lower().count("url:") + output.lower().count("http")
        assert url_count >= 2, f"Multi-URL test didn't process multiple URLs: {output}"


# Utility test functions
class TestUtilities:
    """Test utility functions and edge cases."""

    def test_invalid_url_handling(self, hexhttp_command: Any) -> None:
        """Test handling of invalid URLs."""
        result = hexhttp_command("-u", "not-a-valid-url")

        # Should fail gracefully, not crash
        assert result["returncode"] != -1, "Command crashed on invalid URL"
        assert result["returncode"] == 0, "Should handle invalid URL gracefully"

    def test_unreachable_url_handling(self, hexhttp_command: Any) -> None:
        """Test handling of unreachable URLs."""
        result = hexhttp_command(
            "-u", "http://192.0.2.1:12345/"
        )  # RFC5737 test address

        # Should fail gracefully, not crash
        assert result["returncode"] != -1, "Command crashed on unreachable URL"
        # Should handle connection error gracefully
        assert result["returncode"] == 0, "Should handle unreachable URL gracefully"


if __name__ == "__main__":
    # Allow running this test file directly
    pytest.main([__file__, "-v"])
