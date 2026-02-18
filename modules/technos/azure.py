#!/usr/bin/env python3

from utils.style import Colors
from utils.utils import configure_logger, random, requests

logger = configure_logger(__name__)


def azure_rules_engine_test(url: str, s: requests.Session) -> None:
    """
    Test Azure Front Door Rules Engine header injection.
    AFD can be configured to add headers based on request conditions;
    some rules evaluate client-supplied headers without sanitization.
    """
    probe_value = "bycodejump"
    injection_headers = [
        {"X-FD-HealthProbe": "1"},
        {"X-Azure-FDID": probe_value},
        {"X-FD-ClientIP": "127.0.0.1"},
        {"X-Original-URL": f"/{probe_value}"},
        {"X-Forwarded-Host": f"{probe_value}.evil.com"},
        {"X-Azure-ClientIP": "127.0.0.1"},
    ]
    try:
        for h in injection_headers:
            uri = f"{url}?cb={random.randrange(9999)}"
            req = s.get(uri, headers=h, verify=False, timeout=10, allow_redirects=False)
            val = list(h.values())[0]
            if val in req.text:
                print(
                    f"{Colors.GREEN}   └── [REFLECTION] {h} reflected in body{Colors.RESET}"
                )
            print(f"   └── {h} -> {req.status_code} [{len(req.content)}b]")
    except Exception as e:
        logger.exception(e)


def azure_cache_key_test(url: str, s: requests.Session) -> None:
    """
    Test Azure CDN / AFD cache key manipulation.
    AFD supports Vary-based caching; some deployments include X-Azure-FDID
    or X-FD-* in the cache key – or don't, making them unkeyed vectors.
    """
    test_headers = [
        {"X-Azure-FDID": f"bycodejump-{random.randrange(9999)}"},
        {"X-FD-Features": "ESI"},
        {"X-MSEdge-Ref": "bycodejump"},
    ]
    try:
        baseline = s.get(f"{url}?cb={random.randrange(9999)}", verify=False, timeout=10)
        baseline_len = len(baseline.content)
        for h in test_headers:
            uri = f"{url}?cb={random.randrange(9999)}"
            req = s.get(uri, headers=h, verify=False, timeout=10, allow_redirects=False)
            if len(req.content) != baseline_len or req.status_code != baseline.status_code:
                print(
                    f"{Colors.YELLOW}   └── [BEHAVIOR] {h} -> {baseline.status_code}/{baseline_len}b "
                    f"> {req.status_code}/{len(req.content)}b{Colors.RESET}"
                )
    except Exception as e:
        logger.exception(e)


def azure_health_probe_bypass(url: str, s: requests.Session) -> None:
    """
    AFD health probes use X-FD-HealthProbe: 1 – some origins skip auth checks
    or return different content when this header is present.
    """
    uri = f"{url}?cb={random.randrange(9999)}"
    try:
        normal = s.get(uri, verify=False, timeout=10)
        probe = s.get(uri, headers={"X-FD-HealthProbe": "1"}, verify=False, timeout=10)
        if probe.status_code != normal.status_code or len(probe.content) != len(normal.content):
            print(
                f"{Colors.YELLOW}   └── [HealthProbe bypass] normal={normal.status_code}/{len(normal.content)}b "
                f"probe={probe.status_code}/{len(probe.content)}b{Colors.RESET}"
            )
    except Exception as e:
        logger.exception(e)


def azure_fd_debug_headers(url: str, s: requests.Session) -> None:
    """Test Azure Front Door debug / diagnostic headers"""
    debug_headers = [
        {"X-FD-Debug": "1"},
        {"X-FD-Perf": "1"},
        {"X-Azure-DebugInfo": "1"},
        {"Pragma": "afd-debug"},
    ]
    try:
        for h in debug_headers:
            req = s.get(url, headers=h, verify=False, timeout=10)
            for rh in req.headers:
                if any(k in rh.lower() for k in ["x-fd-", "x-azure-", "x-msedge", "x-cache"]):
                    print(f"{Colors.CYAN}   └── AFD header: {rh}: {req.headers[rh]}{Colors.RESET}")
    except Exception as e:
        logger.exception(e)


def azure(url: str, s: requests.Session) -> None:
    """
    Azure Front Door / Azure CDN analysis.
    Signatures: X-Azure-Ref, X-FD-*, X-MSEdge-Ref, X-Cache (TCP_HIT), Via: 1.1 Azure
    https://docs.microsoft.com/en-us/azure/frontdoor/
    """
    azure_fd_debug_headers(url, s)
    azure_rules_engine_test(url, s)
    azure_cache_key_test(url, s)
    azure_health_probe_bypass(url, s)