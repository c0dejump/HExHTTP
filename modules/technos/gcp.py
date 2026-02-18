#!/usr/bin/env python3

from utils.style import Colors
from utils.utils import configure_logger, random, requests

logger = configure_logger(__name__)


def gcp_cdn_debug_headers(url: str, s: requests.Session) -> None:
    """
    Test Google Cloud CDN cache-control directives and debug signals.
    GCP CDN respects CDN-Cache-Control and Cache-Control directives from origin.
    """
    debug_headers = [
        {"X-Google-Cache-Control": "no-cache"},
        {"X-GFE-Debug": "1"},
        {"X-Google-Debug": "1"},
    ]
    try:
        for h in debug_headers:
            req = s.get(url, headers=h, verify=False, timeout=10)
            for rh in req.headers:
                if any(k in rh.lower() for k in ["x-google", "x-gfe", "x-goog", "x-cache", "via"]):
                    print(f"{Colors.CYAN}   └── GCP header: {rh}: {req.headers[rh]}{Colors.RESET}")
    except Exception as e:
        logger.exception(e)


def gcp_cdn_cache_key_test(url: str, s: requests.Session) -> None:
    """
    Google Cloud CDN uses the full URL (scheme + host + path + query) as cache key by default.
    Custom cache keys can exclude query params, headers or cookies.
    Test if unkeyed headers can poison the cache.
    """
    probe_value = "bycodejump"
    unkeyed_candidates = [
        {"X-Forwarded-For": f"127.0.0.1, {probe_value}"},
        {"X-Forwarded-Host": f"{probe_value}.evil.com"},
        {"X-Real-IP": "127.0.0.1"},
        {"Via": f"1.1 {probe_value}"},
        {"X-Google-Real-IP": "127.0.0.1"},
    ]
    try:
        baseline = s.get(f"{url}?cb={random.randrange(9999)}", verify=False, timeout=10)
        for h in unkeyed_candidates:
            uri = f"{url}?cb={random.randrange(9999)}"
            req = s.get(uri, headers=h, verify=False, timeout=10, allow_redirects=False)
            val = list(h.values())[0]
            if val in req.text:
                print(
                    f"{Colors.GREEN}   └── [REFLECTION] {h} reflected in body – potential CP vector{Colors.RESET}"
                )
            elif req.status_code != baseline.status_code:
                print(
                    f"{Colors.YELLOW}   └── [BEHAVIOR] {h} -> {baseline.status_code} > {req.status_code}{Colors.RESET}"
                )
    except Exception as e:
        logger.exception(e)


def gcp_loadbalancer_headers(url: str, s: requests.Session) -> None:
    """
    Google Cloud Load Balancer specific header injection tests.
    GCLB adds X-Forwarded-For, X-Forwarded-Proto and can be abused
    when these are trusted blindly by the backend.
    https://cloud.google.com/load-balancing/docs/https#target-proxies
    """
    probe = "bycodejump"
    headers = [
        {"X-Client-Geo-Location": f"{probe},FR"},
        {"X-Forwarded-Proto": "nohttps"},
        {"X-Cloud-Trace-Context": probe},
        {"X-Goog-Authenticated-User-Email": f"{probe}@test.iam.gserviceaccount.com"},
    ]
    try:
        for h in headers:
            uri = f"{url}?cb={random.randrange(9999)}"
            req = s.get(uri, headers=h, verify=False, timeout=10, allow_redirects=False)
            print(f"   └── {h} -> {req.status_code} [{len(req.content)}b]")
            val = list(h.values())[0]
            if probe in req.text:
                print(f"{Colors.GREEN}       └── Reflected{Colors.RESET}")
    except Exception as e:
        logger.exception(e)


def gcp(url: str, s: requests.Session) -> None:
    """
    Google Cloud CDN / Cloud Load Balancer analysis.
    Signatures: Via: 1.1 google, X-Google-Cache, Age header from GFE,
    Server: Google Frontend / ESF, x-goog-* response headers.
    https://cloud.google.com/cdn/docs
    """
    gcp_cdn_debug_headers(url, s)
    gcp_cdn_cache_key_test(url, s)
    gcp_loadbalancer_headers(url, s)