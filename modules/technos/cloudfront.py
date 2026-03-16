#!/usr/bin/env python3

from utils.style import Colors
from utils.utils import requests

def lambda_edge_test(url: str, s: requests.Session) -> None:
    """Test Lambda@Edge headers"""
    lambda_headers = [
        {"X-Amz-Cf-Id": "plop123"},
        {"X-Edge-Location": "plop123"},
        {"CloudFront-Viewer-Country": "XX"}
    ]
    
    for header in lambda_headers:
        try:
            req = s.get(url, headers=header, verify=False, timeout=10)
            print(f"   └── {header} -> {req.status_code}")
            
            if "plop123" in req.text:
                print(f"{Colors.GREEN}   └── Lambda@Edge reflection possible{Colors.RESET}")
        except Exception:
            pass


def cf_cache_key_test(url: str, s: requests.Session) -> None:
    """Test CloudFront cache key manipulation"""
    import random
    
    # Test query string ordering
    params_orders = [
        {"a": "1", "b": "2"},
        {"b": "2", "a": "1"}
    ]
    
    results = []
    for params in params_orders:
        try:
            req = s.get(url, params=params, verify=False, timeout=10)
            cache_status = req.headers.get("X-Cache", "")
            results.append(cache_status)
        except Exception:
            pass
    
    if len(set(results)) > 1:
        print(f"{Colors.YELLOW}   └── Cache key ordering matters{Colors.RESET}")



def cloudfront(url: str, s: requests.Session) -> None:
    """
    Amazon CloudFront analysis.

    CloudFront-specific headers:
    - X-Amz-Cf-Pop: Indicates the CloudFront edge location (Point of Presence)
    - X-Amz-Cf-Id: CloudFront request ID for tracking
    - X-Cache: Cache status (Hit from cloudfront, Miss from cloudfront, etc.)
    - Via: Often contains CloudFront information

    Common CloudFront cache behaviors and testing opportunities.
    """

    # Basic CloudFront cache testing
    headers = {"X-Forwarded-Proto": "nohttps"}
    try:
        url = f"{url}?cb=123132"
        cf_test = s.get(url, headers=headers, verify=False, timeout=6)

        if cf_test.status_code in [301, 302, 303]:
            print(
                f"{Colors.YELLOW} │   └── Potential CloudFront redirect behavior detected{Colors.RESET}"
            )
    except requests.exceptions.TooManyRedirects:
        print(
                f"{Colors.YELLOW} │   └── TooManyRedirects / Potential CloudFront redirect behavior detected{Colors.RESET}"
            )
    lambda_edge_test(url, s)
    cf_cache_key_test(url, s)
