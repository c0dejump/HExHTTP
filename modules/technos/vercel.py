#!/usr/bin/env python3

from utils.utils import requests


def vercel_edge_functions_test(url: str, s: requests.Session) -> None:
    """Test Vercel Edge Functions"""
    edge_paths = [
        "/api/edge-function",
        "/_next/data",
        "/api/*"
    ]
    
    for path in edge_paths:
        test_url = f"{url}{path}"
        try:
            req = s.get(test_url, verify=False, timeout=10)
            
            # Check for Edge Function headers
            if "x-vercel-id" in req.headers or "x-vercel-cache" in req.headers:
                print(f"{Colors.CYAN}   └── Edge Function detected: {path}{Colors.RESET}")
                
                for h in ["x-vercel-cache", "x-vercel-id", "cache-control"]:
                    if h in req.headers:
                        print(f"       {h}: {req.headers[h]}")
        except Exception:
            pass


def vercel_rewrite_test(url: str, s: requests.Session) -> None:
    """Test Vercel rewrites and redirects"""
    test_paths = [
        "/api/hello",
        "/.well-known/vercel/info",
        "/_next/static",
        "/api/../admin"
    ]
    
    for path in test_paths:
        test_url = f"{url}{path}"
        try:
            req = s.get(test_url, verify=False, timeout=10, allow_redirects=False)
            if req.status_code in [301, 302, 307, 308]:
                print(f"{Colors.YELLOW}   └── Redirect: {path} -> {req.headers.get('location', 'unknown')}{Colors.RESET}")
        except Exception:
            pass


def vercel(url: str, s: requests.Session) -> None:
    """
    https://vercel.com/docs/edge-network/headers
    https://vercel.com/docs/edge-network/caching
    """
    vercel_header_list = [
        {"x-vercel-forwarded-for": "127.0.0.1"},
        {"x-vercel-deployment-url": "plop123.vercel.app"},
        {"x-vercel-ip-continent": "EU"},
        {"x-vercel-ip-country": "FR"},
        {"x-vercel-ip-city": "Paris"},
        {"x-vercel-signature": "plop123"},
        {"X-Vercel-Id": "A" * 55},
        {"x-vercel-ip-timezone": "Europe/Paris"},
        {"x-vercel-proxied-for": "127.0.0.1"},
        {"x-real-ip": "127.0.0.1"}
    ]
    
    for vhl in vercel_header_list:
        try:
            req = s.get(url, headers=vhl, verify=False, timeout=10)
            print(f"   └── {vhl} -> {req.status_code} [{len(req.content)} bytes]")
            
            # Check for reflection
            for key, value in vhl.items():
                if value in req.text:
                    print(f"{Colors.GREEN}       └── {key} reflected{Colors.RESET}")
        except Exception:
            pass
    vercel_edge_functions_test(url, s)
    vercel_rewrite_test(url, s)