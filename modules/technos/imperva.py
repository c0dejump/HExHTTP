#!/usr/bin/env python3
from utils.utils import configure_logger, requests
from collections import defaultdict
logger = configure_logger(__name__)

def imperva_cookie_test(url: str, s: requests.Session) -> None:
    """Test Imperva cookie-based protection"""
    try:
        req1 = s.get(url, verify=False, timeout=10)
        
        # Check for Imperva cookies
        incap_cookies = [c for c in s.cookies if "incap" in c.name.lower()]
        if incap_cookies:
            req2 = requests.get(url, verify=False, timeout=10)
            if req2.status_code != req1.status_code:
                print(f"       Cookie validation enforced: {req1.status_code} vs {req2.status_code}")
    except Exception:
        pass


def imperva(url: str, s: requests.Session) -> None:
    """
    https://docs.imperva.com/bundle/cloud-application-security/page/settings/xray-debug-headers.htm
    https://docs.imperva.com/bundle/advanced-bot-protection/page/74736.htm
    """
    imperva_list = [
        ("incap-cache-key", "1"),
        ("incap-cache-reason", "1"),
        ("incap-cache-control", "no-cache"),
        ("incap-cache-status", "bypass"),
        
        ("incap-client-ip", "127.0.0.1"),
        ("x-forwarded-for", "127.0.0.1"),
        ("true-client-ip", "127.0.0.1"),
        
        ("x-iinfo", "1"),
        ("x-cdn", "Imperva"),
        ("x-imperva-debug", "1"),
        ("x-imperva-request-id", "test"),
        
        ("x-distil-debug", "1"),
        ("x-distil-cs", "test"),
        ("x-distil-session", "test"),
        ("x-distil-ajax", "1"),
        
        ("incap-rule-id", "1"),
        ("incap-acl-id", "1"),
        ("incap-policy-id", "1"),
        ("incap-session-id", "test123"),
        
        ("x-incap-bypass", "1"),
        ("x-incap-no-cache", "1"),
        ("incap-auth-token", "test"),
        
        ("x-incap-client-type", "browser"),
        ("x-incap-user-agent", "test"),
        ("x-incap-country", "US"),
        
        ("x-incap-api-key", "test"),
        ("x-incap-origin-ip", "127.0.0.1"),
        ("x-incap-edge-id", "test"),
    ]
    
    baseline_size = 0
    try:
        baseline = s.get(url, verify=False, timeout=10)
        baseline_size = len(baseline.content)
    except Exception:
        pass
    
    imperva_headers_shown = False
    
    size_groups = defaultdict(list)
    
    for header_name, header_value in imperva_list:
        try:
            headers = {header_name: header_value}
            req = s.get(url, headers=headers, verify=False, timeout=10)
            current_size = len(req.content)
            
            size_groups[current_size].append((header_name, header_value, req.status_code))
            
            if not imperva_headers_shown:
                imperva_resp_headers = ["x-iinfo", "x-cdn", "x-distil-cs", "x-distil-session"]
                for h in req.headers:
                    if any(ih in h.lower() for ih in imperva_resp_headers):
                        value = req.headers[h][:100]
                        print(f"       {h}: {value}")
                imperva_headers_shown = True
                
        except Exception:
            logger.exception(f"Error with Imperva check on {url}")
    
    for size in sorted(size_groups.keys()):
        headers_list = size_groups[size]
        count = len(headers_list)
        
        diff = ""
        if baseline_size > 0:
            size_diff = abs(size - baseline_size)
            if size_diff > 100:
                diff = f" ⚠ Diff: {size_diff:+} bytes"
        
        if count < 3:
            for header_name, header_value, status_code in headers_list:
                print(f"   └── {header_name}={header_value} → {status_code} [{size} bytes]{diff}")
        else:
            print(f"   └── [{size} bytes]{diff} (+ {count})")
            header_names = [f"{h[0]}={h[1]}" for h in headers_list]
            print(f"       {', '.join(header_names)}")
    
    imperva_cookie_test(url, s)