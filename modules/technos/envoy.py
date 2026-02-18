#!/usr/bin/env python3

from utils.style import Colors
from utils.utils import random, requests, sys, urlparse, defaultdict


def envoy_admin_test(url: str, s: requests.Session) -> None:
    """Test for exposed Envoy admin interface"""
    from utils.utils import urlparse
    
    admin_paths = [
        "/admin",
        "/stats",
        "/config_dump",
        "/clusters",
        "/server_info"
    ]
    
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    
    for path in admin_paths:
        test_url = f"{base_url}{path}"
        try:
            req = s.get(test_url, verify=False, timeout=10, allow_redirects=False)
            
            if req.status_code == 200:
                text_lower = req.text.lower()
                
                envoy_keywords = ["envoy", "cluster", "listener", "route", "upstream"]
                error_keywords = ["error", "404", "not found", "aspxerrorpath"]
                
                has_envoy = any(keyword in text_lower for keyword in envoy_keywords)
                has_error = any(keyword in text_lower for keyword in error_keywords)
                
                if has_envoy and not has_error:
                    print(f"{Colors.YELLOW}   └── Envoy admin potentialy exposed: {path}{Colors.RESET}")
                    print(f"       URL: {test_url}")
        except Exception:
            pass
            

def envoy(url: str, s: requests.Session) -> None:
    url = f"{url}?cb={random.randint(1, 100)}"
    envoy_header_list = [
        {"X-Envoy-external-adress": "plop123"},
        {"X-Envoy-external-address": "plop123"},
        {"X-Envoy-internal": "plop123"},
        {"X-Envoy-Original-Dst-Host": "plop123"},
        {"X-Echo-Set-Header": "X-Foo: plop123"},
        {"x-envoy-original-path": "/plop123"},
        {"x-envoy-upstream-service-time": "9999"},
        {"x-envoy-decorator-operation": "plop123"},
        {"x-envoy-peer-metadata": "plop123"},
        {"x-envoy-attempt-count": "999"},
        {"x-b3-traceid": "plop123"},
        {"x-b3-spanid": "plop123"},
        {"x-request-id": "plop123"},
    ]

    results = defaultdict(list)
    reflections = []

    for ehl in envoy_header_list:
        try:
            x_req = s.get(url, headers=ehl, verify=False, timeout=10)
            status = x_req.status_code
            size = len(x_req.content)
            result_key = (status, size)

            results[result_key].append(ehl)

            if "plop123" in x_req.text or "plop123" in str(x_req.headers):
                reflections.append(ehl)
        except Exception:
            results[("ERROR", 0)].append(ehl)

    for (status, size), headers in results.items():
        if status == "ERROR":
            print(f"{Colors.RED}   └── ERROR{Colors.RESET} : {headers[0]}")
            if len(headers) > 1:
                print(f"       +{len(headers)-1} autres erreurs")
            continue

        if len(headers) <= 3:
            for h in headers:
                print(f"   └── {h}{'→':^3} {status:>3} [{size} bytes]")
        else:
            print(f"   └── {headers[0]}{'→':^3} {status:>3} [{size} bytes] (+{len(headers)-1} similar)")

    if reflections:
        print(f"{Colors.YELLOW}   └── INTERESTING BEHAVIOR - HEADER REFLECTION{Colors.RESET}")
        if len(reflections) <= 3:
            for ref in reflections:
                print(
                    f"   └── {Colors.BLUE}{url}{Colors.RESET} | PAYLOAD: {ref}"
                )
        else:
            print(f"   └── {Colors.BLUE}{url}{Colors.RESET}")
            print(f"   └── {len(reflections)} headers reflected: {', '.join([list(r.keys())[0] for r in reflections[:3]])}...")

    envoy_admin_test(url, s)