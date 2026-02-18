#!/usr/bin/env python3

from utils.utils import configure_logger, requests, urlparse
from utils.style import Colors

logger = configure_logger(__name__)


def nginx_off_by_slash(url: str, s: requests.Session) -> None:
    """Test NGINX off-by-slash vulnerability"""
    parsed = urlparse(url)
    paths_to_test = [
        "/admin../",
        "/api../",
        "/../admin/",
        "/static../admin"
    ]
    
    for path in paths_to_test:
        test_url = f"{parsed.scheme}://{parsed.netloc}{path}"
        try:
            req = s.get(test_url, verify=False, timeout=10, allow_redirects=False)
            if req.status_code in [200, 301, 302]:
                print(f"{Colors.YELLOW}   └── Off-by-slash behavior: {path} -> {req.status_code}{Colors.RESET}")
        except Exception:
            pass


def nginx_proxy_headers(url: str, s: requests.Session) -> None:
    """Test NGINX proxy-specific headers"""
    nginx_headers = [
        {"X-Real-IP": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-Host": "evil.com"},
        {"X-Forwarded-Proto": "https"},
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"Forwarded": "for=127.0.0.1;host=evil.com;proto=https"}
    ]
    
    for header in nginx_headers:
        try:
            req = s.get(url, headers=header, verify=False, timeout=10)
            print(f"   └── {header} -> {req.status_code} [{len(req.content)} bytes]")
            
            # Check for reflection
            header_value = list(header.values())[0]
            if header_value in req.text:
                print(f"{Colors.GREEN}       └── Reflection detected{Colors.RESET}")
        except Exception:
            pass


def nginx_merge_slashes_test(url: str, s: requests.Session) -> None:
    """Test NGINX merge_slashes directive"""
    test_paths = [
        "//admin",
        "///admin",
        "/./admin",
        "/.//admin",
        "/api//v1",
        "/static///files"
    ]
    
    for path in test_paths:
        test_url = f"{url}{path}"
        try:
            req = s.get(test_url, verify=False, timeout=10)
            if req.status_code == 200:
                print(f"{Colors.YELLOW}   └── Merge slashes: {path} -> {req.status_code}{Colors.RESET}")
        except Exception:
            pass


def nginx(url: str, s: requests.Session) -> None:
    """Extended Unkeyed Query Exploitation tests"""
    uqe_payloads = [
        '%2F?"><script>alert(1)</script>',
        '%2F?"><u>plop123</u>',
        '/%2F?"><u>plop123</u>',
        '/..%2F?"><u>plop123</u>',
        '/%5C?"><u>plop123</u>',
        '//plop123',
        '/%252F?"><u>plop123</u>'
    ]
    
    for payload in uqe_payloads:
        try:
            test_url = f"{url}{payload}"
            req = s.get(test_url, verify=False, timeout=6)
            if req.status_code not in [403, 401, 400, 500]:
                if "plop123" in req.text or "alert" in req.text:
                    print(f"{Colors.GREEN}   └── UQE reflection: {payload}{Colors.RESET}")
        except Exception:
            pass
    nginx_off_by_slash(url, s)
    nginx_proxy_headers(url, s)
    nginx_merge_slashes_test(url, s)