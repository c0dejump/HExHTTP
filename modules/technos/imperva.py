#!/usr/bin/env python3

from utils.utils import configure_logger, requests

logger = configure_logger(__name__)


def imperva_cookie_test(url: str, s: requests.Session) -> None:
    """Test Imperva cookie-based protection"""
    try:
        req1 = s.get(url, verify=False, timeout=10)
        
        # Check for Imperva cookies
        incap_cookies = [c for c in s.cookies if "incap" in c.name.lower()]
        if incap_cookies:
            print(f"{Colors.CYAN}   └── Imperva cookies found: {len(incap_cookies)}{Colors.RESET}")
            
            # Try without cookies
            req2 = requests.get(url, verify=False, timeout=10)
            if req2.status_code != req1.status_code:
                print(f"   └── Cookie validation enforced: {req1.status_code} vs {req2.status_code}")
    except Exception:
        pass


def imperva(url: str, s: requests.Session) -> None:
    """
    https://docs.imperva.com/bundle/cloud-application-security/page/settings/xray-debug-headers.htm
    https://docs.imperva.com/bundle/advanced-bot-protection/page/74736.htm
    """
    imperva_list = [
        "incap-cache-key",
        "incap-cache-reason",
        "x-distil-debug",
        "x-iinfo",  # Imperva info
        "x-cdn",  # CDN info
        "incap-client-ip",
        "x-forwarded-for"  # Test with internal IPs
    ]
    
    for il in imperva_list:
        try:
            headers = {il: "1"}
            if il == "x-forwarded-for":
                headers = {il: "127.0.0.1"}
                
            req = s.get(url, headers=headers, verify=False, timeout=10)
            print(f"   └── {il}{'→':^3} {req.status_code:>3} [{len(req.content)} bytes]")
            
            # Check for Imperva headers in response
            imperva_resp_headers = ["x-iinfo", "x-cdn", "set-cookie"]
            for h in req.headers:
                if any(ih in h.lower() for ih in imperva_resp_headers):
                    if "incap" in req.headers[h].lower() or "imperva" in req.headers[h].lower():
                        print(f"       {h}: {req.headers[h][:100]}")
        except Exception:
            logger.exception(f"Error with Imperva check on {url}")
    imperva_cookie_test(url, s)
