#!/usr/bin/env python3

import json

from utils.utils import requests

proxy_enabled = False
burp_enabled = False

proxy_url = "http://127.0.0.1:8080"
burp_url = "http://127.0.0.1:8080"

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0"
)


def parse_proxy_url(proxy_input: str | None, default_host: str = "127.0.0.1", default_port: int = 8080) -> str:
    """Parse proxy input in host:port format, return http://host:port"""
    if not proxy_input:
        return f"http://{default_host}:{default_port}"
    
    # Check if it already has http:// or https://
    if proxy_input.startswith(("http://", "https://")):
        return proxy_input
    
    # Check if it contains :
    if ":" in proxy_input:
        host, port = proxy_input.split(":", 1)
        try:
            int(port)  # Validate port is a number
            return f"http://{host}:{port}"
        except ValueError:
            return f"http://{default_host}:{default_port}"
    else:
        # Only host provided, use default port
        return f"http://{proxy_input}:{default_port}"





def create_burp_issue(
    s: requests.Session,
    url: str,
    title: str,
    description: str,
    severity: str,
    headers: dict,
) -> bool:
    try:
        issue_data = json.dumps(
            {"title": title, "description": description, "severity": severity}
        )
        headers.update({"X-Create-Burp-Issue": issue_data})
        s.get(url, headers=headers, timeout=10)
        return True

    except Exception as e:
        print(f"Error: {e}")
        return False


def proxy_request(
    s: requests.Session,
    url: str,
    method: str,
    headers: dict[str, str] = dict(),
    data: str | None = None,
    severity: str = "",
) -> None:

    s.headers.update({"User-Agent": DEFAULT_USER_AGENT})
    # Use burp_url for Burp-specific requests, otherwise use proxy_url
    target_proxy = burp_url if burp_enabled else proxy_url
    s.proxies = {"http": target_proxy, "https": target_proxy}
    s.verify = False

    try:
        s.request(method, url, headers=headers, data=data)
        if severity == "behavior":
            create_burp_issue(
                s,
                url,
                "[HExHTTP] Behavior",
                f"Cache poisoning vulnerability detected on {url}",
                "Medium",
                headers,
            )
        elif severity == "confirmed":
            create_burp_issue(
                s,
                url,
                "[HExHTTP] Confirmed",
                f"Cache poisoning vulnerability detected on {url}",
                "High",
                headers,
            )
    except Exception as e:
        print(f"Error : {e}")


def test_proxy_connection(proxy_url_to_test: str | None = None) -> bool:
    """Test if a proxy connection is working"""
    test_url = proxy_url_to_test or proxy_url
    proxies = {
        "http": test_url,
        "https": test_url,
    }
    try:
        requests.get("http://httpbin.org/ip", proxies=proxies, timeout=5, verify=False)
        return True
    except Exception:
        return False
