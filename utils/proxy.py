#!/usr/bin/env python3

import json

from utils.utils import requests

proxy_enabled = False

proxy_url = "http://127.0.0.1:8080"


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

    headers.update(
        {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0"
        }
    )
    s.proxies = {"http": proxy_url, "https": proxy_url}

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


def test_proxy_connection() -> bool:
    proxies = {
        "http": proxy_url,
        "https": proxy_url,
    }
    try:
        requests.get("http://httpbin.org/ip", proxies=proxies, timeout=5, verify=False)
        return True
    except Exception:
        return False
