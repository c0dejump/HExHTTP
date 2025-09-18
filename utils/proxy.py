import requests
import json
import base64
from urllib.parse import urlparse

proxy_enabled = False

proxy_url = "http://127.0.0.1:8080"

def create_burp_issue(s, url, title, description, severity, headers):
    try:        
        issue_data = json.dumps({
            "title": title,
            "description": description,
            "severity": severity
        })
        
        headers.update({"X-Create-Burp-Issue": issue_data})
        
        response = s.get(url, headers=headers, timeout=10)
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        return False


def proxy_request(s, method, url, headers=None, data=None, severity=None):

    headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0"})
    s.proxies = {
            "http": proxy_url,
            "https": proxy_url
    }

    s.verify = False

    try:
        response = s.request(method, url, headers=headers, data=data)
        if severity == "behavior":
            create_burp_issue(
                s,
                url,
                "[HExHTTP] Behavior", 
                f"Cache poisoning vulnerability detected on {url}",
                "Medium",
                headers
            )
        elif severity == "confirmed":
            create_burp_issue(
                s,
                url,
                "[HExHTTP] Confirmed", 
                f"Cache poisoning vulnerability detected on {url}",
                "High",
                headers
            )
    except Exception as e:
        print(f"Error : {e}")


def test_proxy_connection():
    proxies = {
        "http": proxy_url,
        "https": proxy_url,
    }
    try:
        response = requests.get("http://httpbin.org/ip", proxies=proxies, timeout=5, verify=False)
        return True
    except:
        return False