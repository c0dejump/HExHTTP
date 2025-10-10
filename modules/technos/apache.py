#!/usr/bin/env python3

from utils.utils import requests

"""
Origin CORS DoS poisoning
def requestUriTooLongNoCacheParamTest(url, ip):
    
    baselineRequest = getRequest(ip, url)
    baseUrlLength = len(url)
    maxParamLength = 8190 - baseUrlLength - 1
    if("?" in url):
        craftedUrl = f"{url}&{'a' * maxParamLength}"
    else:
        craftedUrl = f"{url}?{'a' * maxParamLength}"
    poisonnedRequest = getRequest(ip, craftedUrl, headers={'Accept-Encoding': 'identity'})
    resultRequest = getRequest(ip, url, headers={'Accept-Encoding': 'identity'})
    
    if baselineRequest != None and poisonnedRequest != None and resultRequest != None:
        if baselineRequest.status_code != resultRequest.status_code:
                log("RequestUriTooLongNoCacheParam", ip, f"{url} (do not forget to set the 'Accept-Encoding: identity' header", f"(Status Codes: {baselineRequest.status_code} -> {resultRequest.status_code})", baselineRequest.status_code == 200)
                if(DEBUG):
                    debugRequests(baselineRequest, poisonnedRequest, resultRequest)
"""


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
