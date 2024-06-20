#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules.utils import *

def apache(url, s):
    """
    Unkeyed Query Exploitation: // | //?"><script>
        X-Forwarded-Server
        X-Real-IP
        Max-Forwards

    https://hackerone.com/reports/2327341: CVE-2024-21733 Apache Tomcat HTTP Request Smuggling (Client- Side Desync) (CWE: 444)
    """
    try:
        #CVE-2024-21733
        res_post_without_data = requests.post(url, verify=False, timeout=10)
        res_post = requests.post(url, data="X", verify=False, timeout=10)

        len_pwd = len(res_post_without_data.content)
        len_p = len(res_post.content)

        if len_p not in range(len_pwd - 50, len_pwd + 50) and res_post.status_code not in [404, 200, 403] and res_post.status_code != res_post_without_data.status_code and len_p != 0:
            print(f"   └── [ND][{res_post_without_data.status_code}][{len_pwd}b] :: [X][{res_post.status_code}][{len_p}b] | {url}")
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
    except Exception as e:
        pass
        #print(f"Error {url} : {str(e)}")
    uqe_url = f'{url}/?"><u>plop123</u>'
    uqe_req = s.get(uqe_url, verify=False, timeout=6)
    if uqe_req not in [403, 401, 400, 500]:
        if "plop123" in uqe_req.text:
            #print("coucou")
            #TODO
            pass
    apache_headers = [{"X-Forwarded-Server": "plop123"}, {"X-Real-IP": "plop123"}, {"Max-Forwards": "plop123"}]
    for aph in apache_headers:
        x_req = s.get(url, headers=aph, verify=False, timeout=10)
        print(f"   └── {aph}{'→':^3} {x_req.status_code:>3} [{len(x_req.content)} bytes]")
        if "plop123" in x_req.text:
            print(f"   └── plop123 reflected in text with {aph} payload")
