#! /usr/bin/env python3
# -*- coding: utf-8 -*-


def nginx(url, s):
    """
    Unkeyed Query Exploitation: /%2F | /%2F?"><u>
    X-Real-IP
    Forwarded
    """
    try:
        uqe_url = '{}%2F?"><u>plop123</u>'.format(url)
        uqe_req = s.get(uqe_url, verify=False, timeout=6)
        if uqe_req not in [403, 401, 400, 500]:
            if "plop123" in uqe_req.text:
                #print("coucou")
                pass
    except:
        pass
    nginx_headers = [{"X-Real-IP": "plop123"}, {"Forwarded": "plop123"}]
    for ngh in nginx_headers:
        try:
            x_req = s.get(url, headers=ngh, verify=False, timeout=10)
            print(f"   └── {ngh}{'→':^3} {x_req.status_code:>3} [{len(x_req.content)} bytes]")
            if "plop123" in x_req.text:
                print("plop123 reflected in text with {} payload".format(ngh))
        except:
            print("   └── Error with {} payload".format(ngh))