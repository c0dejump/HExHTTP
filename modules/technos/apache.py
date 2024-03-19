#! /usr/bin/env python3
# -*- coding: utf-8 -*-


def apache(url, s):
    """
    Unkeyed Query Exploitation: // | //?"><script>
        X-Forwarded-Server
        X-Real-IP
        Max-Forwards
    """
    uqe_url = '{}/?"><u>plop123</u>'.format(url)
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
            print("plop123 reflected in text with {} payload".format(aph))