#!/usr/bin/env python3
# -*- coding: utf-8 -*-


def vercel(url, s):
    """
    https://vercel.com/docs/edge-network/headers
    """
    #TODO
    vercel_header_list = [
        {"x-vercel-forwarded-for": "dscfvsdsdc.com"},
        {"x-vercel-deployment-url": "plop123"}, 
        {"x-vercel-ip-continent": "plop123"},
        {"x-vercel-signature": "plop123"},
    ]
    for vhl in vercel_header_list:
        try:
            headers = {vhl: "1"}
            req = s.get(url, headers=headers, verify=False, timeout=10)
            print(f"   └── {vhl}{'→':^3} {req.status_code:>3} [{len(req.content)} bytes]")
        except:
            pass
    