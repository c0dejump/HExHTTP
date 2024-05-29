#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules.utils import * 

def imperva(url, s):
    """
      https://docs.imperva.com/bundle/cloud-application-security/page/settings/xray-debug-headers.htm
      https://docs.imperva.com/bundle/advanced-bot-protection/page/74736.htm
      incap-cache-key
      incap-cache-reason
      x-distil-debug
    """
    imperva_list = ["incap-cache-key", "incap-cache-reason", "x-distil-debug"]
    for il in imperva_list:
        try:
            headers = {il: "1"}
            req = s.get(url, headers=headers, verify=False, timeout=10)
            print(f"   └── {il}{'→':^3} {req.status_code:>3} [{len(req.content)} bytes]")
        except:
            pass
    