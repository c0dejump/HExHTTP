#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import sys
import random
import traceback

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def fastly(url, s):
    """
    https://docs.fastly.com/en/guides/checking-cache
    """
    fastly_list = [{
    "Fastly-Debug":"1"
    }]
    for fl in fastly_list:
        req_fastly = s.get(url, headers=fl, timeout=10)
        for rf in req_fastly.headers:
            if "fastly" in rf.lower() or "surrogate" in rf.lower():
                print("   └── {}: {}".format(rf, req_fastly.headers[rf]))
