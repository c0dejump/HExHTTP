#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import sys
import random
import traceback

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def imperva(url, s):
    """
      https://docs.imperva.com/bundle/cloud-application-security/page/settings/xray-debug-headers.htm
      incap-cache-key
      incap-cache-reason
    """