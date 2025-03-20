#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Check support for different HTTP versions
"""

from http.client import HTTPConnection
from modules.utils import requests, configure_logger

logger = configure_logger(__name__)


def check_http_version(url):
  
    print("\033[36m ├ HTTP Version analysis\033[0m")
    versions = ["HTTP/0.9", "HTTP/1.0", "HTTP/1.1", "HTTP/1.6", "HTTP/2", "HTTP/3", "QUIC", "HtTP/1.1", "SHTTP/1.3", "HTTP/1.1.1"]

    try:
        req = requests.get(url, verify=False, allow_redirects=False, timeout=10)
        req_base_version = req.raw.version
        logger.debug("HTTP Version : %s", req_base_version)

        for v in versions:
            HTTPConnection._http_vsn_str = v
            try:
                req_v = requests.get(url, timeout=10, verify=False, allow_redirects=False)
                print(
                    f" └── {v:<9}: {req_v.status_code:<3} [{len(req_v.content)} bytes] [Header Size: {len(req_v.headers)}b]"
                )
            except requests.exceptions.Timeout:
                print(f" └── Timeout Error with {v}")
            except KeyboardInterrupt as exc:
                raise KeyboardInterrupt from exc
            except Exception as e:
                print(f" └── Error with {v} : {e}")
                logger.exception(e)

        if req_base_version == 10:
            HTTPConnection._http_vsn_str = "HTTP/1.0"
        elif req_base_version == 11:
            HTTPConnection._http_vsn_str = "HTTP/1.1"
        elif req_base_version == 20:
            HTTPConnection._http_vsn_str = "HTTP/2"
    except Exception as e:
        print(f" └── Error {e}")
        logger.exception(e)


if __name__ == "__main__":
    url = "https://www.hosteur.com"
    check_http_version(url)
