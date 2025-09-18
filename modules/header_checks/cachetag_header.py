#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def check_cachetag_header(url, req_main, base_header):
    print("\n\033[36m ├ Header cache tags\033[0m")
    # basic_header = ["Content-Type", "Content-Length", "Date", "Content-Security-Policy", "Alt-Svc", "Etag", "Referrer-Policy", "X-Dns-Prefetch-Control", "X-Permitted-Cross-Domain-Policies"]

    result = []
    for headi in base_header:
        if "cache" in headi or "Cache" in headi:
            result.append(f"{headi.split(':')[0]}:{headi.split(':')[1]}")
    for vary in base_header:
        if "Vary" in vary:
            result.append(f"{vary.split(':')[0]}:{vary.split(':')[1]}")
    for age in base_header:
        if age == "age" or age == "Age":
            result.append(f"{age.split(':')[0]}:{age.split(':')[1]}")
    for get_custom_header in base_header:
        if "Access" in get_custom_header:
            result.append(
                f"{get_custom_header.split(':')[0]}:{get_custom_header.split(':')[1]}"
            )
    for get_custom_host in base_header:
        if "host" in get_custom_header:
            result.append(
                f"{get_custom_host.split(':')[0]}:{get_custom_host.split(':')[1]}"
            )
    for r in result:
        print(f" ├──  {r:<30}")