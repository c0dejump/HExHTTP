#! /usr/bin/env python3
# -*- coding: utf-8 -*-


def envoy(url, s):
    apache_headers = [{"X-Envoy-external-adress": "plop123"}, {"X-Envoy-internal": "plop123"}, {"X-Envoy-Original-Dst-Host": "plop123"}]
    for aph in apache_headers:
        x_req = s.get(url, headers=aph, verify=False, timeout=10)
        print(f" └── {aph}{'→':^3} {x_req.status_code:>3} [{len(x_req.content)} bytes]")
        if "plop123" in x_req.text:
            print("plop123 reflected in text with {} payload".format(aph))