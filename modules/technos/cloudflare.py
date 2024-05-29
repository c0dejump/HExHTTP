#!/usr/bin/env python3
# -*- coding: utf-8 -*-


def cloudflare(url, s):
    """
        Cloudflare:
        X-Forwarded-Proto: http => 301/302/303 + CF-Cache-Status: HIT
    #Default Cache Times:
        By default, positive response codes:
        200 OK, 204 No Content, and 206 Partial Content, are cached for 120 minutes (two hours).
        - 204: 
            POST exemple.com Content-Type: application/json (void)
            DELETE exemple.com
        - 206:
            GET exemple.com Range: bytes=0-499
        Redirects (301 Moved Permanently, 302 Found, etc.) are cached for 20 minutes. 
        404 Not Found and 410 Gone, and similar errors are cached for only 3 minutes. 
        405 Method Not Allowed, and 500 (server) series errors only last for just 1 minute.

    # https://developers.cloudflare.com/pages/configuration/debugging-pages/
        curl -I https://example.com/.well-known/acme-challenge/randomstring => https://example.cloudflareaccess.com/cdn-cgi/access/login/admin.moneyboxapp.org?kid=ab6e5facb0659ad47308f4008f9f2cc680d87004273d595a5fbb7550a72daceb&redirect_url=%2F.well-known%2Facme-challenge%2Faaaaa&meta=eyJraWQiOiIxMTg1OTkxOTFiMzMyZDVmM2NmYWRmN2MzYjlkNTYwZDBmZTk4YmIwZDJiMThhNzQzYzZjODU2OTNiYWU3Zjk5IiwiYWxnIjoiUlMyNTYiLCJ0eXAiOiJKV1QifQ.eyJzZXJ2aWNlX3Rva2VuX3N0YXR1cyI6ZmFsc2UsImlhdCI6MTcwOTczNTk2Niwic2VydmljZV90b2tlbl9pZCI6IiIsImF1ZCI6ImFiNmU1ZmFjYjA2NTlhZDQ3MzA4ZjQwMDhmOWYyY2M2ODBkODcwMDQyNzNkNTk1YTVmYmI3NTUwYTcyZGFjZWIiLCJob3N0bmFtZSI6ImFkbWluLm1vbmV5Ym94YXBwLm9yZyIsImFwcF9zZXNzaW9uX2hhc2giOiIyMWQ2ZWUwMmUwY2QxZmNmNTM4YTZmMzZmYzU1MTViNmFhNjdiMDYzZWI4NzRlZTdkOWM0OTYxYTUxMDQ0MzNmIiwibmJmIjoxNzA5NzM1OTY2LCJpc193YXJwIjpmYWxzZSwiaXNfZ2F0ZXdheSI6ZmFsc2UsInR5cGUiOiJtZXRhIiwicmVkaXJlY3RfdXJsIjoiXC8ud2VsbC1rbm93blwvYWNtZS1jaGFsbGVuZ2VcL2FhYWFhIiwibXRsc19hdXRoIjp7ImNlcnRfaXNzdWVyX3NraSI6IiIsImNlcnRfcHJlc2VudGVkIjpmYWxzZSwiY2VydF9zZXJpYWwiOiIiLCJjZXJ0X2lzc3Vlcl9kbiI6IiIsImF1dGhfc3RhdHVzIjoiTk9ORSJ9LCJhdXRoX3N0YXR1cyI6Ik5PTkUifQ.EjbKVnnSi0B2MRYeMPx9xT9n-_9AlkcMMwuRQ4qA4jZyrIIaFfLkrKMUN3u0CYKk2kXVB1Dw0S8jSr3LlI9Op5OKwuvKQ5i1AItM2JfoKaZWMHlslVPzoakQI1rs_OVwtg8HqvbSlQ8xlUKU_2XcNTmYaioj96btduBmuB5Ou4WWKf_ipZD7JumvxwNj1tVcp27yyt7jITA-0WyCZRaVvf9VeFuhJlStOw5UlNoH0_Z7bBX6KjyZ7f6SJ1CPc1CD306FCWUW4yDxWU7sMi8ASBtz7CfBRipzLbZmwZilVBD5LTQnDSOnkUqNZi4MQ8H7-7A_OqIAf0TgwAddoFBv_A
    """
    headers = {"X-Forwarded-Proto": "nohttps"}
    cf_loop = s.get(url, headers=headers, verify=False, timeout=6)
    if cf_loop in [301, 302, 303]:
        print(cf_loop.headers)
        if "CF-Cache-Status: HIT" in cf_loop.headers:
            print(f"\033[32m   └──\033[0m Potential redirect loop exploit possible with \033[32m{headers}\033[0m payload")