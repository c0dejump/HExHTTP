#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
change format poisoning (html to json/xml)
https://cpdos.org/
"""

import json
import utils.proxy as proxy
from utils.style import Identify, Colors
from utils.utils import (
    configure_logger,
    human_time,
    random,
    requests,
    sys,
    re,
    random_ua,
)
from utils.print_utils import print_results, cache_tag_verify
from utils.collect import add_finding
from modules.lists.cfp_list import cfp_payloads


logger = configure_logger(__name__)


# Magic bytes for binary format detection
MAGIC_BYTES = {
    'PDF':        b'%PDF-',
    'ZIP':        b'PK\x03\x04',
    'PNG':        b'\x89PNG',
    'JPEG':       b'\xff\xd8\xff',
    'GIF':        b'GIF8',
    'WEBP':       b'RIFF',
    # Protobuf has no universal magic — detected via Content-Type only
    # MessagePack: first byte 0xc0–0xff or 0x80–0x8f (fixmap), heuristic only
    'MSGPACK':    None,
}

# HTML tags used to rule out XML/plain responses
HTML_TAGS_STRICT = [
    b'<html', b'<head', b'<body', b'<title', b'<meta',
    b'<link', b'<script', b'<style',
]

HTML_TAGS_EXTENDED = [
    b'<head', b'<body', b'<div', b'<span', b'<p>', b'<a ', b'<img',
    b'<script', b'<style', b'<meta', b'<title', b'<link', b'<form',
    b'<input', b'<button', b'<table', b'<tr', b'<td', b'<th',
    b'<ul', b'<ol', b'<li', b'<h1', b'<h2', b'<h3', b'<h4', b'<h5', b'<h6',
    b'<header', b'<footer', b'<nav', b'<section', b'<article', b'<aside',
    b'<main', b'<figure', b'<canvas', b'<svg', b'<video', b'<audio',
    b'<iframe', b'<embed', b'<object', b'<textarea', b'<select', b'<option',
    b'<label', b'<fieldset', b'<legend', b'<details', b'<summary',
]

CODE_PATTERNS = [
    b'function', b'var ', b'const ', b'let ', b'return',
    b'import ', b'def ', b'class ', b'if ', b'for ', b'while ',
]

XML_NAMESPACE_PATTERNS = [
    rb'<\?xml',
    rb'xmlns:',
    rb'<[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+',
]

# Tags that indicate a fully-rendered HTML page (with assets/styling)
ASSET_TAGS = [b'<link', b'<style', b'<script']

# Minimum size delta + ratio to consider content degradation
DEGRADE_MIN_DELTA = 500     # at least 500 bytes smaller
DEGRADE_MIN_RATIO = 0.30    # at least 30% smaller


def _has_bytes(content: bytes, tags: list, limit: int = 3000) -> bool:
    """Return True if any tag is found within the first `limit` bytes (case-insensitive)."""
    chunk = content[:limit].lower()
    return any(tag in chunk for tag in tags)


def _count_asset_tags(content: bytes) -> int:
    """Count occurrences of <link>, <style>, <script> in content."""
    lower = content.lower()
    return sum(lower.count(tag) for tag in ASSET_TAGS)


def _detect_degradation(init_content: bytes, init_len: int, probe_content: bytes, probe_len: int) -> str | None:
    """
    Detect content degradation: same format (both HTML) but page lost
    CSS/JS/assets — user sees raw unstyled HTML.

    Returns a short description string or None.
    """
    # Size-based: significant shrink
    delta = init_len - probe_len
    if init_len > 0 and delta >= DEGRADE_MIN_DELTA:
        ratio = delta / init_len
        if ratio >= DEGRADE_MIN_RATIO:
            # Confirm: original had asset tags, probe lost them
            init_assets = _count_asset_tags(init_content)
            probe_assets = _count_asset_tags(probe_content)
            if init_assets > 0 and probe_assets < init_assets:
                lost = init_assets - probe_assets
                return f"DEGRADED -{ratio:.0%} ({init_len}b > {probe_len}b)"

            # Even without asset tag loss, a huge size drop is suspicious
            if ratio >= 0.50:
                return f"DEGRADED -{ratio:.0%} ({init_len}b > {probe_len}b)"

    # Asset-tag-based: same size-ish but assets stripped
    if init_len > 1000:
        init_assets = _count_asset_tags(init_content)
        probe_assets = _count_asset_tags(probe_content)
        if init_assets >= 3 and probe_assets == 0:
            return f"DEGRADED lost all {init_assets} asset tags"

    return None


def detect_format(content: bytes, headers: dict) -> str | bool:
    """
    Attempt to identify the format of a response body.

    Returns a format string (e.g. 'JSON', 'XML', 'CSV', 'YAML', …) or False
    when the content appears to be HTML / unrecognised.
    """
    content_type = headers.get('Content-Type', '').lower()

    # --- Binary magic bytes ---
    for fmt, magic in MAGIC_BYTES.items():
        if magic and content.startswith(magic):
            return fmt

    # Heuristic MessagePack detection (first byte in fixmap / fixarray range)
    if content and (
        0x80 <= content[0] <= 0x9f   # fixmap / fixarray
        or content[0] in (0xdc, 0xdd, 0xde, 0xdf)  # array16/32, map16/32
    ) and 'msgpack' in content_type:
        return 'MSGPACK'

    content_stripped = content.strip()

    # --- JSON ---
    if 'application/json' in content_type or 'application/ld+json' in content_type:
        return 'JSON'

    if content_stripped[:1] in (b'{', b'['):
        try:
            json.loads(content)
            return 'JSON'
        except (json.JSONDecodeError, ValueError):
            pass

    # --- XML (strict Content-Type check first) ---
    if 'application/xml' in content_type or 'text/xml' in content_type:
        if not _has_bytes(content, [b'<!doctype html', b'<html'], limit=500):
            return 'XML'

    # --- XML (<?xml declaration) ---
    if content_stripped.startswith(b'<?xml'):
        if not _has_bytes(content, HTML_TAGS_STRICT, limit=2000):
            return 'XML'
        return False  # Looks like XHTML

    # --- XML (generic root tag heuristic) ---
    if re.match(rb'^\s*<[a-zA-Z0-9_-]+[^>]*>', content[:100]):
        if not _has_bytes(content, HTML_TAGS_EXTENDED):
            has_xml_ns = any(
                re.search(p, content[:1000]) for p in XML_NAMESPACE_PATTERNS
            )
            root_tags = re.findall(rb'^<([a-zA-Z0-9_-]+)', content_stripped)
            if root_tags and (has_xml_ns or b'</' in content):
                return 'XML'

    # --- CSV ---
    if 'text/csv' in content_type or 'application/csv' in content_type:
        if b'<' not in content[:1000] and b'>' not in content[:1000]:
            return 'CSV'

    # CSV heuristic: at least 2 non-empty lines with a consistent comma count,
    # no code keywords, and no markup.
    if b',' in content and b'\n' in content:
        lines = [ln for ln in content.split(b'\n')[:10] if ln.strip()]
        if len(lines) >= 2:
            comma_counts = [ln.count(b',') for ln in lines]
            count_variety = len(set(comma_counts))
            if count_variety <= 2 and min(comma_counts) >= 1:
                if not any(p in content[:1000].lower() for p in CODE_PATTERNS):
                    if b'<' not in content[:1000]:
                        return 'CSV'

    # --- YAML ---
    if any(k in content_type for k in ('yaml', 'yml')):
        return 'YAML'

    # YAML heuristic: starts with "---" followed by key: value or list items
    if content_stripped.startswith(b'---'):
        lines = content_stripped.split(b'\n')[:5]
        if any(b':' in ln or ln.strip().startswith(b'- ') for ln in lines[1:]):
            return 'YAML'

    # YAML heuristic: bare key: value at top level (no leading markup)
    if not content_stripped.startswith(b'<') and not content_stripped.startswith(b'{'):
        if re.match(rb'^[a-zA-Z_][a-zA-Z0-9_\-]*\s*:', content_stripped[:100]):
            return 'YAML'

    # --- RSS / Atom ---
    if (
        b'<rss' in content[:200].lower()
        or b'xmlns="http://www.w3.org/2005/atom"' in content[:500]
    ):
        return 'RSS/ATOM'

    # --- SOAP ---
    if (
        b'soap:envelope' in content[:500].lower()
        or b's:envelope' in content[:500].lower()
    ):
        return 'SOAP'

    # --- Protobuf (Content-Type only — no reliable magic bytes) ---
    if any(k in content_type for k in ('protobuf', 'x-protobuf', 'vnd.google.protobuf')):
        return 'PROTOBUF'

    # --- Fallback: trust Content-Type when it isn't text/html ---
    if 'text/plain' in content_type:
        return 'PLAINTEXT'

    if 'text/html' not in content_type and content_type:
        return content_type

    return False


def _get_cache_age(response: requests.Response) -> int | None:
    """Return the Age header value in seconds, or None if absent / unparseable."""
    age = response.headers.get('Age')
    if age is not None:
        try:
            return int(age)
        except ValueError:
            pass
    return None


def verify_cp(
    s: requests.Session,
    uri: str,
    cfp: dict,
    authent,
) -> str | bool:
    """
    Re-send the poisoning payload three times then issue a clean probe
    (reusing the existing session `s` so proxy / auth settings are honoured).
    Returns the detected format of the clean probe response.
    """
    for _ in range(3):
        s.get(uri, headers=cfp, verify=False, auth=authent, timeout=10, allow_redirects=False)

    req_verify = s.get(uri, verify=False, auth=authent, timeout=10, allow_redirects=False)
    return detect_format(req_verify.content, req_verify.headers)


def verify_cp_degradation(s, uri, cfp, authent, init_content, init_len):
    """
    Re-send poisoning payload 3x, then clean probe.
    Returns degradation description or None.
    """
    for _ in range(3):
        s.get(uri, headers=cfp, verify=False, auth=authent, timeout=10, allow_redirects=False)

    req_verify = s.get(uri, verify=False, auth=authent, timeout=10, allow_redirects=False)
    return _detect_degradation(init_content, init_len, req_verify.content, len(req_verify.content))


def format_poisoning(url, s, initial_response, authent, human):
    main_len = len(initial_response.content)
    init_content = initial_response.content
    df_init = detect_format(init_content, initial_response.headers)

    for cfp in cfp_payloads:
        uri = f"{url}{random.randrange(9999)}"
        try:
            s.headers.update(random_ua())
            req = s.get(uri, headers=cfp, verify=False, auth=authent, timeout=10, allow_redirects=False)
            df = detect_format(req.content, req.headers)

            cache_age = _get_cache_age(req)

            evidence_base = {
                "status_code": req.status_code,
                "response_size": len(req.content),
                "initial_status": initial_response.status_code,
                "initial_size": main_len,
                "uri": uri,
            }
            if cache_age is not None:
                evidence_base["cache_age"] = cache_age

            # --- Case 1: Format change (HTML → JSON, HTML → XML, etc.) ---
            if df and df != df_init:
                print_results(Identify.behavior, "CFP", f"{df_init or 'HTML'} > {df}", cache_tag_verify(req), uri, cfp)
                add_finding(url, {
                    "type": "CPDoS",
                    "severity": "info",
                    "title": "CFP",
                    "description": f"{df_init or 'HTML'} > {df}",
                    "payload": cfp,
                    "evidence": evidence_base,
                })

                vcp = verify_cp(s, uri, cfp, authent)
                if vcp and vcp != df_init:
                    print_results(Identify.confirmed, "CFP", f"{df_init or 'HTML'} > {df}", cache_tag_verify(req), uri, cfp)
                    add_finding(url, {
                        "type": "CPDoS",
                        "severity": "critical",
                        "title": "CFP",
                        "description": f"{df_init or 'HTML'} > {df}",
                        "payload": cfp,
                        "evidence": evidence_base,
                    })

            # --- Case 2: Same format but content degraded (lost CSS/JS/assets) ---
            elif not df_init and not df:
                # Both are HTML — check for degradation
                degrade_desc = _detect_degradation(init_content, main_len, req.content, len(req.content))
                if degrade_desc:
                    print_results(Identify.behavior, "CFP", degrade_desc, cache_tag_verify(req), uri, cfp)
                    add_finding(url, {
                        "type": "CPDoS",
                        "severity": "info",
                        "title": "CFP",
                        "description": degrade_desc,
                        "payload": cfp,
                        "evidence": evidence_base,
                    })

                    # Confirm: re-poison then clean probe
                    confirmed_degrade = verify_cp_degradation(s, uri, cfp, authent, init_content, main_len)
                    if confirmed_degrade:
                        print_results(Identify.confirmed, "CFP", confirmed_degrade, cache_tag_verify(req), uri, cfp)
                        add_finding(url, {
                            "type": "CPDoS",
                            "severity": "critical",
                            "title": "CFP",
                            "description": confirmed_degrade,
                            "payload": cfp,
                            "evidence": evidence_base,
                        })

        except UnicodeEncodeError:
            pass
        except (requests.exceptions.InvalidHeader, ValueError):
            # Expected: urllib3 rejects headers with \n, \r, \t, leading whitespace
            logger.debug(f"CFP header rejected by urllib3: {cfp}")
        except Exception as e:
            print(e)
            logger.exception(e)

        print(f" {Colors.BLUE} CFP : {cfp}{Colors.RESET}\r", end="")
        print("\033[K", end="")