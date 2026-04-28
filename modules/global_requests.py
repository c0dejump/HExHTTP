#!/usr/bin/env python3

"""
Global & Compare requests to check if cp worked
"""

import threading
import uuid
import utils.proxy as proxy
from utils.style import Colors, Identify
from utils.utils import configure_logger, sys, human_time, random, requests, range_exclusion, verify_waf, random_ua
from utils.print_utils import cache_tag_verify, format_payload
from utils.collect import add_finding

logger = configure_logger(__name__)

# --- Per-URL combo tracking (thread-safe) ---
_combo_lock = threading.Lock()
_combinations: dict[str, dict] = {}        # base_url -> {combo_key: count}
_exclude_combinations: dict[str, set] = {} # base_url -> {combo_keys}


def _get_combos(base_url):
    """Return (combinations_dict, exclude_set) for a given base URL, creating if needed."""
    with _combo_lock:
        if base_url not in _combinations:
            _combinations[base_url] = {}
            _exclude_combinations[base_url] = set()
        return _combinations[base_url], _exclude_combinations[base_url]


def _cb():
    """Unique cache buster to avoid cross-thread cache collision."""
    return uuid.uuid4().hex[:12]


BODY_PAYLOADS = [
    "xx",
    "A" * 128,        # petit
    "A" * 8192,       # 8k  - nginx default buffer
    "A" * 16384,      # 16k - nginx 64bit / haproxy
    "A" * 32768,      # 32k - varnish
    "A" * 65536,      # 64k - envoy
    "A" * 131072,     # 128k
]


def confirm_vuln_with_body(url, s, authent, fp_results, human, probe, payload_header, initialStatusCode, initialResponseLen, rangeLenExclusion):
    """Fallback: sends probe with body on GET to force caching, control without body"""
    for body in BODY_PAYLOADS:
        uri = f"{url}{_cb()}"
        for _ in range(3):
            probe = s.get(
                uri,
                headers=payload_header,
                data=body,
                timeout=10,
                auth=authent,
                allow_redirects=False,
            )
            human_time(human)
 
        s.headers.update(random_ua())
        control = s.get(uri, verify=False, timeout=10, auth=authent, allow_redirects=False)
 
        canary_session = requests.Session()
        canary_session.headers.update(random_ua())
        canary_uri = f"{url}{_cb()}"
        canary = canary_session.get(canary_uri, verify=False, timeout=10, auth=authent, allow_redirects=False)
        canary_session.close()
 
        if canary.status_code != initialStatusCode and canary.status_code not in [403, 429]:
            continue
 
        if (
            control.status_code == probe.status_code
            and control.status_code not in [initialStatusCode, 429, 403]
        ):
            body = body if len(body) < 10 else f"A * {len(body) -1}" 
            return ("confirmed", f"DIFFERENT STATUS-CODE {initialStatusCode} > {control.status_code} [BODY:{repr(body)}]")
 
        elif (
            len(control.content) == len(probe.content)
            and len(control.content) not in rangeLenExclusion
            and control.status_code not in [403, 429]
        ):
            body = body if len(body) < 10 else f"A * {len(body) -1}" 
            return ("confirmed", f"DIFFERENT RESP-LENGTH {initialResponseLen}b > {len(control.content)}b [BODY:{repr(body)}]")
 
    return (None, None)



def confirm_vuln(url, s, authent, fp_results, human, probe, payload_header, initialStatusCode, initialResponseLen, rangeLenExclusion):
    uri = f"{url}{_cb()}"
    for _ in range(3):
        probe = s.get(
            uri,
            headers=payload_header,
            timeout=10,
            auth=authent,
            allow_redirects=False,
        )
        human_time(human)
                
        s.headers.update(random_ua())

        control = s.get(uri, verify=False, timeout=10, auth=authent, allow_redirects=False)

        canary_session = requests.Session()
        canary_session.headers.update(random_ua())
        canary_uri = f"{url}{_cb()}"
        canary = canary_session.get(canary_uri, verify=False, timeout=10, auth=authent, allow_redirects=False)
        canary_session.close()
        
        if canary.status_code != initialStatusCode and canary.status_code not in [403, 429]:
            return (None, None)

        if (
            control.status_code == probe.status_code
            and control.status_code not in [initialStatusCode, 429, 403]
        ):
            return ("confirmed", f"DIFFERENT STATUS-CODE {initialStatusCode} > {control.status_code}")

        elif (
            len(control.content) == len(probe.content)
            and len(control.content) not in rangeLenExclusion
            and control.status_code not in [403, 429]
        ):
            return ("confirmed", f"DIFFERENT RESP-LENGTH {initialResponseLen}b > {len(control.content)}b")
    
    return (None, None)


def confirm_vuln_raw(url, s, authent, fp_results, human, probe, payload_header, initialStatusCode, initialResponseLen, rangeLenExclusion):
    from modules.cpdos.basic_cpdos import raw_get
    
    uri = f"{url}{_cb()}"

    for _ in range(3):
        merged_headers = dict(s.headers)
        merged_headers.update(payload_header)
        probe = raw_get(uri, headers=payload_header, auth=authent, timeout=10)
        human_time(human)
    
    control = s.get(uri, verify=False, timeout=10, auth=authent, allow_redirects=False)

    canary_session = requests.Session()
    canary_session.headers.update(random_ua())
    canary_uri = f"{url}{_cb()}"
    canary = canary_session.get(canary_uri, verify=False, timeout=10, auth=authent, allow_redirects=False)
    canary_session.close()

    if canary.status_code != initialStatusCode and canary.status_code not in [403, 429]:
        return (None, None)
        
    if (
        control.status_code == probe.status_code
        and control.status_code not in [initialStatusCode, 429, 403]
    ):
        return ("confirmed", f"DIFFERENT STATUS-CODE {initialStatusCode} > {control.status_code}")
    elif (
        len(control.content) == len(probe.content)
        and len(control.content) not in rangeLenExclusion
        and control.status_code not in [403, 429]
    ):
        return ("confirmed", f"DIFFERENT RESP-LENGTH {initialResponseLen}b > {len(control.content)}b")
    else:
        return (None, None)


def send_global_requests(url, s, authent, fp_results, VULN_NAME, human, payload_header, initialResponse, raw=False):

    initialStatusCode = initialResponse.status_code
    initialResponseLen = len(initialResponse.content)

    # Per-URL combo tracking instead of global shared state
    combinations, exclude_combinations = _get_combos(url)
    
    reason = ""
    status = ""
    severity = ""

    uri = f"{url}{_cb()}"
    rangeLenExclusion = range_exclusion(initialResponseLen)

    if raw:
        from modules.cpdos.basic_cpdos import raw_get
        merged_headers = dict(s.headers)
        merged_headers.update(payload_header)

        probe = raw_get(uri, headers=merged_headers, auth=authent, timeout=10)
    else:
        s.headers.update(random_ua())
        probe = s.get(
                uri,
                headers=payload_header,
                verify=False,
                timeout=10,
                auth=authent,
                allow_redirects=False,
        )

    human_time(human)

    if probe.status_code in [405, 403, 412, 429]:
        verify_waf(url, s, initialResponse, payload=payload_header)


    combo_key = (probe.status_code, len(probe.content))
    
    with _combo_lock:
        if len(probe.content) not in rangeLenExclusion:
            if combo_key not in combinations:
                combinations[combo_key] = 1
            elif combinations[combo_key] < 5 and combo_key not in exclude_combinations:
                combinations[combo_key] += 1
            
            if combo_key in combinations and combinations[combo_key] == 5:
                exclude_combinations.add(combo_key)

        is_excluded = combo_key in exclude_combinations

    if not is_excluded and len(probe.content) not in rangeLenExclusion:
        if (probe.status_code != initialStatusCode 
            and probe.status_code != fp_results[0]
            and probe.status_code not in [403, 429]
        ):
            reason = f"DIFFERENT STATUS-CODE {initialStatusCode} > {probe.status_code}"
            status = f"{Identify.behavior}"
            severity = "behavior"

            add_finding(url, {
                "type": "CPDoS",
                "severity": "info",
                "title": VULN_NAME,
                "description": reason,
                "payload": payload_header,
                "evidence": {
                        "status_code": probe.status_code,
                        "response_size": len(probe.content),
                        "initial_status": initialStatusCode,
                        "initial_size": initialResponseLen,
                        "uri": uri,
                    }
            })

            if raw:
                confirmed_severity, confirmed_reason = confirm_vuln_raw(url, s, authent, fp_results, human, probe, payload_header, initialStatusCode, initialResponseLen, rangeLenExclusion)
            else:
                confirmed_severity, confirmed_reason = confirm_vuln(url, s, authent, fp_results, human, probe, payload_header, initialStatusCode, initialResponseLen, rangeLenExclusion)

            if not confirmed_severity:
                confirmed_severity, confirmed_reason = confirm_vuln_with_body(url, s, authent, fp_results, human, probe, payload_header, initialStatusCode, initialResponseLen, rangeLenExclusion)
            
            if confirmed_severity:
                reason = confirmed_reason
                status = f"{Identify.confirmed}"
                severity = confirmed_severity

                add_finding(url, {
                    "type": "CPDoS",
                    "severity": "critical",
                    "title": VULN_NAME,
                    "description": reason,
                    "payload": payload_header,
                    "evidence": {
                        "status_code": probe.status_code,
                        "response_size": len(probe.content),
                        "initial_status": initialStatusCode,
                        "initial_size": initialResponseLen,
                        "uri": uri,
                    }
                })
        
        elif len(probe.content) != initialResponseLen and len(probe.content) != fp_results[1]:
            reason = f"DIFFERENT RESP-LENGTH {initialResponseLen}b > {len(probe.content)}b"
            status = f"{Identify.behavior}"
            severity = "behavior"

            add_finding(url, {
                "type": "CPDoS",
                "severity": "info",
                "title": VULN_NAME,
                "description": reason,
                "payload": payload_header,
                "evidence": {
                        "status_code": probe.status_code,
                        "response_size": len(probe.content),
                        "initial_status": initialStatusCode,
                        "initial_size": initialResponseLen,
                        "uri": uri,
                    }
            })

            if raw:
                confirmed_severity, confirmed_reason = confirm_vuln_raw(url, s, authent, fp_results, human, probe, payload_header, initialStatusCode, initialResponseLen, rangeLenExclusion)
            else:
                confirmed_severity, confirmed_reason = confirm_vuln(url, s, authent, fp_results, human, probe, payload_header, initialStatusCode, initialResponseLen, rangeLenExclusion)

            if not confirmed_severity:
                confirmed_severity, confirmed_reason = confirm_vuln_with_body(url, s, authent, fp_results, human, probe, payload_header, initialStatusCode, initialResponseLen, rangeLenExclusion)

            
            if confirmed_severity:
                reason = confirmed_reason
                status = f"{Identify.confirmed}"
                severity = confirmed_severity

                add_finding(url, {
                    "type": "CPDoS",
                    "severity": "critical",
                    "title": VULN_NAME,
                    "description": reason,
                    "payload": payload_header,
                    "evidence": {
                        "status_code": probe.status_code,
                        "response_size": len(probe.content),
                        "initial_status": initialStatusCode,
                        "initial_size": initialResponseLen,
                        "uri": uri,
                    }
                })
    
    elif is_excluded:
        potential_reason = None
        if (probe.status_code != initialStatusCode 
            and probe.status_code != fp_results[0]
            and probe.status_code not in [403, 429]
        ):
            potential_reason = f"DIFFERENT STATUS-CODE {initialStatusCode} > {probe.status_code}"
        
        elif len(probe.content) != initialResponseLen and len(probe.content) != fp_results[1]:
            potential_reason = f"DIFFERENT RESP-LENGTH {initialResponseLen}b > {len(probe.content)}b"
        
        if potential_reason:
            confirmed_severity, confirmed_reason = confirm_vuln(url, s, authent, fp_results, human, probe, payload_header, initialStatusCode, initialResponseLen, rangeLenExclusion)
            
            if confirmed_severity:
                reason = confirmed_reason
                status = f"{Identify.confirmed}"
                severity = confirmed_severity

                add_finding(url, {
                    "type": "CPDoS",
                    "severity": "critical",
                    "title": VULN_NAME,
                    "description": reason,
                    "payload": payload_header,
                    "evidence": {
                        "status_code": probe.status_code,
                        "response_size": len(probe.content),
                        "initial_status": initialStatusCode,
                        "initial_size": initialResponseLen,
                        "uri": uri,
                    }
                })

    if reason:
        #print(f"Combinations: {combinations}")
        #print(f"Excluded: {exclude_combinations}")
        if not raw:
            print(
                f" {status} | {VULN_NAME} [REQ] | {reason} | CACHETAG {cache_tag_verify(probe)} | {Colors.BLUE}{uri}{Colors.RESET} | PAYLOAD: {Colors.THISTLE}{format_payload(payload_header)}{Colors.RESET}"
            )
        else:
            print(
                f" {status} | {VULN_NAME} [RAW] | {reason} | CACHETAG {cache_tag_verify(probe)} | {Colors.BLUE}{uri}{Colors.RESET} | PAYLOAD: {Colors.THISTLE}{format_payload(payload_header)}{Colors.RESET}"
            )
    
    if reason and proxy.proxy_enabled:
        from utils.proxy import proxy_request
        proxy_request(
            s,
            "GET",
            uri,
            headers=payload_header,
            data=None,
            severity=severity,
        )