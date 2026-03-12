#!/usr/bin/env python3

"""
Global & Compare requests to check if cp worked
"""

import utils.proxy as proxy
from utils.style import Colors, Identify
from utils.utils import configure_logger, sys, human_time, random, requests, range_exclusion, verify_waf, random_ua
from utils.print_utils import cache_tag_verify, format_payload
from utils.collect import add_finding

logger = configure_logger(__name__)

combinations = {}
exclude_combinations = set()

def confirm_vuln(url, s, authent, fp_results, human, probe, payload_header, initialStatusCode, initialResponseLen, rangeLenExclusion):
    uri = f"{url}{random.randrange(9999)}"
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
        canary_uri = f"{url}{random.randrange(9999)}"
        canary = canary_session.get(canary_uri, verify=False, timeout=10, auth=authent, allow_redirects=False)
        canary_session.close()
        
        if canary.status_code != initialStatusCode and canary.status_code not in [403, 419]:
            return (None, None)

        if (
            control.status_code == probe.status_code
            and control.status_code not in [initialStatusCode, 429]
        ):
            return ("confirmed", f"DIFFERENT STATUS-CODE {initialStatusCode} > {control.status_code}")

        elif (
            len(control.content) == len(probe.content)
            and len(control.content) not in rangeLenExclusion
            and control.status_code not in [403, 419]
        ):
            return ("confirmed", f"DIFFERENT RESP-LENGTH {initialResponseLen}b > {len(control.content)}b")
    
    return (None, None)


def confirm_vuln_raw(url, s, authent, fp_results, human, probe, payload_header, initialStatusCode, initialResponseLen, rangeLenExclusion):
    from modules.cpdos.basic_cpdos import raw_get
    
    uri = f"{url}{random.randrange(9999)}"

    for _ in range(3):
        merged_headers = dict(s.headers)
        merged_headers.update(payload_header)
        probe = raw_get(uri, headers=payload_header, auth=authent, timeout=10)
        human_time(human)
    
    control = s.get(uri, verify=False, timeout=10, auth=authent, allow_redirects=False)

    canary_session = requests.Session()
    canary_session.headers.update(random_ua())
    canary_uri = f"{url}{random.randrange(9999)}"
    canary = canary_session.get(canary_uri, verify=False, timeout=10, auth=authent, allow_redirects=False)
    canary_session.close()

    if canary.status_code != initialStatusCode and canary.status_code not in [403, 419]:
        return (None, None)
        
    if (
        control.status_code == probe.status_code
        and control.status_code not in [initialStatusCode, 429]
    ):
        return ("confirmed", f"DIFFERENT STATUS-CODE {initialStatusCode} > {control.status_code}")
    elif (
        len(control.content) == len(probe.content)
        and len(control.content) not in rangeLenExclusion
        and control.status_code not in [403, 419]
    ):
        return ("confirmed", f"DIFFERENT RESP-LENGTH {initialResponseLen}b > {len(control.content)}b")
    else:
        return (None, None)


def send_global_requests(url, s, authent, fp_results, VULN_NAME, human, payload_header, initialResponse, raw=False):

    initialStatusCode = initialResponse.status_code
    initialResponseLen = len(initialResponse.content)

    global combinations, exclude_combinations
    
    reason = ""
    status = ""
    severity = ""

    uri = f"{url}{random.randrange(9999)}"
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
    
    if len(probe.content) not in rangeLenExclusion:
        if combo_key not in combinations:
            combinations[combo_key] = 1
        elif combinations[combo_key] < 5 and combo_key not in exclude_combinations:
            combinations[combo_key] += 1
        
        if combo_key in combinations and combinations[combo_key] == 5:
            exclude_combinations.add(combo_key)

    if combo_key not in exclude_combinations and len(probe.content) not in rangeLenExclusion:
        if (probe.status_code != initialStatusCode 
            and probe.status_code != fp_results[0]
            and probe.status_code not in [403, 419]
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
    
    elif combo_key in exclude_combinations:
        potential_reason = None
        if (probe.status_code != initialStatusCode 
            and probe.status_code != fp_results[0]
            and probe.status_code not in [403, 419]
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
                f" {status} | {VULN_NAME} | {reason} | CACHETAG {cache_tag_verify(probe)} | {Colors.BLUE}{uri}{Colors.RESET} | PAYLOAD: {Colors.THISTLE}{format_payload(payload_header)}{Colors.RESET}"
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