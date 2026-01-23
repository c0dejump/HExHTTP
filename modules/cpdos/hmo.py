#!/usr/bin/env python3

"""
Attempts to find Cache Poisoning with HTTP Method Override (HMO)
https://cpdos.org/#HMO
"""

from utils.style import Colors
from utils.utils import configure_logger, random, requests
from modules.global_requests import send_global_requests


logger = configure_logger(__name__)

VULN_NAME = "HTTP Method Override"


def HMO(
    url: str,
    s: requests.Session,
    initialResponse: requests.Response,
    authent: tuple[str, str] | None,
    fp_results: tuple[int, int] | None,
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

    for header, method in (
        (header, method) for header in hmo_headers for method in methods
    ):
        
        try:
            uri = f"{url}{random.randrange(999)}"

            probe_headers = {header: method}
            
            send_global_requests(uri, s, authent, fp_results, VULN_NAME, human, probe_headers, initialResponse)
            
            print(f" {Colors.BLUE} {VULN_NAME} : {probe_headers}{Colors.RESET}\r", end="")
            print("\033[K", end="")

        except requests.exceptions.ConnectionError as e:
            #print(e)
            logger.exception(e)