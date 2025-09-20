#!/usr/bin/env python3

from utils.utils import configure_logger, requests

logger = configure_logger(__name__)


def imperva(url: str, s: requests.Session) -> None:
    """
    https://docs.imperva.com/bundle/cloud-application-security/page/settings/xray-debug-headers.htm
    https://docs.imperva.com/bundle/advanced-bot-protection/page/74736.htm
    incap-cache-key
    incap-cache-reason
    x-distil-debug
    """
    imperva_list = ["incap-cache-key", "incap-cache-reason", "x-distil-debug"]
    for il in imperva_list:
        try:
            headers = {il: "1"}
            req = s.get(url, headers=headers, verify=False, timeout=10)
            print(
                f"   └── {il}{'→':^3} {req.status_code:>3} [{len(req.content)} bytes]"
            )
        except Exception as e:
            logger.exception(f"Error with Imperva check on {url}", e)
