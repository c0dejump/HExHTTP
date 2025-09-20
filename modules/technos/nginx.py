#!/usr/bin/env python3

from utils.utils import configure_logger, requests

logger = configure_logger(__name__)


def nginx(url: str, s: requests.Session) -> None:
    """
    Unkeyed Query Exploitation: /%2F | /%2F?"><u>
    X-Real-IP
    Forwarded
    """
    try:
        uqe_url = f'{url}%2F?"><u>plop123</u>'
        uqe_req = s.get(uqe_url, verify=False, timeout=6)
        if uqe_req.status_code not in [403, 401, 400, 500]:
            if "plop123" in uqe_req.text:
                # print("coucou")
                pass
    except Exception as e:
        logger.exception(f"Error with UQE check on {url}", e)

    nginx_headers = [{"X-Real-IP": "plop123"}, {"Forwarded": "plop123"}]
    for ngh in nginx_headers:
        try:
            x_req = s.get(url, headers=ngh, verify=False, timeout=10)
            print(
                f"   └── {ngh}{'→':^3} {x_req.status_code:>3} [{len(x_req.content)} bytes]"
            )
            if "plop123" in x_req.text:
                print("plop123 reflected in text with {ngh} payload")
        except Exception as e:
            print(f"   └── Error with {ngh} payload")
            logger.exception(f"Error with UQE check on {url}", e)
