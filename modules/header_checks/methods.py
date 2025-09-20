#!/usr/bin/env python3

"""
Check support for different HTTP methods (NOT DELETE & PATCH)
Improved version with deduplication and CONNECT verification
"""

from collections import defaultdict
from typing import Any

from urllib3 import PoolManager, Timeout

from utils.style import Colors
from utils.utils import configure_logger, get_ip_from_url, human_time, requests, urllib3

logger = configure_logger(__name__)

desc_method = {
    200: f"{Colors.GREEN}200 OK{Colors.RESET}",
    204: f"204 No Content{Colors.RESET}",
    400: f"{Colors.YELLOW}400 Bad Request{Colors.RESET}",
    401: f"{Colors.RED}401 HTTP Authent{Colors.RESET}",
    403: f"{Colors.RED}403 Forbidden{Colors.RESET}",
    405: f"{Colors.YELLOW}405 Method Not Allowed{Colors.RESET}",
    406: f"{Colors.YELLOW}406 Not Acceptable{Colors.RESET}",
    409: f"{Colors.YELLOW}409 Conflict{Colors.RESET}",
    410: "410 Gone",
    412: f"{Colors.YELLOW}412 Precondition Failed{Colors.RESET}",
    500: f"{Colors.RED}500 Internal Server Error{Colors.RESET}",
    501: f"{Colors.RED}501 Not Implemented{Colors.RESET}",
    502: f"{Colors.RED}502 Bad Gateway{Colors.RESET}",
    301: f"{Colors.REDIR}301 Moved Permanently{Colors.RESET}",
    302: f"{Colors.REDIR}302 Moved Temporarily{Colors.RESET}",
}

header = {
    "User-agent": "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko"
}


def get(url: str) -> tuple[int, Any, str, int, bytes]:
    req_g = requests.get(
        url, verify=False, allow_redirects=False, headers=header, timeout=120
    )
    return req_g.status_code, req_g.headers, "GET", len(req_g.content), req_g.content


def post(url: str) -> tuple[int, Any, str, int, bytes]:
    req_p = requests.post(
        url, verify=False, allow_redirects=False, headers=header, timeout=120
    )
    return req_p.status_code, req_p.headers, "POST", len(req_p.content), req_p.content


def put(url: str) -> tuple[int, Any, str, int, bytes]:
    req_pt = requests.put(
        url, verify=False, allow_redirects=False, headers=header, timeout=120
    )
    return (
        req_pt.status_code,
        req_pt.headers,
        "PUT",
        len(req_pt.content),
        req_pt.content,
    )


def patch(url: str) -> tuple[int, Any, str, int, bytes]:
    req_ptch = requests.patch(
        url, verify=False, allow_redirects=False, headers=header, timeout=120
    )
    return (
        req_ptch.status_code,
        req_ptch.headers,
        "PATCH",
        len(req_ptch.content),
        req_ptch.content,
    )


def options(url: str) -> tuple[int, Any, str, int, bytes]:
    req_o = requests.options(
        url, verify=False, allow_redirects=False, headers=header, timeout=120
    )
    return (
        req_o.status_code,
        req_o.headers,
        "OPTIONS",
        len(req_o.content),
        req_o.content,
    )


def verify_connect_method(url: str, http: PoolManager) -> tuple[bool, str]:
    target_ip = get_ip_from_url(url)
    vulnerabilities: list[str] = []

    security_tests = [
        ("google.com:80", "External HTTP tunneling"),
        ("8.8.8.8:53", "External DNS tunneling"),
        ("1.1.1.1:443", "External HTTPS tunneling"),
        ("127.0.0.1:22", "SSH localhost bypass"),
        ("127.0.0.1:3306", "MySQL localhost bypass"),
        ("localhost:80", "Localhost HTTP bypass"),
        ("0.0.0.0:80", "Wildcard bind bypass"),
        ("169.254.169.254:80", "AWS metadata access"),
        ("metadata.google.internal:80", "GCP metadata access"),
        ("192.168.1.1:80", "Private network access"),
        ("10.0.0.1:80", "Private network access"),
        ("172.16.0.1:80", "Private network access"),
    ]

    baseline_responses = []
    try:
        resp_target = http.request("CONNECT", target_ip + ":80")
        baseline_responses.append(resp_target.status)

        resp_fake = http.request("CONNECT", "nonexistent.invalid:80")
        baseline_responses.append(resp_fake.status)

    except Exception as e:
        logger.debug(f"Baseline CONNECT test failed: {e}")
        return False, ""

    if len(set(baseline_responses)) == 1 and baseline_responses[0] in [200, 201, 202]:
        vulnerabilities.append("Blind CONNECT proxy detected")

    successful_tests = []

    for test_target, vuln_desc in security_tests:
        try:
            resp = http.request("CONNECT", test_target)

            if resp.status in [200, 201, 202, 204]:
                successful_tests.append(vuln_desc)
                logger.debug(f"SECURITY: CONNECT {test_target} returned {resp.status}")

            elif resp.status == 502 and "localhost" in test_target:
                successful_tests.append(f"Partial {vuln_desc} (502 response)")

        except Exception as e:
            logger.debug(f"CONNECT security test error on {test_target}: {e}")
            continue

    if successful_tests:
        external_vulns = [v for v in successful_tests if "External" in v]
        localhost_vulns = [
            v for v in successful_tests if "localhost" in v or "Localhost" in v
        ]
        metadata_vulns = [v for v in successful_tests if "metadata" in v]
        private_vulns = [v for v in successful_tests if "Private network" in v]

        security_messages = []

        if external_vulns:
            security_messages.append(f"{Colors.RED}OPEN PROXY DETECTED{Colors.RESET}")
        if localhost_vulns:
            security_messages.append(f"{Colors.YELLOW}LOCALHOST BYPASS{Colors.RESET}")
        if metadata_vulns:
            security_messages.append(f"{Colors.RED}CLOUD METADATA ACCESS{Colors.RESET}")
        if private_vulns:
            security_messages.append(
                f"{Colors.YELLOW}INTERNAL NETWORK ACCESS{Colors.RESET}"
            )

        if vulnerabilities:
            security_messages.extend(
                [f"{Colors.RED}{v}{Colors.RESET}" for v in vulnerabilities]
            )

        return True, " | ".join(security_messages)

    try:
        smuggling_payload = (
            f"{target_ip}:80 HTTP/1.1\r\nContent-Length: 20\r\n\r\nGET /admin HTTP/1.1"
        )
        resp_smuggling = http.request("CONNECT", smuggling_payload)

        if resp_smuggling.status == 200 and len(resp_smuggling.data) > 50:
            return True, f"{Colors.RED}REQUEST SMUGGLING RISK{Colors.RESET}"

    except Exception as e:
        logger.debug(f"Request smuggling test failed: {e}")

    if any(status in [200, 201, 202, 204] for status in baseline_responses):
        return False, "SUPPORTED"

    return False, ""


def check_other_methods(
    ml: str,
    url: str,
    http: PoolManager,
    pad: int,
    results_tracker: dict[tuple, list[dict]],
) -> None:
    try:
        test_url = url
        if ml == "DELETE":
            test_url = f"{url}plopiplop.css"

        resp = http.request(ml, test_url)
        rs = resp.status
        resp_h = resp.headers

        cache_status = False
        try:
            rs_display = desc_method[rs]
        except KeyError:
            rs_display = str(rs)
            logger.debug("No descriptions available for status %s", rs)

        for rh in resp_h:
            if (
                "Cache-Status" in rh
                or "X-Cache" in rh
                or "x-drupal-cache" in rh
                or "X-Proxy-Cache" in rh
                or "X-HS-CF-Cache-Status" in rh
                or "X-Vercel-Cache" in rh
                or "X-nananana" in rh
                or "x-vercel-cache" in rh
                or "X-TZLA-EDGE-Cache-Hit" in rh
                or "x-spip-cache" in rh
                or "x-nextjs-cache" in rh
            ):
                cache_status = True

        len_req = len(resp.data.decode("utf-8"))

        # Créer une clé unique pour le tri (status + length)
        result_key = (rs, len_req)
        results_tracker[result_key].append(
            {
                "method": ml,
                "status": rs,
                "status_display": rs_display,
                "length": len_req,
                "cache_status": cache_status,
                "response_data": resp.data,
            }
        )

    except urllib3.exceptions.MaxRetryError:
        results_tracker[("ERROR", 0)].append(
            {
                "method": ml,
                "status": "ERROR",
                "status_display": "Error due to too many redirects",
                "length": 0,
                "cache_status": False,
                "response_data": b"",
            }
        )
    except Exception as e:
        logger.exception(e)
        results_tracker[("ERROR", 0)].append(
            {
                "method": ml,
                "status": "ERROR",
                "status_display": f"Error: {str(e)}",
                "length": 0,
                "cache_status": False,
                "response_data": b"",
            }
        )


def display_deduplicated_results(
    results_tracker: dict[tuple, list[dict]], pad: int, url: str, http: PoolManager
) -> None:
    displayed_groups: set[tuple] = set()

    for result_key, methods_list in results_tracker.items():
        if len(methods_list) >= 3:
            if result_key not in displayed_groups:
                first_method = methods_list[0]
                space = " " * (pad - len(first_method["method"]) + 1)
                other_methods = [m["method"] for m in methods_list[1:]]

                print(
                    f" ├── {first_method['method']}{space}{first_method['status_display']:<3}  "
                    f"[{first_method['length']} bytes]{'':<2} "
                    f"({Colors.CYAN}+{len(other_methods)} similar{Colors.RESET})"
                )  # {', '.join(other_methods)})

                displayed_groups.add(result_key)
        else:
            for method_result in methods_list:
                space = " " * (pad - len(method_result["method"]) + 1)

                connect_info = ""
                if method_result["method"] == "CONNECT" and method_result[
                    "status"
                ] not in ["ERROR", 405, 501]:
                    is_fp, fp_reason = verify_connect_method(url, http)
                    connect_info = (
                        f"[{Colors.GREEN}{'VALID'}: {fp_reason}{Colors.RESET}]"
                        if is_fp
                        else ""
                    )

                print(
                    f" ├── {method_result['method']}{space}{method_result['status_display']:<3}  "
                    f"[{method_result['length']} bytes]{'':<2} {connect_info}"
                )


def check_methods(url: str, custom_header: Any, authent: Any, human: bool) -> None:
    htimeout = Timeout(connect=7.0, read=7.0)
    http = PoolManager(timeout=htimeout)

    print(f"{Colors.CYAN} ├ Methods analysis{Colors.RESET}")
    result_list: list[tuple[int, Any, str, int, bytes]] = []
    for funct in [get, post, put, patch, options]:
        try:
            result_list.append(funct(url))
        except Exception as e:
            print(f" ├── Error with {funct} method: {e}")
            logger.exception("Error with %s method", funct, exc_info=True)

    for rs, req_head, type_r, len_req, req_content in result_list:
        try:
            rs_display = desc_method[rs]
        except KeyError:
            rs_display = str(rs)
            logger.debug("No descriptions available for status %s", rs)

        print(f" ├── {type_r:<10} {rs_display:<3} [{len_req} bytes] ")
        if type_r == "OPTIONS":
            for x in req_head:
                if x.lower() == "allow":
                    print(f" │  └─ Allows: {req_head[x]}")

    list_path = "modules/lists/methods_list.lst"
    try:
        with open(list_path) as method_file:
            method_list = method_file.read().splitlines()
            pad = max(len(m) for m in method_list)

            results_tracker: dict[tuple, list[dict]] = defaultdict(list)

            for ml in method_list:
                check_other_methods(ml, url, http, pad, results_tracker)
                if human:
                    human_time("1")

            display_deduplicated_results(results_tracker, pad, url, http)

    except FileNotFoundError:
        logger.error(f"Methods list file not found: {list_path}")
        print(f" ├── Error: Methods list file not found: {list_path}")
    except Exception as e:
        logger.exception(f"Error reading methods list {e}")
        print(" ├── Error reading methods list")
