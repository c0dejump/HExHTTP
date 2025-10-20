#!/usr/bin/env python3

"""
Attempts to find Cache Poisoning Denial of Service (CpDoS) error based
https://cpdos.org/
"""

import utils.proxy as proxy
from modules.lists import payloads_keys
from utils.style import Identify, Colors
from utils.utils import (
    configure_logger,
    human_time,
    random,
    requests,
    sys,
    range_exclusion,
    random_ua,
)
from utils.print_utils import print_results, cache_tag_verify

# stdlib
import socket
import ssl
from urllib.parse import urlsplit
import string
import base64

logger = configure_logger(__name__)


class SimpleResponse:
    def __init__(self, status_code: int, headers: dict[str, str], content: bytes):
        self.status_code = status_code
        self.headers = headers
        self.content = content


def raw_get(url: str, headers: dict[str, str] | None, auth: tuple[str, str] | None, timeout: int = 10) -> SimpleResponse:
    headers = headers or {}

    if getattr(proxy, "proxy_enabled", False):
        logger.warning("Proxy enabled but not supported by raw sending; direct sending without proxy.")

    u = urlsplit(url)
    scheme = u.scheme.lower() or "http"
    host_port = u.netloc
    if not host_port:
        raise ValueError(f"invalid URL: {url}")

    # host et port
    if ":" in host_port:
        host, port_str = host_port.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            port = 443 if scheme == "https" else 80
    else:
        host = host_port
        port = 443 if scheme == "https" else 80

    # chemin + query
    path = u.path or "/"
    if u.query:
        path = f"{path}?{u.query}"

    lines: list[bytes] = []
    lines.append(f"GET {path} HTTP/1.1\r\n".encode("utf-8", errors="surrogatepass"))

    has_host_like = any(k.lower() == "host" for k in (headers.keys() if headers else []))
    if not has_host_like:
        lines.append(f"Host: {host}\r\n".encode("utf-8", errors="surrogatepass"))

    if auth and len(auth) == 2 and all(auth):
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode("utf-8", errors="surrogatepass")).decode("ascii")
        lines.append(f"Authorization: Basic {token}\r\n".encode("ascii"))

    lines.append(b"Connection: close\r\n")

    if headers:
        for k, v in headers.items():
            name_bytes = str(k).encode("utf-8", errors="surrogatepass")
            val_bytes = str(v).encode("utf-8", errors="surrogatepass")
            lines.append(name_bytes + b": " + val_bytes + b"\r\n")

    lines.append(b"\r\n")
    req_bytes = b"".join(lines)

    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ssock = ctx.wrap_socket(sock, server_hostname=host)
        else:
            ssock = sock

        ssock.sendall(req_bytes)

        chunks = []
        while True:
            data = ssock.recv(65536)
            if not data:
                break
            chunks.append(data)
        raw = b"".join(chunks)
    finally:
        try:
            ssock.close()
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass

    sep = raw.find(b"\r\n\r\n")
    if sep == -1:
        return SimpleResponse(status_code=0, headers={}, content=raw)

    head = raw[:sep]
    body = raw[sep+4:]

    first_crlf = head.find(b"\r\n")
    status_line = head[:first_crlf] if first_crlf != -1 else head
    try:
        parts = status_line.decode("latin-1", errors="ignore").split()
        code = int(parts[1]) if len(parts) >= 2 else 0
    except Exception:
        code = 0

    headers_dict: dict[str, str] = {}
    if first_crlf != -1:
        for line in head[first_crlf+2:].split(b"\r\n"):
            if b":" in line:
                name, val = line.split(b":", 1)
                headers_dict[name.decode("latin-1", errors="ignore")] = val.strip().decode("latin-1", errors="ignore")

    return SimpleResponse(status_code=code, headers=headers_dict, content=body)


def safe_get(s, url: str, headers: dict[str, str] | None, verify: bool, allow_redirects: bool, auth: tuple[str, str] | None, timeout: int):
    try:
        s.headers.update(random_ua())
        return s.get(
            url,
            headers=headers,
            verify=verify,
            allow_redirects=allow_redirects,
            auth=auth,
            timeout=timeout,
        )
    except requests.exceptions.InvalidHeader as e:
        logger.debug(f"safe_get fallback raw pour {url}: {e}")
        return raw_get(url, headers, auth, timeout=timeout)



def check_cached_status(
    url: str,
    s: requests.Session,
    pk: dict[str, str],
    main_status_code: int,
    authent: tuple[str, str] | None,
) -> None:
    behavior = True
    confirmed = False
    cache_status: bool = False

    for _ in range(0, 3):
        req = safe_get(
            s,
            url,
            headers=pk,
            verify=False,
            allow_redirects=False,
            auth=authent,
            timeout=10,
        )
    req_verify = safe_get(
        s, url, headers=None, verify=False, allow_redirects=False, auth=authent, timeout=10
    )
    logger.debug(f"{req.status_code} :: {req_verify.status_code}")
    if (
        req_verify.status_code != main_status_code
        and req.status_code == req_verify.status_code
        and req.status_code not in [429, 304, 303, 403]
        and req_verify.status_code not in [429, 304, 303, 403]
    ):
        confirmed = True


    if confirmed:
        print_results(Identify.confirmed , "CPDoSError", f"{main_status_code} > {req.status_code}", cache_tag_verify(req), url, pk)
        if proxy.proxy_enabled:
            from utils.proxy import proxy_request
            proxy_request(s, "GET", url, headers=pk, data=None, severity="confirmed")
        behavior = False
    elif behavior:
        print_results(Identify.behavior , "CPDoSError", f"{main_status_code} > {req.status_code}", cache_tag_verify(req), url, pk)
        if proxy.proxy_enabled:
            from utils.proxy import proxy_request
            proxy_request(s, "GET", url, headers=pk, data=None, severity="behavior")


def check_cached_len(
    url: str,
    s: requests.Session,
    pk: dict[str, str],
    main_len: int,
    authent: tuple[str, str] | None,
) -> None:
    behavior = True
    confirmed = False
    cache_status: bool = False

    for _ in range(0, 3):
        req = safe_get(
            s,
            url,
            headers=pk,
            verify=False,
            allow_redirects=False,
            auth=authent,
            timeout=10,
        )
    req_verify = safe_get(
        s, url, headers=None, verify=False, allow_redirects=False, auth=authent, timeout=10
    )
    logger.debug(f"{req.status_code} :: {req_verify.status_code}")
    if (
        len(req.content) == len(req_verify.content)
        and len(req_verify.content) != main_len
        and req_verify.status_code not in [429, 403, 401]
    ):
        confirmed = True


    if confirmed:
        print_results(Identify.confirmed , "CPDoSError", f"{main_len}b > {len(req.content)}b", cache_tag_verify(req), url, pk)
        if proxy.proxy_enabled:
            from utils.proxy import proxy_request
            proxy_request(s, "GET", url, headers=pk, data=None, severity="confirmed")
        behavior = False
    elif behavior:
        print_results(Identify.behavior , "CPDoSError", f"{main_len}b > {len(req.content)}b", cache_tag_verify(req), url, pk)
        if proxy.proxy_enabled:
            from utils.proxy import proxy_request
            proxy_request(s, "GET", url, headers=pk, data=None, severity="behavior")


def cpdos_main(
    url: str,
    s: requests.Session,
    initial_response: requests.Response,
    authent: tuple[str, str] | None,
    human: str,
) -> None:
    main_status_code = initial_response.status_code
    main_len = len(initial_response.content)
    blocked = 0

    rel = range_exclusion(main_len)
    
    for pk in payloads_keys:
        uri = f"{url}{random.randrange(9999)}"
        try:
            req = safe_get(
                s,
                uri,
                headers=pk,
                verify=False,
                auth=authent,
                timeout=10,
                allow_redirects=False,
            )
            len_req = len(req.content)

            if req.status_code == 888:
                print_results(Identify.behavior , "CPDoSError", "888 response", cache_tag_verify(req), url, pk)
                check_cached_status(uri, s, pk, main_status_code, authent)
            if req.status_code == 403 or req.status_code == 429:
                uri_403 = f"{url}{random.randrange(999)}"
                req_403_test = safe_get(
                    s,
                    uri_403,
                    headers=None,
                    verify=False,
                    auth=authent,
                    timeout=10,
                    allow_redirects=False,
                )
                if req_403_test.status_code == 403 or req_403_test.status_code == 429:
                    blocked += 1

            if (
                blocked < 3
                and main_status_code not in [403, 401]
                and req.status_code != main_status_code
            ):
                check_cached_status(uri, s, pk, main_status_code, authent)
            elif blocked < 3 and req.status_code == main_status_code:
                if len(str(main_len)) <= 5 and main_len not in rel:
                    check_cached_len(uri, s, pk, main_len, authent)
                elif len(str(main_len)) > 5 and main_len not in rel:
                    check_cached_len(uri, s, pk, main_len, authent)
            human_time(human)

            if len(list(pk.values())[0]) < 50 and len(list(pk.keys())[0]) < 50:
                sys.stdout.write(f"{Colors.BLUE}{pk} :: {req.status_code}{Colors.RESET}\r")
                sys.stdout.write("\033[K")
        except KeyboardInterrupt:
            print("Exiting")
            sys.exit()
        except requests.exceptions.InvalidHeader as e:
            print(f"invalide header (fallback): {e}")
            try:
                req = raw_get(uri, pk, authent, timeout=10)
                #print(f"{Colors.YELLOW}RAW sent -> status {req.status_code}{Colors.RESET}")
            except Exception as ee:
                #print(f"raw send error: {ee}")
                logger.exception(ee)
        except UnicodeEncodeError as e:
            #print(f"invalid unicode: {e}")
            logger.exception(e)
        except Exception as e:
            #print(e)
            logger.exception(e)
        uri = url
