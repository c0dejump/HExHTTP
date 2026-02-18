#!/usr/bin/env python3

"""
Attempts to find Cache Poisoning Denial of Service (CpDoS) error based
https://cpdos.org/
"""

import utils.proxy as proxy
from modules.lists import payloads_keys
from modules.global_requests import send_global_requests
from utils.style import Colors, Identify
from utils.utils import (
    configure_logger,
    random,
    requests,
    sys,
)
from utils.print_utils import print_results, cache_tag_verify

# stdlib
import socket
import ssl
from urllib.parse import urlsplit
import base64

from http.client import RemoteDisconnected
from urllib3.exceptions import ProtocolError
from requests.exceptions import ContentDecodingError

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

    # host & port
    if ":" in host_port:
        host, port_str = host_port.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            port = 443 if scheme == "https" else 80
    else:
        host = host_port
        port = 443 if scheme == "https" else 80

    # path + query
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



def cpdos_main(
    url: str,
    s: requests.Session,
    initialResponse: requests.Response,
    authent: tuple[str, str] | None,
    fp_results: tuple[int, int] | None,
    human: str,
) -> None:
    
    for pk in payloads_keys:
        uri = f"{url}{random.randrange(9999)}"
        try:
            send_global_requests(uri, s, authent, fp_results, "CPDoS", human, pk, initialResponse)

            if len(list(pk.values())[0]) < 50 and len(list(pk.keys())[0]) < 50:
                sys.stdout.write(f"{Colors.BLUE}CPDoS : {pk}{Colors.RESET}\r")
                sys.stdout.write("\033[K")
                
        except KeyboardInterrupt:
            print("Exiting")
            sys.exit()
            
        except requests.exceptions.InvalidHeader as ih:
            try:
                raw = True
                send_global_requests(uri, s, authent, fp_results, "CPDoS", human, pk, initialResponse, raw)
            except Exception as ihi:
                #print(ih)
                #logger.exception(ih)
                pass
        except UnicodeEncodeError as u:
            try:
                raw = True
                send_global_requests(uri, s, authent, fp_results, "CPDoS", human, pk, initialResponse, raw)
            except Exception as uu:
                #print(uu)
                #logger.exception(uu)
                pass
        except (requests.exceptions.ConnectionError, RemoteDisconnected, ProtocolError) as c:
            #logger.exception(f"Connection closed by remote server for header {pk}: {str(c)}")
            pass
        except requests.Timeout as t:
            pass
            #logger.exception(t)

        except ContentDecodingError as cde:
            print(f" {Identify.behavior} | Server returned corrupted gzip | {Colors.BLUE}{uri}{Colors.RESET} | PAYLOAD: {Colors.THISTLE}{pk}{Colors.RESET}")
            try:
                cache_test = s.get(
                    uri,
                    allow_redirects=False,
                    verify=False
                )
            except ContentDecodingError:
                print(f" {Identify.confirmed} | Server returned corrupted gzip | {Colors.BLUE}{uri}{Colors.RESET} | PAYLOAD: {Colors.THISTLE}{pk}{Colors.RESET}")
                
            except Exception as e:
                pass

        except ValueError as ve:
            # Skip payloads with invalid IP addresses
            if "does not appear to be an IPv4 or IPv6 address" in str(ve):
                raw = True
                send_global_requests(uri, s, authent, fp_results, "CPDoS", human, pk, initialResponse, raw)
            else:
                pass
                #logger.exception(f"Basic CPDoS with {pk} payload: {str(ve)}")
                
        except AttributeError as ae:
            # Skip payloads that are malformed (set instead of dict)
            if "'set' object has no attribute" in str(ae):
                logger.error(f"Malformed payload (set instead of dict): {pk}")
            else:
                logger.exception(f"Basic CPDoS with {pk} payload: {str(ae)}")
                
        except Exception as e:
            logger.exception(f"Basic CPDoS with {pk} payload: {str(e)}")
                    
        uri = url