#!/usr/bin/env python3
import requests
from utils.style import Colors

def cache_tag_verify(req: requests.Response) -> str:
    cachetag = False
    for rh in req.headers:
        if "age" in rh.lower() or "hit" in rh.lower() or "cache" in rh.lower():
            cachetag = True
        else:
            pass
    colored_cachetag = (
        f"{Colors.GREEN}" if cachetag else f"{Colors.RED}"
    ) + f"{str(cachetag)}{Colors.RESET}"
    return colored_cachetag
    

def _escape_bytewise(s: str) -> str:
    """
      - backslash -> \\
      - \n -> \\n, \r -> \\r, \t -> \\t
      - quote simple -> \'
      - printable ASCII (0x20..0x7e)
      - other octets -> \\xHH
    """
    if s is None:
        return ""
    b = s.encode("utf-8", errors="surrogatepass")
    out_parts = []
    for byte in b:
        ch = chr(byte)
        if ch == "\\":
            out_parts.append("\\\\")
        elif ch == "\n":
            out_parts.append("\\n")
        elif ch == "\r":
            out_parts.append("\\r")
        elif ch == "\t":
            out_parts.append("\\t")
        elif ch == "'":
            out_parts.append("\\'")
        elif 32 <= byte <= 126:
            out_parts.append(ch)
        else:
            out_parts.append(f"\\x{byte:02x}")
    return "".join(out_parts)


def format_payload(payload: dict) -> str:
    parts = []
    for k, v in payload.items():
        ks_escaped = _escape_bytewise(str(k))
        vs_escaped = _escape_bytewise(str(v))
        if len(vs_escaped) > 60:
            vs_escaped = f"{vs_escaped[:60]}...({len(vs_escaped)} total chars)"
        parts.append(f"{ks_escaped}: {vs_escaped}")
    return "" + ", ".join(parts) + ""


def print_results(identify, vulnerability_type, reason, cachetag, url, payload):
	print(f" {identify} | {vulnerability_type} {reason} | CACHETAG: {cachetag} | {Colors.BLUE}{url}{Colors.RESET} | PAYLOAD: {Colors.THISTLE}{format_payload(payload)}{Colors.RESET}")