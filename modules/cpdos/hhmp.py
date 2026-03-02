#! /usr/bin/env python3

"""
Host Header manipulation poisoning
"""

from utils.style import Colors, Identify
from utils.utils import configure_logger, get_domain_from_url, random, requests
from modules.global_requests import send_global_requests
import tldextract

logger = configure_logger(__name__)

VULN_NAME = "HHMP"


def HHMP(
    url: str,
    s: requests.Session,
    initialResponse: requests.Response,
    authent: tuple[str, str] | None,
    fp_results: tuple[int, int] | None,
    human: str,
) -> None:

    ext = tldextract.extract(url)

    hhmp_list = [
        {f"Connection": f"Host", "Host": f"{ext.domain}.{ext.suffix}"},
        {f"Host": f"{ext.domain}.{ext.suffix}:"},
        {f"Host": f"{ext.domain}.{ext.suffix}:0"},
        {f"Host": f"{ext.domain}.{ext.suffix}:65536"},
        {f"Host": f"{ext.domain}.{ext.suffix}"},
        {f"Host": f"{ext.domain}.{ext.suffix}."},
        {f"Host": f"{ext.domain}.{ext.suffix}:443:443"},
        {f"Host": f" {ext.domain}.{ext.suffix}"},
        {f"Host": f"{ext.domain}.{ext.suffix}\t"},
        {f"Höst": f"{ext.domain}.{ext.suffix}"},
        {f"hOST": f"{ext.domain}.{ext.suffix}"},
        {f"Host": f"{ext.domain}.{ext.suffix}\r\nHost: evil.{ext.suffix}"},
        {f"Host": f"{ext.domain}.{ext.suffix}\nX-Injected: true"},
        {f"X-Forwarded-Proto": f"http", "X-Forwarded-Host": f"{ext.domain}.{ext.suffix}"},
        {f'X-Forwarded-Host': f'{ext.domain}©.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}®.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}™.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}€.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}£.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}¥.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}¢.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}°.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}±.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}µ.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}\ufeff.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}\ufffe.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}�.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}\u200c.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}\u200d.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}\u200e.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}\u200f.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}\u202a.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}\u202b.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}\u202c.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}\u202d.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}\u202e.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}💀.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}🔥.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}💉.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}🎯.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}\x80.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}\x81.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}\x8d.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}\x8f.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}\x90.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}\x9d.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}\xa0.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}ÿ.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}\u2028.{ext.suffix}'},
        {f'X-Forwarded-Host': f'{ext.domain}\u2029.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}©.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}®.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}™.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}€.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}£.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}¥.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}¢.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}°.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}±.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}µ.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}\ufeff.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}\ufffe.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}�.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}\u200c.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}\u200d.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}\u200e.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}\u200f.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}\u202a.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}\u202b.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}\u202c.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}\u202d.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}\u202e.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}💀.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}🔥.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}💉.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}🎯.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}\x80.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}\x81.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}\x8d.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}\x8f.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}\x90.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}\x9d.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}\xa0.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}ÿ.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}\u2028.{ext.suffix}'},
        {f'Forwarded': f'{ext.domain}\u2029.{ext.suffix}'},
        {f'Host©': f'{ext.domain}.{ext.suffix}'},
        {f'Host®': f'{ext.domain}.{ext.suffix}'},
        {f'Host€': f'{ext.domain}.{ext.suffix}'},
        {f'Host™': f'{ext.domain}.{ext.suffix}'},
        {f'Host\ufeff': f'{ext.domain}.{ext.suffix}'},
        {f'Host\u200b': f'{ext.domain}.{ext.suffix}'},
        {f'Host\u200c': f'{ext.domain}.{ext.suffix}'},
        {f'Host\u200d': f'{ext.domain}.{ext.suffix}'},
        {f'Host\u200e': f'{ext.domain}.{ext.suffix}'},
        {f'Host\u202e': f'{ext.domain}.{ext.suffix}'},
        {f'Host\x80': f'{ext.domain}.{ext.suffix}'},
        {f'Hostÿ': f'{ext.domain}.{ext.suffix}'},
        {f'Host\u2028': f'{ext.domain}.{ext.suffix}'},
        {f'Host\u2029': f'{ext.domain}.{ext.suffix}'},
        {f'Host💀': f'{ext.domain}.{ext.suffix}'},
    ]

    for hl in hhmp_list:
        try:
            send_global_requests(url, s, authent, fp_results, VULN_NAME, human, hl, initialResponse)

            print(f" {Colors.BLUE} {VULN_NAME} : {hl}{Colors.RESET}\r", end="")
            print("\033[K", end="")
        except requests.exceptions.InvalidHeader as ih:
            try:
                raw = True
                send_global_requests(url, s, authent, fp_results, VULN_NAME, human, pk, initialResponse, raw)
            except Exception as ihi:
                #print(ih)
                #logger.exception(ih)
                pass
        except UnicodeEncodeError as u:
            try:
                raw = True
                send_global_requests(url, s, authent, fp_results, VULN_NAME, human, pk, initialResponse, raw)
            except Exception as uu:
                #print(uu)
                #logger.exception(uu)
                pass