#!/usr/bin/env python3

"""
Standalone "top" Cache-Poisoning / CPDoS module.

Runs ONLY the curated shortlists — the fast pass used by the `--only-top`
option, which executes this module and skips every other check:

    1. `top_payloads_errors`     -> error-based CPDoS (top ~150 payloads)
    2. `top_reflected_payloads`  -> reflected Cache-Poisoning leading to XSS

It is intentionally self-contained and reuses the same senders/detectors as the
full modules, so a `--only-top` run stays faithful to the deep scan while being
an order of magnitude faster.
"""

from modules.lists import top_payloads_errors, top_reflected_payloads
from modules.cpdos.basic_cpdos import _run_cpdos_payloads
from modules.cachepoisoning.cache_poisoning import reflected_cache_poisoning
from utils.style import Colors
from utils.utils import configure_logger, random, requests, new_session, fp_baseline

logger = configure_logger(__name__)


def _randomiz_url(url: str) -> str:
    return f"{url}{'&' if '?' in url else '?'}TopCP={random.randint(133, 337)}"


def check_top_cp(
    url: str,
    s: requests.Session,
    req_main: requests.Response,
    custom_header: dict,
    authent: tuple[str, str] | None,
    human: str,
) -> None:

    print(f"{Colors.CYAN} ├ Top CP/CPDoS analysis {Colors.RESET}")

    # 1) Error-based CPDoS — curated top payloads only
    try:
        base = _randomiz_url(url)
        fp_results = fp_baseline(base, s)
        session = new_session(s)
        print(f"{Colors.CYAN} ├─ CPDoS top payloads [{len(top_payloads_errors)}]{Colors.RESET}")
        _run_cpdos_payloads(
            top_payloads_errors, base, session, req_main, authent, fp_results, human
        )
    except Exception as e:
        logger.exception(f"check_top_cp (errors): {e}")

    # 2) Reflected Cache-Poisoning -> XSS — curated top payloads only
    try:
        print(f"{Colors.CYAN} ├─ Reflected CP [{len(top_reflected_payloads)}]{Colors.RESET}")
        reflected_cache_poisoning(url, s, req_main, custom_header, authent, human)
    except Exception as e:
        logger.exception(f"check_top_cp (reflected): {e}")
