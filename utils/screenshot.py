#!/usr/bin/env python3

"""
Screenshot utility for confirmed poisoned pages.
Requires: pip install playwright && playwright install chromium
"""

import os
from datetime import datetime
from urllib.parse import urlparse

screenshot_enabled: bool = False
screenshot_dir: str = "screenshots"


def take_screenshot(url: str) -> str | None:
    if not screenshot_enabled:
        return None

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(
            " [!] playwright not installed — run: pip install playwright && playwright install chromium"
        )
        return None

    os.makedirs(screenshot_dir, exist_ok=True)

    parsed = urlparse(url)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    safe_host = parsed.netloc.replace(".", "_").replace(":", "-")
    filepath = os.path.join(screenshot_dir, f"{safe_host}_{timestamp}.png")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(ignore_https_errors=True)
            page.goto(url, timeout=15000, wait_until="domcontentloaded")
            page.screenshot(path=filepath, full_page=True)
            browser.close()
        print(f" [SCREEN] {url} {filepath}")
        return filepath
    except Exception as e:
        print(f" [!] Screenshot failed: {e}")
        return None
