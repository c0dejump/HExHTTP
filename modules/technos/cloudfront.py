#!/usr/bin/env python3

from utils.style import Colors
from utils.utils import requests


def cloudfront(url: str, s: requests.Session) -> None:
    """
    Amazon CloudFront analysis.

    CloudFront-specific headers:
    - X-Amz-Cf-Pop: Indicates the CloudFront edge location (Point of Presence)
    - X-Amz-Cf-Id: CloudFront request ID for tracking
    - X-Cache: Cache status (Hit from cloudfront, Miss from cloudfront, etc.)
    - Via: Often contains CloudFront information

    Common CloudFront cache behaviors and testing opportunities.
    """
    print(f"{Colors.CYAN} ├── CloudFront detected{Colors.RESET}")

    # Basic CloudFront cache testing
    headers = {"X-Forwarded-Proto": "nohttps"}
    try:
        url = f"{url}?cb=123132"
        cf_test = s.get(url, headers=headers, verify=False, timeout=6)

        if cf_test.status_code in [301, 302, 303]:
            print(
                f"{Colors.YELLOW} │   └── Potential CloudFront redirect behavior detected{Colors.RESET}"
            )
    except requests.exceptions.TooManyRedirects:
        print(
                f"{Colors.YELLOW} │   └── TooManyRedirects / Potential CloudFront redirect behavior detected{Colors.RESET}"
            )

    # Check for common CloudFront cache headers
    cf_headers = ["x-cache", "x-amz-cf-pop", "x-amz-cf-id", "via"]
    detected_headers = []

    for header in cf_headers:
        if header in [h.lower() for h in cf_test.headers.keys()]:
            detected_headers.append(header)

    """if detected_headers:
        print(
            f"{Colors.GREEN} │   └── CloudFront headers found: {', '.join(detected_headers)}{Colors.RESET}"
        )"""
