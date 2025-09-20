#!/usr/bin/env python3

from bs4 import BeautifulSoup
from bs4.element import Tag

from utils.utils import re, requests, urljoin

COMMON_PATHS = [
    "accessibilite",
    "mentions-legales",
    "mentions",
    "legal",
    "cgu",
    "terms",
    "conditions",
    "terms-of-service",
    "privacy",
    "politique-de-confidentialite",
    "faq",
]

COMMON_REGEX = re.compile(
    r"|".join(re.escape(path).replace("-", r"[-\s]*") for path in COMMON_PATHS),
    re.IGNORECASE,
)


def get_unrisk_page(
    base_url: str, s: requests.Session, response: requests.Response
) -> str | None:
    soup = BeautifulSoup(response.text, "html.parser")

    for link in soup.find_all("a", href=True):
        if isinstance(link, Tag):
            href_attr = link.get("href")
            if isinstance(href_attr, str):
                href = href_attr.lower()
                if any(keyword in href for keyword in COMMON_PATHS):
                    legal_url = urljoin(base_url, href)
                    return legal_url

    for path in COMMON_PATHS:
        test_url = urljoin(base_url, "/" + path)
        try:
            resp = s.get(test_url, timeout=5)
            if resp.status_code == 200:
                if COMMON_REGEX.search(resp.text):
                    return test_url
        except requests.RequestException:
            continue

    return None
