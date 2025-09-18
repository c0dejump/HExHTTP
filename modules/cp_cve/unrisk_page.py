from bs4 import BeautifulSoup
from utils.utils import requests, re 
from urllib.parse import urljoin

COMMON_PATHS = [
    "accessibilite", "mentions-legales", "mentions", "legal", "cgu", "terms", "conditions",
    "terms-of-service", "privacy", "politique-de-confidentialite", "faq"
]

COMMON_REGEX = re.compile(
    r"|".join(re.escape(path).replace("-", r"[-\s]*") for path in COMMON_PATHS),
    re.IGNORECASE
)

def get_unrisk_page(base_url, response):
    soup = BeautifulSoup(response.text, "html.parser")

    for link in soup.find_all("a", href=True):
        href = link["href"].lower()
        if any(keyword in href for keyword in COMMON_PATHS):
            legal_url = urljoin(base_url, href)
            return legal_url

    for path in COMMON_PATHS:
        test_url = urljoin(base_url, "/" + path)
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200:
                if COMMON_REGEX.search(response.text):
                    return test_url
        except requests.RequestException:
            continue

    return None