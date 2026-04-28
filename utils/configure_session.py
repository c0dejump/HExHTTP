import sys
import requests
import utils.proxy as proxy
from utils.style import Colors

try:
    from curl_cffi import requests as creq
    from curl_cffi.requests import exceptions as creq_exceptions
    CURL_CFFI_AVAILABLE = True
except ImportError:
    CURL_CFFI_AVAILABLE = False
    creq_exceptions = None

session = None

BROWSER_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Priority": "u=4",
}


class StealthSession:
    """Wrapper curl_cffi compatible avec l'API requests.Session."""

    def __init__(self, impersonate="chrome120"):
        self._session = creq.Session(impersonate=impersonate, verify=False)
        self.headers = self._session.headers
        self.cookies = self._session.cookies
        self.proxies = {}
        self.verify = False
        self.max_redirects = 60
        self.adapters = {}

    def request(self, method, url, **kwargs):
        if "proxies" not in kwargs and self.proxies:
            kwargs["proxies"] = self.proxies

        merged_headers = dict(self.headers)
        if "headers" in kwargs:
            merged_headers.update(kwargs.pop("headers"))
        kwargs["headers"] = merged_headers

        kwargs.setdefault("verify", self.verify)
        kwargs.setdefault("max_redirects", self.max_redirects)
        kwargs.setdefault("timeout", 30)

        try:
            return self._session.request(method, url, **kwargs)
        except creq_exceptions.RequestException as e:
            if "curl: (23)" in str(e):
                raise requests.exceptions.ConnectionError(
                    f"curl_cffi write error on {method} {url}: {e}"
                ) from e
            raise

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def put(self, url, **kwargs):
        return self.request("PUT", url, **kwargs)

    def delete(self, url, **kwargs):
        return self.request("DELETE", url, **kwargs)

    def head(self, url, **kwargs):
        return self.request("HEAD", url, **kwargs)

    def options(self, url, **kwargs):
        return self.request("OPTIONS", url, **kwargs)

    def patch(self, url, **kwargs):
        return self.request("PATCH", url, **kwargs)


def build_session(args):
    global session

    stealth = getattr(args, "stealth", False)

    if stealth:
        if not CURL_CFFI_AVAILABLE:
            print(f" {Colors.RED}--stealth requires curl_cffi: pip install curl_cffi{Colors.RESET}")
            sys.exit(1)
        session = StealthSession(impersonate="chrome120")
        session.headers.update(BROWSER_HEADERS)
        #print(f" {Colors.GREEN}Stealth mode enabled (TLS impersonation: chrome120){Colors.RESET}")
    else:
        session = requests.Session()
        session.verify = False
        session.max_redirects = 60

    session.headers.update(
        {
            "User-Agent": f"{args.user_agent}",
            #DECOMMENTHIS
            #"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            #"Accept-Language": "en-US,en;q=0.5",
            #"Accept-Encoding": "gzip, deflate, br",
            #"Connection": "keep-alive",
            #"Upgrade-Insecure-Requests": "1",
            #"Sec-Fetch-Dest": "document",
            #"Sec-Fetch-Mode": "navigate",
            #"Sec-Fetch-Site": "none",
            #"Sec-Fetch-User": "?1",
            #"Priority": "u=4",
        }
    )
    if getattr(args, "custom_header", None):
        for raw in args.custom_header:
            if ":" in raw:
                name, _, value = raw.partition(":")
                session.headers[name.strip()] = value.strip()
            else:
                print(f" Error in custom header format: {raw}")
                sys.exit()
    if args.proxy is not None or args.burp is not None:
        if args.proxy is not None:
            proxy.proxy_url = proxy.parse_proxy_url(args.proxy)
            if proxy.test_proxy_connection(proxy.proxy_url):
                proxy.proxy_enabled = True
                print(f" Proxy configured: {proxy.proxy_url}")
            else:
                print(f" {Colors.YELLOW}Proxy connection test failed, but continuing: {proxy.proxy_url}{Colors.RESET}")
                proxy.proxy_enabled = True
        if args.burp is not None:
            proxy.burp_url = proxy.parse_proxy_url(args.burp)
            if proxy.test_proxy_connection(proxy.burp_url):
                proxy.burp_enabled = True
                print(f" Burp proxy configured: {proxy.burp_url}")
            else:
                print(f" {Colors.RED}Burp proxy connection failed: {proxy.burp_url}{Colors.RESET}")
                sys.exit(1)
        if args.burp is not None and args.proxy is None:
            proxy.proxy_enabled = True
            proxy.proxy_url = proxy.burp_url
        session.proxies = {"http": proxy.proxy_url, "https": proxy.proxy_url}
    return session


def clone_session():
    if isinstance(session, StealthSession):
        s = StealthSession()
        s.headers.update(dict(session.headers))
        if session.proxies:
            s.proxies = session.proxies.copy()
        if session.cookies:
            s.cookies.update(session.cookies)
        return s
    else:
        s = requests.Session()
        s.verify = session.verify
        s.max_redirects = session.max_redirects
        s.headers.update(dict(session.headers))
        if session.proxies:
            s.proxies = session.proxies.copy()
        if session.cookies:
            s.cookies.update(session.cookies)
        return s