import sys
import requests
import utils.proxy as proxy
from utils.style import Colors

session: requests.Session = None


def build_session(args) -> requests.Session:
    global session

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


def clone_session() -> requests.Session:
    s = requests.Session()
    s.verify = session.verify
    s.max_redirects = session.max_redirects
    s.headers.update(dict(session.headers))
    if session.proxies:
        s.proxies = session.proxies.copy()
    if session.cookies:
        s.cookies.update(session.cookies)
    return s