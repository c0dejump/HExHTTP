#!/usr/bin/env python3


from modules.cpdos.backslash import backslash_poisoning
from modules.cpdos.basic_cpdos import cpdos_main
from modules.cpdos.multiple_headers import MHC
from modules.cpdos.ocd import OCD
from modules.cpdos.path_traversal import path_traversal_check
from utils.style import Colors
from utils.utils import configure_logger, random, re, requests, sys

logger = configure_logger(__name__)


def crawl_files(
    url: str,
    s: requests.Session,
    req_main: requests.Response,
    authent: tuple[str, str] | None,
    human: str,
) -> None:
    try:
        regexp1 = r'(?<=src=")(\/[^\/].+?\.(js|css|html|svg))(?=")'
        regexp2 = r'(?<=href=")(\/[^\/].+?\.(js|css|html|svg))(?=")'
        # regexp3 = r'(?<=src=")(\/[^\/].+?)(?=")'
        # regexp4 = r'(?<=href=")(\/[^\/].+?)(?=")'

        responseText = req_main.text

        filesURL = re.findall(regexp1, responseText)
        filesURL += re.findall(regexp2, responseText)
        # filesURL = re.findall(regexp3, responseText)
        # filesURL += re.findall(regexp4, responseText)

        for fu in filesURL:
            if "<" not in fu[0]:
                if len(url.split("/")) > 4:
                    url = f"{'/'.join(url.split('/')[:3])}/"
                uri = f"{url}{fu[0]}"
                if uri.startswith("https://"):
                    uri = f"https://{uri[8:].replace('//', '/')}"
                elif uri.startswith("http://"):
                    uri = f"https://{uri[7:].replace('//', '/')}"

                # print(uri)
                run_cpdos_modules(uri, s, req_main, authent, human)
                backslash_poisoning(uri, s)

    except Exception as e:
        logger.exception(e)


def run_cpdos_modules(
    url: str,
    s: requests.Session,
    req_main: requests.Response,
    authent: tuple[str, str] | None,
    human: str,
) -> None:
    uri = f"{url}?CPDoS={random.randint(1, 100)}"
    try:
        logger.debug(req_main.content)

        # HHO(uri, s, req_main, authent, human)
        # HMC(uri, s, req_main, authent, human)
        # HMO(uri, s, req_main, authent, human)
        # HHCN(uri, s, req_main, authent)
        # HBH(url, s, req_main, authent, human)
        MHC(url, req_main, authent, human)
        OCD(url, authent)
        path_traversal_check(url, s, req_main, authent)
        cpdos_main(uri, s, req_main, authent, human)
        # waf_rules(url, s, req_main, authent)
    except KeyboardInterrupt:
        print(" ! Canceled by keyboard interrupt (Ctrl-C)")
        sys.exit()
    except Exception as e:
        logger.exception(e)


def check_CPDoS(
    url: str,
    s: requests.Session,
    req_main: requests.Response,
    custom_header: dict,
    authent: tuple[str, str] | None,
    human: str,
) -> None:
    if req_main.status_code in [301, 302]:
        url = (
            req_main.headers["location"]
            if "http" in req_main.headers["location"]
            else f'{url}{req_main.headers["location"]}'
        )

    print(f"{Colors.CYAN} ├ CPDoS analysis{Colors.RESET}")

    run_cpdos_modules(url, s, req_main, authent, human)
    crawl_files(url, s, req_main, authent, human)
