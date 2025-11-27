#!/usr/bin/env python3


from modules.cpdos.bsf import backslash_poisoning
from modules.cpdos.basic_cpdos import cpdos_main
from modules.cpdos.msh import MSH
from modules.cpdos.hho import HHO
from modules.cpdos.hmc import HMC
from modules.cpdos.hmo import HMO
from modules.cpdos.hhcn import HHCN
from modules.cpdos.hbh import HBH
from modules.cpdos.ocp import OCP
from modules.cpdos.ptp import path_traversal_check
from modules.cpdos.cfp import format_poisoning
from utils.style import Colors
from utils.utils import configure_logger, random, re, requests, sys, new_session, verify_waf
logger = configure_logger(__name__)


def crawl_files(
    url: str,
    s: requests.Session,
    req_main: requests.Response,
    authent: tuple[str, str] | None,
    human: str,
) -> None:
    try:
        regexp1 = r'(?<=src=")(\/[^\/].+?\.(js|css|html|htm|jsp|svg|txt))(?=")'
        regexp2 = r'(?<=href=")(\/[^\/].+?\.(js|css|html|htm|jsp|svg|txt))(?=")'
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
                run_cpdos_modules(uri, s, authent, human, crawl=True)
                backslash_poisoning(uri, s, authent, human)


    except Exception as e:
        logger.exception(e)


def randomiz_url(url):
    return f"{url}?CPDoS={random.randint(1, 99)}"


def run_cpdos_modules(
    url: str,
    s: requests.Session,
    authent: tuple[str, str] | None,
    human: str,
    crawl = False
) -> None:

    uri = f"{url}?CPDoS={random.randint(1337, 7331)}"

    req_main = requests.get(uri, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0"}, verify=False, allow_redirects=False, auth=authent, timeout=8)

    try:

        s = new_session(s)
        logger.debug(req_main.content)
        
        HHO(randomiz_url(url), s, req_main, authent, human)
        verify_waf(req_main, s.get(url))
        HMC(randomiz_url(url), s, req_main, authent, human)
        verify_waf(req_main, s.get(url))
        HMO(randomiz_url(url), s, req_main, authent, human)
        verify_waf(req_main, s.get(url))
        HHCN(randomiz_url(url), s, req_main, authent)
        verify_waf(req_main, s.get(url))
        HBH(randomiz_url(url), s, req_main, authent, human)
        verify_waf(req_main, s.get(url))
        MSH(url, req_main, authent, human)
        verify_waf(req_main, s.get(url))
        OCP(randomiz_url(url), authent)
        verify_waf(req_main, s.get(url))
        path_traversal_check(url, s, req_main, authent)
        verify_waf(req_main, s.get(url))
        cpdos_main(randomiz_url(url), s, req_main, authent, human)
        verify_waf(req_main, s.get(url))
        if not crawl:
            format_poisoning(randomiz_url(url), s, req_main, authent, human)
        # waf_rules(url, s, req_main, authent)
    except KeyboardInterrupt:
        print(" ! Canceled by keyboard interrupt (Ctrl-C)")
        sys.exit()
    except Exception as e:
        #print(e)
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

    run_cpdos_modules(url, s, authent, human)
    crawl_files(url, s, req_main, authent, human)
