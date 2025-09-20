#!/usr/bin/env python3

from datetime import datetime
from queue import Empty, Queue
from threading import Thread
from typing import Any

# utils
import utils.proxy as proxy
from cli import args

# cp & cpdos
from modules.cp_check.cache_poisoning_nf_files import check_cache_files
from modules.cp_check.methods_poisoning import check_methods_poisoning
from modules.CPDoS import check_CPDoS
from modules.CVE import check_cpcve
from modules.header_checks.cachetag_header import check_cachetag_header

# header checks
from modules.header_checks.check_localhost import check_localhost
from modules.header_checks.http_version import check_http_version
from modules.header_checks.methods import check_methods
from modules.header_checks.server_error import get_server_error
from modules.header_checks.uncommon_header import get_http_headers
from modules.header_checks.vhosts import check_vhost

# others
from modules.logging_config import configure_logging
from modules.technologies import technology
from tools.autopoisoner.autopoisoner import check_cache_poisoning
from utils.style import Colors
from utils.utils import get_domain_from_url, requests, sys, time

# Global queue for multi-threaded processing
enclosure_queue: Queue[str] = Queue()

# Global variables for CLI arguments
human: str | None = None
url_file: str | None = None
custom_header: list[str] | None = None
behavior: bool | None = None
only_cp: bool | None = None
threads: int | None = None
authent: tuple[str, str] | None = None


def get_technos(a_tech: Any, req_main: Any, url: str, s: Any) -> None:
    """
    Check what is the reverse proxy/WAF/cached server... and test based on the result.
    #TODO Cloudfoundry => https://hackerone.com/reports/728664
    """
    print(f"{Colors.CYAN} ├ Techno analysis{Colors.RESET}")
    technos = {
        "apache": ["apache", "tomcat"],
        "nginx": ["nginx"],
        "envoy": ["envoy"],
        "akamai": [
            "akamai",
            "x-akamai",
            "x-akamai-transformed",
            "akamaighost",
            "akamaiedge",
            "edgesuite",
        ],
        "imperva": ["imperva"],
        "fastly": ["fastly"],
        "cloudflare": ["cf-ray", "cloudflare", "cf-cache-status", "cf-ray"],
        "vercel": ["vercel"],
        # "cloudfoundry": ["cf-app"]
    }

    for t in technos:
        tech_hit: str | bool = False
        for v in technos[t]:
            for rt in req_main.headers:
                # case-insensitive comparison
                if (
                    v.lower() in req_main.text.lower()
                    or v.lower() in req_main.headers[rt].lower()
                    or v.lower() in rt.lower()
                ):
                    tech_hit = t
        if tech_hit and isinstance(tech_hit, str):
            getattr(a_tech, tech_hit)(url, s)
            tech_hit = False


"""
def fuzz_x_header(url):
    When fuzzing for custom X-Headers on a target, a setup example as below can be combined with a dictionary/bruteforce attack. This makes it possible to extract hidden headers that the target uses.
        X-Forwarded-{FUZZ}
        X-Original-{FUZZ}
        X-{COMPANY_NAME}-{FUZZ}
    (https://blog.yeswehack.com/yeswerhackers/http-header-exploitation/)
    #TODO Really useful ?
"""


def process_modules(url: str, s: Any, a_tech: Any) -> None:
    domain = get_domain_from_url(url)
    resp_main_headers = []

    try:
        req_main = s.get(
            url, verify=False, allow_redirects=False, timeout=10, auth=authent
        )

        main_status_code = req_main.status_code
        main_head = req_main.headers
        main_len = len(req_main.content)

        print(f"{Colors.BLUE}⟙{Colors.RESET}")
        # print(s.headers)
        start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{Colors.SALMON}[STARTED]{Colors.RESET} {start_time}")
        print(f" URL: {url}")
        print(f" URL response: {req_main.status_code}")
        print(f" URL response size: {main_len} bytes")
        print(
            f" Proxy: {Colors.RED}OFF{Colors.RESET}"
            if not proxy.proxy_enabled
            else f" Proxy: {Colors.GREEN}ON{Colors.RESET}"
        )
        print(f"{Colors.BLUE}⟘{Colors.RESET}")
        if req_main.status_code not in [200, 302, 301, 403, 401] and not url_file:
            choice = input(
                f" {Colors.YELLOW}The url does not seem to answer correctly, continue anyway ?{Colors.RESET} [y/n]"
            )
            if choice not in ["y", "Y"]:
                sys.exit()
        for k in req_main.headers:
            resp_main_headers.append(f"{k}: {req_main.headers[k]}")

        if not only_cp:
            check_cachetag_header(resp_main_headers)
            get_server_error(url, authent)
            check_vhost(url)
            check_localhost(url, s, domain, authent)
            check_methods(url, custom_header, authent, human is not None)
            check_http_version(url)
            get_technos(a_tech, req_main, url, s)

        get_http_headers(url, s, main_status_code, main_len, main_head, authent)
        check_cpcve(
            url, s, req_main, parse_headers(custom_header), authent, human or ""
        )
        check_CPDoS(
            url, s, req_main, parse_headers(custom_header), authent, human or ""
        )
        check_methods_poisoning(url, s, parse_headers(custom_header), authent)
        check_cache_poisoning(
            url,
            parse_headers(custom_header),
            behavior or False,
            authent is not None,
            human or "",
        )
        check_cache_files(url, s, parse_headers(custom_header), authent)
        # fuzz_x_header(url) #TODO
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        pass
        # print(f"Error in processing {url}: {e}")


def parse_headers(header_list: list[str] | None) -> dict[str, str]:
    headers = {}
    if header_list:
        for header in header_list:
            if ":" in header:
                key, value = header.split(":", 1)
                headers[key.strip()] = value.strip()
    return headers


def main(urli: Any, s: Any, auth: str | None) -> None:
    global authent

    # DEBUG global completed_tasks

    a_tech = technology()

    if auth:
        from utils.utils import check_auth

        authent = check_auth(auth, urli)
    else:
        authent = None

    if url_file and threads != 1337:
        try:
            while True:
                try:
                    url = urli.get_nowait()
                except Empty:
                    break
                try:
                    process_modules(url, s, a_tech)
                except Exception as e:
                    # Log the error but continue processing
                    if hasattr(e, "__str__"):
                        print(f"Error processing URL {url}: {e}")
                finally:
                    urli.task_done()
        except KeyboardInterrupt:
            print(" ! Canceled by keyboard interrupt (Ctrl-C)")
            # Don't call task_done() here as it was already called in the finally block
            sys.exit()
        except Exception as e:
            print(f"Worker thread error: {e}")
            # Don't call task_done() here as it should be handled in the finally block
    else:
        try:
            process_modules(urli, s, a_tech)
        except KeyboardInterrupt:
            print(" ! Canceled by keyboard interrupt (Ctrl-C)")
            sys.exit()
        except Exception as e:
            print(f"Error : {e}")


def cli_main() -> None:
    """Entry point for the CLI command."""
    # Parse arguments
    results = args()

    # Make variables global so they can be accessed by process_modules
    global human, url_file, custom_header, behavior, only_cp, threads, authent

    url = results.url
    url_file = results.url_file
    custom_header = results.custom_header
    behavior = results.behavior
    auth = results.auth
    user_agent = results.user_agent
    threads = results.threads
    humans = results.humans
    custom_proxy = results.custom_proxy
    only_cp = results.only_cp

    configure_logging(results.verbose, results.log, results.log_file)

    human = humans

    try:
        s = requests.Session()
        s.verify = False
        s.max_redirects = 60

        s.headers.update(
            {
                "User-Agent": user_agent,
            }
        )

        if custom_header:
            try:
                custom_headers = parse_headers(custom_header)
                s.headers.update(custom_headers)
            except Exception as e:
                print(e)
                sys.exit()

        if custom_proxy:
            test_proxy = proxy.test_proxy_connection()
            if test_proxy:
                proxy.proxy_enabled = custom_proxy

        if url_file and threads != 1337:
            with open(url_file) as url_file_handle:
                urls = url_file_handle.read().splitlines()
            try:
                for url in urls:
                    enclosure_queue.put(url)
                worker_threads = []
                for _ in range(threads or 1):
                    worker = Thread(target=main, args=(enclosure_queue, s, auth))
                    worker.daemon = True
                    worker.start()
                    worker_threads.append(worker)
                # Add a timeout to prevent infinite waiting
                start_time = time.time()
                timeout = 300  # 5 minutes maximum

                while not enclosure_queue.empty():
                    if time.time() - start_time > timeout:
                        print("Warning: Queue processing timeout reached, forcing exit")
                        break
                    time.sleep(0.1)

                # Wait for worker threads to finish with timeout
                for worker in worker_threads:
                    worker.join(timeout=30)  # 30 second timeout per worker
            except KeyboardInterrupt:
                print("Exiting")
                sys.exit()
            except FileNotFoundError:
                print("Input file not found")
                sys.exit()
            except Exception as e:
                print(f"Error : {e}")
            print("Scan finish")
        elif url_file and threads == 1337:
            with open(url_file) as url_file_handle:
                urls = url_file_handle.read().splitlines()
                for url in urls:
                    main(url, s, auth)
        else:
            main(url, s, auth)
        # basic errors
    except KeyboardInterrupt:
        print("Exiting")
        sys.exit()
    # requests errors
    except requests.ConnectionError:
        print("Error, cannot connect to target")
    except requests.Timeout:
        print("Error, request timeout (10s)")
    except requests.exceptions.MissingSchema:
        print("Error, missing http:// or https:// schema")
    except Exception as e:
        print(f"Error : {e}")
    print("")


if __name__ == "__main__":
    cli_main()
