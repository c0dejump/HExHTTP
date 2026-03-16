#!/usr/bin/env python3*

import sys
sys.dont_write_bytecode = True

from datetime import datetime
import time
from queue import Empty, Queue
from threading import Thread

# cp & cpdos
from modules.cachepoisoning.cache_poisoning_nf_files import check_cache_files
from modules.cachepoisoning.cache_poisoning import check_cache_poisoning
from modules.cpdos.fmp import check_methods_poisoning
from modules.CPDoS import check_CPDoS
from modules.CVE import check_cpcve
from modules.header_checks.cachetag_header import check_cachetag_header

# header checks
from modules.header_checks.scan_localhost import check_localhost
from modules.header_checks.scan_http_version import check_http_version
from modules.header_checks.scan_methods import check_methods
from modules.header_checks.scan_server_error import check_server_error
from modules.header_checks.scan_uncommon_header import check_uncommon_header
from modules.header_checks.scan_vhosts import check_vhost
from modules.header_checks.scan_debug_header import check_http_debug

# others
from modules.logging_config import configure_logging
from modules.Technology import get_technos, Technology

# utils
from cli import args
from utils.style import Colors
from utils.utils import (
    check_auth,
    configure_logger,
    get_domain_from_url,
    requests,
    verify_waf,
    fp_baseline,
    parse_headers,
    urllib3,
)
from utils.collect import init_url, update_url, add_finding, add_error, get_results
from utils.configure_session import build_session, clone_session
import utils.proxy as proxy

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = configure_logger(__name__)

# Global queue for multi-threaded processing
enclosure_queue: Queue[str] = Queue()

# Global variables for CLI arguments
human: str | None = None
url_file: str | None = None
custom_header: list[str] | None = None
only_cp: bool | None = None
threads: int | None = None


def process_modules(url: str, s: requests.Session, a_tech: Technology, auth: tuple[str, str] | None = None) -> None:
    resp_main_headers = []
    initStatusCode = 0
    initResponseLen = 0
    initHeader = {}
    detected_tech = "Unknown"

    # Register URL immediately — findings will be collected in real-time
    init_url(url)

    try:
        initResponse = s.get(
            url, verify=False, allow_redirects=False, timeout=10, auth=auth
        )

        initStatusCode = initResponse.status_code
        initHeader = initResponse.headers
        initResponseLen = len(initResponse.content)
        ph = parse_headers(custom_header)

        # Store status immediately — don't wait for finally
        cache_hdrs = {k: v for k, v in initHeader.items()
                      if 'cache' in k.lower() or k.lower() in
                      ('age', 'x-varnish', 'x-cache', 'cf-cache-status', 'x-cache-hits')}

        update_url(url, status_code=initStatusCode, response_size=initResponseLen, cache_headers=cache_hdrs)

        print(f"{Colors.BLUE} ⟙{Colors.RESET}")

        start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{Colors.SALMON}[STARTED]{Colors.RESET} {start_time}")
        print(f" URL: {url}")
        print(f" URL response: {Colors.GREEN}{initStatusCode}{Colors.RESET}") if initStatusCode == 200 else print(f" URL response: {Colors.YELLOW}{initStatusCode}{Colors.RESET}")
        print(f" URL response size: {initResponseLen} bytes")
        proxy_status = f" Proxy: {Colors.RED}OFF{Colors.RESET}"
        if proxy.proxy_enabled:
            proxy_status = f" Proxy: {Colors.GREEN}ON{Colors.RESET} ({proxy.proxy_url})"
        if proxy.burp_enabled:
            proxy_status += f" | Burp: {Colors.GREEN}ON{Colors.RESET} ({proxy.burp_url})"
        print(proxy_status)
        print(f" Auth : {Colors.RED}OFF{Colors.RESET}") if not auth else print(f" Auth: {auth}") 

        print(f"{Colors.BLUE} ⟘{Colors.RESET}")
        print(f"{Colors.BLUE} ⟙{Colors.RESET}")

        if initStatusCode not in [200, 302, 301] and not url_file:
            choice = input(
                f" {Colors.YELLOW}The url does not seem to answer correctly, continue anyway ?{Colors.RESET} [y/n]"
            )
            if choice not in ["y", "Y"]:
                return

        for k in initHeader:
            resp_main_headers.append(f"{k}: {initHeader[k]}")

        fp_results = fp_baseline(f"{url}?cb=123byc0dejump", s)

        if initStatusCode == 403 and url_file:
            return
        else:
            if not only_cp:
                check_cachetag_header(resp_main_headers)
                check_server_error(url, auth)
                check_vhost(url)
                check_localhost(url, s, get_domain_from_url(url), auth)
                check_methods(url, auth, human or "")
                check_http_version(url)
                verify_waf(url, s, initResponse)
                check_http_debug(url, s, initStatusCode, initResponseLen, initHeader, auth, human or "")
                verify_waf(url, s, initResponse)
                check_cpcve(url, s, initResponse, ph, auth, fp_results, human or "")

            detected_tech = get_technos(url, s, initResponse, a_tech) or "Unknown"

            check_uncommon_header(url, s, initResponse, dict(initHeader), fp_results, auth)
            check_CPDoS(url, s, initResponse, ph, auth, human or "")
            check_methods_poisoning(url, s, ph, auth)
            verify_waf(url, s, initResponse)
            check_cache_poisoning(url, s, ph, auth, human or "")
            check_cache_files(url, s, ph, auth)
        
    except requests.ConnectionError as e:
        add_error(url, str(e))
        if "Connection refused" in str(e):
            print(f"Error, connection refused by target host: {e}")
        else:
            print(f"Error, cannot connect to target: {e}")
    except requests.Timeout:
        add_error(url, "Request timeout (10s)")
        print("Error, request timeout (10s)")
    except requests.exceptions.MissingSchema:
        add_error(url, "Missing http:// or https:// schema")
        print("Error, missing http:// or https:// schema")
    except Exception as e:
        add_error(url, str(e))
        print(f"Error : {e}")
        logger.exception(f"hexhttp.py: {e}")
    finally:
        update_url(
            url=url,
            status_code=initStatusCode,
            response_size=initResponseLen,
            technology=detected_tech,
            cache_headers={k: v for k, v in initHeader.items() 
                          if 'cache' in k.lower() or k.lower() in 
                          ('age', 'x-varnish', 'x-cache', 'cf-cache-status', 'x-cache-hits')},
        )


def worker_main(s: requests.Session, auth: str | None) -> None:
    """Worker function for thread pool."""
    a_tech = Technology()
    
    while True:
        try:
            url = enclosure_queue.get_nowait()
        except Empty:
            break
        
        try:
            worker_session = clone_session()
            
            # Handle auth
            auth_tuple = check_auth(auth, url) if auth else None
            
            process_modules(url, worker_session, a_tech, auth_tuple)
            
        except Exception as e:
            logger.exception(f"Error processing URL {url}: {e}")
        finally:
            enclosure_queue.task_done()
            if 'worker_session' in locals():
                worker_session.close()


def create_report(parser, start_time_report):
    from modules.html_report import generate_html_report, build_scan_meta
    meta = build_scan_meta(parser, start_time_report)
    path = None if parser.output_html == 'default' else parser.output_html
    report = generate_html_report(get_results(), path, meta)
    print(f" Report saved: {report}")


def cli_main() -> None:
    """Entry point for the CLI command."""
    parser = args()

    global human, url_file, custom_header, only_cp, threads

    url = parser.url
    url_file = parser.url_file
    custom_header = parser.custom_header
    auth = parser.auth
    user_agent = parser.user_agent
    threads = parser.threads
    humans = parser.humans
    proxy_arg = parser.proxy
    burp_arg = parser.burp
    only_cp = parser.only_cp
    output_html = parser.output_html

    configure_logging(parser.verbose, parser.log, parser.log_file)

    human = humans
    start_time_report = time.time()

    try:
        s = build_session(parser)

        if url_file and threads != 1337:
            with open(url_file) as url_file_handle:
                urls = url_file_handle.read().splitlines()
            
            try:
                for url in urls:
                    enclosure_queue.put(url)
                
                worker_threads = []
                for _ in range(threads or 1):
                    worker = Thread(target=worker_main, args=(s, auth))
                    worker.daemon = True
                    worker.start()
                    worker_threads.append(worker)
                
                enclosure_queue.join()
                
                for worker in worker_threads:
                    worker.join(timeout=60)

            except KeyboardInterrupt:
                print("Exiting")
                if output_html:
                    create_report(parser, start_time_report)
                sys.exit()
            except FileNotFoundError:
                print("Input file not found")
                sys.exit()
            except Exception as e:
                logger.exception(e)
            print("Scan finish")
            
        elif url_file and threads == 1337:
            with open(url_file) as url_file_handle:
                urls = url_file_handle.read().splitlines()
                for url in urls:
                    auth_tuple = check_auth(auth, url) if auth else None
                    process_modules(url, s, Technology(), auth_tuple)
        else:
            auth_tuple = check_auth(auth, url) if auth else None
            process_modules(url, s, Technology(), auth_tuple)

        if output_html:
            create_report(parser, start_time_report)


    except KeyboardInterrupt:
        print("Exiting")
        if output_html:
            create_report(parser, start_time_report)
        sys.exit()
    except Exception as e:
        print(f"Error : {e}")
        logger.exception(e)
    print("")


if __name__ == "__main__":
    cli_main()