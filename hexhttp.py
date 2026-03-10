#!/usr/bin/env python3

from datetime import datetime
import time
from queue import Empty, Queue
from threading import Thread

# utils
import utils.proxy as proxy
from cli import args

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

from utils.style import Colors
from utils.utils import (
    check_auth,
    configure_logger,
    get_domain_from_url,
    requests,
    sys,
    verify_waf,
    fp_baseline,
    parse_headers,
    urllib3,
)
from utils.collect import init_url, update_url, add_finding, add_error, get_results

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
    domain = get_domain_from_url(url)
    resp_main_headers = []
    main_status_code = 0
    main_len = 0
    main_head = {}
    detected_tech = "Unknown"

    # Register URL immediately — findings will be collected in real-time
    init_url(url)

    try:
        req_main = s.get(
            url, verify=False, allow_redirects=False, timeout=10, auth=auth
        )

        main_status_code = req_main.status_code
        main_head = req_main.headers
        main_len = len(req_main.content)

        print(f"{Colors.BLUE} ⟙{Colors.RESET}")
        start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{Colors.SALMON}[STARTED]{Colors.RESET} {start_time}")
        print(f" URL: {url}")
        print(f" URL response: {Colors.GREEN}{main_status_code}{Colors.RESET}") if main_status_code == 200 else print(f" URL response: {Colors.YELLOW}{main_status_code}{Colors.RESET}")
        print(f" URL response size: {main_len} bytes")
        proxy_status = f" Proxy: {Colors.RED}OFF{Colors.RESET}"
        if proxy.proxy_enabled:
            proxy_status = f" Proxy: {Colors.GREEN}ON{Colors.RESET} ({proxy.proxy_url})"
        if proxy.burp_enabled:
            proxy_status += f" | Burp: {Colors.GREEN}ON{Colors.RESET} ({proxy.burp_url})"
        print(proxy_status)
        print(f"{Colors.BLUE} ⟘{Colors.RESET}")
        print(f"{Colors.BLUE} ⟙{Colors.RESET}")

        if main_status_code not in [200, 302, 301] and not url_file:
            choice = input(
                f" {Colors.YELLOW}The url does not seem to answer correctly, continue anyway ?{Colors.RESET} [y/n]"
            )
            if choice not in ["y", "Y"]:
                return

        for k in req_main.headers:
            resp_main_headers.append(f"{k}: {req_main.headers[k]}")

        req_main = s.get(
            url, verify=False, allow_redirects=False, timeout=10, auth=auth
        )

        fp_results = fp_baseline(f"{url}?cb=123byc0dejump", s)

        detected_tech = "Unknown"

        if not only_cp:
            check_cachetag_header(resp_main_headers)
            check_server_error(url, auth)
            check_vhost(url)
            check_localhost(url, s, domain, auth)
            check_methods(url, custom_header, auth, human or "")
            check_http_version(url)
            detected_tech = get_technos(url, s, req_main, a_tech) or "Unknown"
            verify_waf(url, s, req_main)
            check_http_debug(url, s, main_status_code, main_len, main_head, auth, human or "")
            verify_waf(url, s, req_main)
            check_cpcve(url, s, req_main, parse_headers(custom_header), auth, fp_results, human or "")

        check_uncommon_header(url, s, req_main, dict(main_head), fp_results, auth)
        check_CPDoS(url, s, req_main, parse_headers(custom_header), auth, human or "")
        check_methods_poisoning(url, s, parse_headers(custom_header), auth)
        verify_waf(url, s, req_main)
        check_cache_poisoning(url, s, parse_headers(custom_header), auth, human or "")
        check_cache_files(url, s, parse_headers(custom_header), auth)
        
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
            status_code=main_status_code,
            response_size=main_len,
            technology=detected_tech,
            cache_headers={k: v for k, v in main_head.items() 
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
            # Create a new session for each URL to avoid sharing issues
            worker_session = requests.Session()
            worker_session.verify = False
            worker_session.max_redirects = 60
            
            # Copy headers from main session
            worker_session.headers.update(dict(s.headers))
            
            # Copy proxies
            if hasattr(s, 'proxies') and s.proxies:
                worker_session.proxies = s.proxies.copy()
            
            # Handle auth
            auth_tuple = check_auth(auth, url) if auth else None
            
            process_modules(url, worker_session, a_tech, auth_tuple)
            
        except Exception as e:
            logger.exception(f"Error processing URL {url}: {e}")
        finally:
            enclosure_queue.task_done()
            if 'worker_session' in locals():
                worker_session.close()


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
    start_time = time.time()

    try:
        s = requests.Session()
        s.verify = False
        s.max_redirects = 60
        s.headers.update(
            {
                "User-Agent": f"{user_agent}-BugBounty-pagesjaunes/ywh",
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

        if custom_header:
            try:
                custom_headers = parse_headers(custom_header)
                s.headers.update(custom_headers)
            except Exception as e:
                logger.exception(e)
                print(f" Error in custom header format: {e}")
                sys.exit()

        # Handle proxy configuration
        if proxy_arg is not None or burp_arg is not None:
            if proxy_arg is not None:
                proxy.proxy_url = proxy.parse_proxy_url(proxy_arg)
                test_proxy = proxy.test_proxy_connection(proxy.proxy_url)
                if test_proxy:
                    proxy.proxy_enabled = True
                    print(f" Proxy configured: {proxy.proxy_url}")
                else:
                    print(f" {Colors.YELLOW}Proxy connection test failed, but continuing: {proxy.proxy_url}{Colors.RESET}")
                    proxy.proxy_enabled = True
            
            if burp_arg is not None:
                proxy.burp_url = proxy.parse_proxy_url(burp_arg)
                test_burp = proxy.test_proxy_connection(proxy.burp_url)
                if test_burp:
                    proxy.burp_enabled = True
                    print(f" Burp proxy configured: {proxy.burp_url}")
                else:
                    print(f" {Colors.RED}Burp proxy connection failed: {proxy.burp_url}{Colors.RESET}")
                    sys.exit(1)
            
            if burp_arg is not None and proxy_arg is None:
                proxy.proxy_enabled = True
                proxy.proxy_url = proxy.burp_url
            
            s.proxies = {"http": proxy.proxy_url, "https": proxy.proxy_url}

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
                    from modules.html_report import generate_html_report, build_scan_meta
                    meta = build_scan_meta(parser, start_time)
                    path = None if parser.output_html == 'default' else parser.output_html
                    report = generate_html_report(get_results(), path, meta)
                    print(f" Report: {report}")
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
            from modules.html_report import generate_html_report, build_scan_meta
            meta = build_scan_meta(parser, start_time)
            path = None if parser.output_html == 'default' else parser.output_html
            report = generate_html_report(get_results(), path, meta)
            print(f" Report: {report}")


    except KeyboardInterrupt:
        print("Exiting5")
        if output_html:
            from modules.html_report import generate_html_report, build_scan_meta
            meta = build_scan_meta(parser, start_time)
            path = None if parser.output_html == 'default' else parser.output_html
            report = generate_html_report(get_results(), path, meta)
            print(f" Report: {report}")
        sys.exit()
    except Exception as e:
        print(f"Error : {e}")
        logger.exception(e)
    print("")


if __name__ == "__main__":
    cli_main()