#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import argparse
import re

from modules.utils import *

#header checks
from modules.header_checks.check_localhost import check_localhost
from modules.header_checks.methods import check_methods
from modules.header_checks.http_version import check_http_version
from modules.header_checks.vhosts import check_vhost

#cp & cpdos
from modules.cp_check.cache_poisoning_nf_files import check_cache_files
from modules.cp_cve.CVE202446982 import datareq_check
from modules.CPDoS import check_CPDoS
from modules.CVE import check_cpcve
from tools.autopoisoner.autopoisoner import check_cache_poisoning

#others
from modules.logging_config import valid_log_level, configure_logging
from modules.server_error import get_server_error
from modules.technologies import technology
from modules.cookie_reflection import check_cookie_reflection


if sys.version_info[0] < 3:
    from Queue import Queue
else:
    import queue as Queue

import threading
from threading import Thread

from static.banner import print_banner

try:
    enclosure_queue = Queue()
except:
    enclosure_queue = Queue.Queue()

# DEBUG completed_tasks = 0
# DEBUG lock = threading.Lock()


def args():
    """
    Parses command-line arguments and returns them.

    This function uses argparse to define and parse command-line arguments for the script.
    It includes options for specifying a URL, a file of URLs, custom HTTP headers, user agents,
    authentication, verbosity, logging, and threading.

    Returns:
        argparse.Namespace: Parsed command-line arguments.

    Arguments:
        -u, --url (str): URL to test [required].
        -f, --file (str): File of URLs.
        -H, --header (str): Add a custom HTTP Header.
        -A, --user-agent (str): Add a custom User Agent.
        -a, --auth (str): Add an HTTP authentication. Ex: --auth admin:admin.
        -b, --behavior (bool): Activates a simplified version of verbose,
            highlighting interesting cache behaviors.
        -t, --threads (int): Threads numbers for multiple URLs. Default: 10.
        -l, --log (str): Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
            Default: WARNING.
        -L, --log-file (str): The file path pattern for the log file.
            Default: ./logs/%Y%m%d_%H%M.log.
        -v, --verbose (int): Increase verbosity (can be used multiple times).

    If no argument is provided, the function will print the help message and exit.
    """
    parser = argparse.ArgumentParser(description=print_banner())

    parser.add_argument(
        "-u", "--url", dest="url", help="URL to test \033[31m[required]\033[0m"
    )
    parser.add_argument(
        "-f", "--file", dest="url_file", help="File of URLs", required=False
    )
    parser.add_argument(
        "-H",
        "--header",
        dest="custom_header",
        help="Add a custom HTTP Header",
        required=False,
    )
    parser.add_argument(
        "-A",
        "--user-agent",
        dest="user_agent",
        help="Add a custom User Agent",
        required=False,
    )
    parser.add_argument(
        "-a",
        "--auth",
        dest="auth",
        help="Add an HTTP authentication. \033[33mEx: --auth admin:admin\033[0m",
        required=False,
    )
    parser.add_argument(
        "-b",
        "--behavior",
        dest="behavior",
        help="Activates a simplified version of verbose, highlighting interesting cache behaviors",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "-hu",
        "--humans",
        dest="humans",
        help="Performs a timesleep to reproduce human behavior (Default: 0s) value: 'r' or 'random'",
        default="0",
        required=False,
    )
    parser.add_argument(
        "-t",
        "--threads",
        dest="threads",
        help="Threads numbers for multiple URLs. \033[32mDefault: 10\033[0m",
        type=int,
        default=10,
        required=False,
    )
    parser.add_argument(
        "-l",
        "--log",
        type=valid_log_level,
        default="WARNING",
        help="Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
    )
    parser.add_argument(
        "-L",
        "--log-file",
        dest="log_file",
        default="./logs/%Y%m%d_%H%M.log",
        help="The file path pattern for the log file. \033[32mDefault: logs/\033[0m",
        required=False,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (can be used multiple times)",
    )
    parser.add_argument(
        "-p",
        "--proxy",
        dest="custom_proxy",
        help="Add a custom proxy. Ex: http://127.0.0.1:8080 [In Progress]",
        required=False,
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    return parser.parse_args()


def get_technos(a_tech, req_main, url, s):
    """
    Check what is the reverse proxy/WAF/cached server... and test based on the result.
    #TODO Cloudfoundry => https://hackerone.com/reports/728664
    """
    print("\033[36m ├ Techno analysis\033[0m")
    technos = {
        "apache": ["apache", "tomcat"],
        "nginx": ["nginx"],
        "envoy": ["envoy"],
        "akamai": ["akamai", "x-akamai", "x-akamai-transformed", "akamaighost"],
        "imperva": ["imperva"],
        "fastly": ["fastly"],
        "cloudflare": ["cf-ray", "cloudflare", "cf-cache-status", "cf-ray"],
        "vercel": ["vercel"],
        # "cloudfoundry": ["cf-app"]
    }

    for t in technos:
        tech_hit = False
        for v in technos[t]:
            for rt in req_main.headers:
                # case-insensitive comparison
                if (
                    v.lower() in req_main.text.lower()
                    or v.lower() in req_main.headers[rt].lower()
                    or v.lower() in rt.lower()
                ):
                    tech_hit = t
        if tech_hit:
            techno_result = getattr(a_tech, tech_hit)(url, s)
            tech_hit = False


def fuzz_x_header(url):
    """
    When fuzzing for custom X-Headers on a target, a setup example as below can be combined with a dictionary/bruteforce attack. This makes it possible to extract hidden headers that the target uses.
        X-Forwarded-{FUZZ}
        X-Original-{FUZZ}
        X-{COMPANY_NAME}-{FUZZ}
    (https://blog.yeswehack.com/yeswerhackers/http-header-exploitation/)
    #TODO
    """
    pass


def check_cachetag_header(url, req_main):
    print("\n\033[36m ├ Header cache tags\033[0m")
    # basic_header = ["Content-Type", "Content-Length", "Date", "Content-Security-Policy", "Alt-Svc", "Etag", "Referrer-Policy", "X-Dns-Prefetch-Control", "X-Permitted-Cross-Domain-Policies"]

    result = []
    for headi in base_header:
        if "cache" in headi or "Cache" in headi:
            result.append(f"{headi.split(':')[0]}:{headi.split(':')[1]}")
    for vary in base_header:
        if "Vary" in vary:
            result.append(f"{vary.split(':')[0]}:{vary.split(':')[1]}")
    for age in base_header:
        if age == "age" or age == "Age":
            result.append(f"{age.split(':')[0]}:{age.split(':')[1]}")
    for get_custom_header in base_header:
        if "Access" in get_custom_header:
            result.append(
                f"{get_custom_header.split(':')[0]}:{get_custom_header.split(':')[1]}"
            )
    for get_custom_host in base_header:
        if "host" in get_custom_header:
            result.append(
                f"{get_custom_host.split(':')[0]}:{get_custom_host.split(':')[1]}"
            )
    for r in result:
        print(f" └──  {r:<30}")


def check_auth(auth, url):
    try:
        authent = (auth.split(":")[0], auth.split(":")[1])
        r = requests.get(
            url, allow_redirects=False, verify=False, auth=authent, timeout=10
        )
        if r.status_code in [200, 302, 301]:
            print("\n+ Authentication successfull\n")
            return authent
        else:
            print("\nAuthentication error")
            continue_error = input(
                "The authentication seems bad, continue ? [y/N]"
            )
            if continue_error not in ["y", "Y"]:
                print("Exiting")
                sys.exit()
    except Exception as e:
        traceback.print_exc()
        print('Error, the authentication format need to be "user:pass"')
        sys.exit()



def process_modules(url, s, a_tech):
    domain = get_domain_from_url(url)

    try:
        req_main = s.get(
            url, verify=False, allow_redirects=False, timeout=10, auth=authent
        )

        print("\033[34m⟙\033[0m")
        print(f" URL: {url}")
        print(f" URL response: {req_main.status_code}")
        print(f" URL response size: {len(req_main.content)} bytes")
        print("\033[34m⟘\033[0m")
        if req_main.status_code not in [200, 302, 301, 403, 401] and not url_file:
            choice = input(
                " \033[33mThe url does not seem to answer correctly, continue anyway ?\033[0m [y/n]"
            )
            if choice not in ["y", "Y"]:
                sys.exit()
        for k in req_main.headers:
            base_header.append(f"{k}: {req_main.headers[k]}")

        check_cachetag_header(url, req_main)
        get_server_error(url, base_header, authent, url_file)
        check_vhost(domain, url)
        check_localhost(url, s, domain, authent)
        check_methods(url, custom_header, authent)
        check_http_version(url)
        check_CPDoS(url, s, req_main, domain, custom_header, authent, human)
        check_cpcve(url, s, req_main, domain, custom_header, authent, human)
        check_cache_poisoning(url, custom_header, behavior, authent, human)
        check_cache_files(url, s, custom_header, authent) #TOREDO
        check_cookie_reflection(url, custom_header, authent)
        techno = get_technos(a_tech, req_main, url, s)
        #fuzz_x_header(url) #TODO
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        pass
        # print(f"Error in processing {url}: {e}")


def main(urli, s, auth):
    global base_header
    global authent
    base_header = []

    # DEBUG global completed_tasks

    a_tech = technology()

    if auth:
        authent = check_auth(auth, urli)
    else:
        authent = False

    if url_file and threads != 1337:
        try:
            while not urli.empty():
                q = urli

                url = urli.get()
                process_modules(url, s, a_tech)
                # with lock: #Debug
                # completed_tasks += 1
                # print(f"completed tasks : {completed_tasks}")
                q.task_done()
        except KeyboardInterrupt:
            print(" ! Canceled by keyboard interrupt (Ctrl-C)")
            q.task_done()
            sys.exit()
        except Exception as e:
            pass
            # print(f"Error : {e}")
            q.task_done()
    elif url_file and threads == 1337:
        try:
            process_modules(urli, s, a_tech)
        except KeyboardInterrupt:
            print(" ! Canceled by keyboard interrupt (Ctrl-C)")
            sys.exit()
        except Exception as e:
            print(f"Error : {e}")
    else:
        try:
            process_modules(urli, s, a_tech)
        except KeyboardInterrupt:
            print(" ! Canceled by keyboard interrupt (Ctrl-C)")
            sys.exit()
        except Exception as e:
            print(f"Error : {e}")


if __name__ == "__main__":
    # Parse arguments
    results = args()

    url = results.url
    url_file = results.url_file
    custom_header = results.custom_header
    behavior = results.behavior
    auth = results.auth
    user_agent = results.user_agent
    threads = results.threads
    humans = results.humans
    proxy = results.custom_proxy

    configure_logging(results.verbose, results.log, results.log_file)

    global human

    human = humans

    try:
        s = requests.Session()
        if user_agent:
            s.headers.update({"User-agent": user_agent})
        else:
            s.headers.update(
                {
                    "User-agent": "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko",
                    #"Accept": "html",
                    "Accept-Encoding": "gzip"
                }
            )

        if custom_header:
            try:
                custom_header = custom_header.replace(" ", "")
                custom_header = {
                    custom_header.split(":")[0]: custom_header.split(":")[1]
                }
                s.headers.update(custom_header)
            except Exception as e:
                print(e)
                print('Error, HTTP Header format need to be "foo:bar"')
                sys.exit()
        if proxy:
            proxies = {
                'https': proxy,
            }
            s.proxies.update(proxies)

        s.max_redirects = 60

        if url_file and threads != 1337:
            with open(url_file, "r") as urls:
                urls = urls.read().splitlines()
            try:
                for url in urls:
                    enclosure_queue.put(url)
                for i in range(threads):
                    worker = Thread(target=main, args=(enclosure_queue, s, auth))
                    worker.start()
                enclosure_queue.join()
                for thread in threads:
                    thread.join()
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
            with open(url_file, "r") as urls:
                urls = urls.read().splitlines()
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
    # print("Scan finish")
