#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import argparse
import re

from modules.utils import *
from modules.logging_config import valid_log_level, configure_logging
from modules.check_localhost import check_localhost
from modules.server_error import get_server_error
from modules.methods import check_methods
from modules.CPDoS import check_CPDoS
from modules.technologies import technology
from modules.cache_poisoning_files import check_cache_files
from modules.cookie_reflection import check_cookie_reflection
from modules.http_version import check_http_version
from modules.vhosts import check_vhost

from tools.autopoisoner.autopoisoner import check_cache_poisoning

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
        -F, --full (bool): Display the full HTTP Header.
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
        "-F",
        "--full",
        dest="full",
        help="Display the full HTTP Header",
        required=False,
        action="store_true",
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



def check_cache_header(url, req_main):
    print("\033[36m ├ Header cache\033[0m")
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

        get_server_error(url, base_header, full, authent, url_file)
        check_vhost(domain, url)
        check_localhost(url, s, domain, authent)
        check_methods(url, custom_header, authent)
        check_http_version(url)
        check_CPDoS(url, s, req_main, domain, custom_header, authent)
        check_cache_poisoning(url, custom_header, behavior, authent)
        check_cache_files(url, custom_header, authent)
        check_cookie_reflection(url, custom_header, authent)
        techno = get_technos(a_tech, req_main, url, s)
        # fuzz_x_header(url) #TODO
        check_cache_header(url, req_main)
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        pass
        # print(f"Error in processing {url}: {e}")


def main(urli, s):
    global base_header
    base_header = []

    # DEBUG global completed_tasks

    a_tech = technology()

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
    full = results.full
    custom_header = results.custom_header
    behavior = results.behavior
    auth = results.auth
    user_agent = results.user_agent
    threads = results.threads

    configure_logging(results.verbose, results.log, results.log_file)

    global authent

    try:
        if auth:
            try:
                authent = (auth.split(":")[0], auth.split(":")[1])
                r = requests.get(
                    url, allow_redirects=False, verify=False, auth=authent, timeout=10
                )
                if r.status_code in [200, 302, 301]:
                    print("\n+ Authentication successfull\n")
                else:
                    print("\nAuthentication error")
                    continue_error = input(
                        "The authentication seems bad, continue ? [y/N]"
                    )
                    if continue_error not in ["y", "Y"]:
                        print("Exiting")
                        sys.exit()
            except Exception as e:
                print('Error, the authentication format need to be "user:pass"')
                sys.exit()
        else:
            authent = False

        s = requests.Session()
        if user_agent:
            s.headers.update({"User-agent": user_agent})
        else:
            s.headers.update(
                {
                    "User-agent": "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko"
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

        s.max_redirects = 60

        if url_file and threads != 1337:
            with open(url_file, "r") as urls:
                urls = urls.read().splitlines()
            try:
                for url in urls:
                    enclosure_queue.put(url)
                for i in range(threads):
                    worker = Thread(target=main, args=(enclosure_queue, s))
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
                    main(url, s)
        else:
            main(url, s)
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
