#!/usr/bin/env python3

from modules.logging_config import valid_log_level
from static.banner import run_banner
from utils.style import Colors
from utils.utils import argparse, sys, random

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    "(KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/118.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0"
]

DEFAULT_USER_AGENT = random.choice(USER_AGENTS)

def args() -> argparse.Namespace:
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
        -t, --threads (int): Threads numbers for multiple URLs. Default: 10.
        -l, --log (str): Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
            Default: WARNING.
        -L, --log-file (str): The file path pattern for the log file.
            Default: ./logs/%Y%m%d_%H%M.log.
        -v, --verbose (int): Increase verbosity (can be used multiple times).
        -hu, --humans: Performs a timesleep to reproduce human behavior (Default: 0s) value: 'r' or 'random'
        -p, --proxy: proxy all requests through this proxy (format: host:port, default: 127.0.0.1:8080)
        --burp: send behavior and confirmed requests to Burp proxy (format: host:port, default: 127.0.0.1:8080)
        --ocp, --only-cp: Only cache poisoning modules

    If no argument is provided, the function will print the help message and exit.
    """
    parser = argparse.ArgumentParser(description=run_banner())

    group = parser.add_argument_group(f"{Colors.BLUE}> General{Colors.RESET}")
    group.add_argument(
        "-u",
        "--url",
        dest="url",
        help=f"URL to test {Colors.RED}[required]{Colors.RESET} if no -f/--file provided",
    )
    group.add_argument(
        "-f",
        "--file",
        dest="url_file",
        help="File of URLs",
        required=False,
    )

    group = parser.add_argument_group(f"{Colors.BLUE}> Request Settings{Colors.RESET}")
    group.add_argument(
        "-H",
        "--header",
        dest="custom_header",
        help="Add a custom HTTP Header",
        action="append",
        required=False,
    )
    group.add_argument(
        "-A",
        "--user-agent",
        dest="user_agent",
        help="Add a custom User Agent",
        default=DEFAULT_USER_AGENT,
    )
    group.add_argument(
        "-a",
        "--auth",
        dest="auth",
        help=f"Add an HTTP authentication.{Colors.YELLOW} Ex: --auth admin:admin{Colors.RESET}",
        required=False,
    )
    group.add_argument(
        "-hu",
        "--humans",
        dest="humans",
        help="Performs a timesleep to reproduce human behavior (Default: 0s) value: 'r' or 'random'",
        default="0",
        required=False,
    )
    group.add_argument(
        "-t",
        "--threads",
        dest="threads",
        help=f"Threads numbers for multiple URLs. {Colors.GREEN}Default: 10{Colors.RESET}",
        type=int,
        default=10,
        required=False,
    )

    group = parser.add_argument_group(f"{Colors.BLUE}> Log settings{Colors.RESET}")
    group.add_argument(
        "-l",
        "--log",
        type=valid_log_level,
        default="WARNING",
        help="Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
    )
    group.add_argument(
        "-L",
        "--log-file",
        dest="log_file",
        default="./logs/%Y%m%d_%H%M.log",
        help=f"The file path pattern for the log file. {Colors.GREEN}Default: logs/{Colors.RESET}",
        required=False,
    )
    group.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (can be used multiple times)",
    )

    group = parser.add_argument_group(f"{Colors.BLUE}> Proxy Settings{Colors.RESET}")
    group.add_argument(
        "-p",
        "--proxy",
        dest="proxy",
        nargs='?',
        const='',  # Default value when --proxy is provided without argument
        help="Proxy all requests through this proxy (format: host:port, default: 127.0.0.1:8080)",
        required=False,
    )
    group.add_argument(
        "--burp",
        dest="burp",
        nargs='?',
        const='',  # Default value when --burp is provided without argument
        help="Send behavior and confirmed requests to Burp proxy (format: host:port, default: 127.0.0.1:8080)",
        required=False,
    )

    group = parser.add_argument_group(f"{Colors.BLUE}> Tips{Colors.RESET}")
    group.add_argument(
        "--ocp",
        "--only-cp",
        action="store_true",
        dest="only_cp",
        help="Only cache poisoning modules",
        required=False,
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    # Validate that either URL or file is provided
    if not args.url and not args.url_file:
        parser.error("Either -u/--url or -f/--file must be provided.")

    return args
