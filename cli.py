#!/usr/bin/env python3

import argparse

from modules.logging_config import valid_log_level
from static.banner import print_banner
from utils.style import Colors
from utils.utils import sys


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
        -b, --behavior (bool): Activates a simplified version of verbose,
            highlighting interesting cache behaviors.
        -t, --threads (int): Threads numbers for multiple URLs. Default: 10.
        -l, --log (str): Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
            Default: WARNING.
        -L, --log-file (str): The file path pattern for the log file.
            Default: ./logs/%Y%m%d_%H%M.log.
        -v, --verbose (int): Increase verbosity (can be used multiple times).
        -hu, --humans: Performs a timesleep to reproduce human behavior (Default: 0s) value: 'r' or 'random'
        -p, --proxy: proxy activation, can be modified in utils/proxy.py
        --ocp, --only-cp: Only cache poisoning modules

    If no argument is provided, the function will print the help message and exit.
    """
    parser = argparse.ArgumentParser(description=print_banner())

    group = parser.add_argument_group(Colors.BLUE + "> General" + Colors.RESET)
    group.add_argument(
        "-u",
        "--url",
        dest="url",
        help="URL to test " + Colors.RED + "[required]" + Colors.RESET,
    )
    group.add_argument(
        "-f", "--file", dest="url_file", help="File of URLs", required=False
    )
    group.add_argument(
        "-b",
        "--behavior",
        dest="behavior",
        help="Activates a simplified version of verbose, highlighting interesting cache behaviors",
        required=False,
        action="store_true",
    )

    group = parser.add_argument_group(Colors.BLUE + "> Request Settings" + Colors.RESET)
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
        default="Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0",
    )
    group.add_argument(
        "-a",
        "--auth",
        dest="auth",
        help="Add an HTTP authentication. "
        + Colors.YELLOW
        + "Ex: --auth admin:admin"
        + Colors.RESET,
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
        help="Threads numbers for multiple URLs. "
        + Colors.GREEN
        + "Default: 10"
        + Colors.RESET,
        type=int,
        default=10,
        required=False,
    )

    group = parser.add_argument_group(Colors.BLUE + "> Log settings" + Colors.RESET)
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
        help="The file path pattern for the log file. "
        + Colors.GREEN
        + "Default: logs/"
        + Colors.RESET,
        required=False,
    )
    group.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (can be used multiple times)",
    )

    group = parser.add_argument_group(Colors.BLUE + "> Tips" + Colors.RESET)
    group.add_argument(
        "-p",
        "--proxy",
        dest="custom_proxy",
        help="proxy activation, can be modified in utils/proxy.py",
        required=False,
        action="store_true",
    )
    group.add_argument(
        "--ocp",
        "--only-cp",
        dest="only_cp",
        help="Only cache poisoning modules",
        required=False,
        action="store_true",
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    return parser.parse_args()
