#!/usr/bin/env python3
import requests
import sys, time

class Colors:
    """Colors constants for the output messages"""

    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    SALMON = "\033[38;2;255;174;157m"
    THISTLE = "\033[38;2;197;197;169m"
    REDIR = "\033[38;2;245;203;92m"
    RESET = "\033[0m"


class Identify:
    behavior = f"{Colors.YELLOW}└──   INTERESTING BEHAVIOR  {Colors.RESET}"
    confirmed = f"{Colors.RED}└── VULNERABILITY CONFIRMED {Colors.RESET}"


def spinner(duration=5, message="        Waiting 2 min...", wait_count=0):
    chars = "|/-\\"
    end_time = time.time() + duration
    i = 0
    display_message = f"{message}+ {wait_count*2} (waf still present)" if wait_count > 0 else message
    while time.time() < end_time:
        sys.stdout.write(f"\r{display_message} {chars[i % len(chars)]}")
        sys.stdout.flush()
        i += 1
        time.sleep(0.1)
    sys.stdout.write("\r" + " " * (len(display_message) + 2) + "\r")