#!/usr/bin/env python3
"""
Attemps to check if localhost can be scanned with Host Header
"""

from utils.style import Colors
from utils.utils import requests


def check_localhost(
    url: str, s: requests.Session, domain: str, authent: tuple[str, str] | None
) -> None:
    list_test = [
        # Original list
        "127.0.0.1",
        "localhost",
        "192.168.0.1",
        "127.0.1",
        "127.1",
        "::1",
        "127.0.0.2",
        "127.0.0.1",
        "127.0.0.1:22",
        "0.0.0.0",  # nosec B104 - Test payload for localhost bypass testing
        "0.0.0.0:443",
        "[::]:80",
        "127.0.0.1.nip.io",
        "127.127.127.127",
        # Extended checks
        "[::1]",
        "[::1]:80",
        "[::1]:443",
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "127.0.0.1:80",
        "127.0.0.1:443",
        "127.0.0.1:8080",
        "127.0.0.1:3306",
        "127.0.0.1:5432",
        "127.0.0.1:6379",
        "127.0.0.1:27017",
        "localhost:22",
        "localhost:3389",
        "localhost:8080",
        "127.0.0.1.xip.io",
        "localtest.me",
        "lvh.me",
        "127.0.0.1.traefik.me",
        f"127.0.0.1.{domain}",
        "0x7f000001",
        "017700000001",
        "2130706433",
        "127.000.000.1",
        "127.0.0.01",
        "127.0.0.001",
        "customer1.app.localhost",
        "admin.127.0.0.1.nip.io",
        "127.0.0.1.",
        "127.0.0.1/",
        "127.0.0.1#",
        "127.0.0.1?",
        "metadata.google.internal",
        "169.254.169.254",
        "consul.service.consul",
        "vault.service.consul",
        "127.0.0.1:80@evil.com",
        "127.0.0.1#evil.com",
        "127.0.0.1 evil.com",
        "http://127.0.0.1/",
        "https://admin.localhost/",
        "127.0.0.1%00.evil.com",
        "127.0.0.1%0A",
        "localhost%2eevil%2ecom",
    ]

    print(f"{Colors.CYAN} ├ Host analysis{Colors.RESET}")

    results_tracker: dict[tuple, list] = {}

    for lt in list_test:
        headers = {"Host": lt}
        try:
            req = s.get(
                url, headers=headers, verify=False, allow_redirects=False, timeout=10
            )
            if req.status_code in [301, 302, 303, 307, 308]:
                try:
                    s.get(
                        url,
                        headers=headers,
                        verify=False,
                        allow_redirects=True,
                        timeout=10,
                        auth=authent,
                    )
                    location = req.headers.get("location", "No location")
                    redirect_key = (req.status_code, "redirect", location)
                    results_tracker[redirect_key].append(lt)
                except Exception:
                    location = req.headers.get("location", "No location")
                    redirect_key = (req.status_code, "redirect", location)
                    results_tracker[redirect_key].append(lt)
            else:
                normal_key = (req.status_code, len(req.content))
                results_tracker[normal_key].append(lt)
            print(f" ├─ {Colors.BLUE}{lt}:{req.status_code}{Colors.RESET}\r", end="")
            print("\033[K", end="")
        except Exception:
            pass

    # Display deduplicated results
    displayed_groups: set[tuple] = set()

    for result_key, hosts_list in results_tracker.items():
        # Unpack result_key once and determine format
        is_redirect = len(result_key) == 3
        if is_redirect:
            status_code, _, location = result_key
            result_info = f"{status_code:>3}{'→':^3}{location}"
        else:
            status_code, content_length = result_key
            result_info = f"{status_code:>3} [{content_length} bytes]"

        # Handle grouped results (3+ similar hosts)
        if len(hosts_list) >= 3 and result_key not in displayed_groups:
            first_host = hosts_list[0]
            similar_count = len(hosts_list) - 1
            print(
                f" ├── Host: {first_host:<25}{'→':^3} {result_info} ({Colors.CYAN}+{similar_count} similar{Colors.RESET})"
            )
            displayed_groups.add(result_key)
        # Handle individual results (< 3 hosts)
        elif len(hosts_list) < 3:
            for host in hosts_list:
                print(f" ├── Host: {host:<25}{'→':^3} {result_info}")
