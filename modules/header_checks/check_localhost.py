#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Attemps to check if localhost can be scanned with Host Header
"""
from utils.utils import *
from utils.style import Colors
from collections import defaultdict

def check_localhost(url, s, domain, authent):
    list_test = [
        # Original list
        "127.0.0.1", "localhost", "192.168.0.1", "127.0.1", "127.1", "::1", "127.0.0.2", 
        "127.0.0.1", "127.0.0.1:22", "0.0.0.0", "0.0.0.0:443", "[::]:80", "127.0.0.1.nip.io", 
        "127.127.127.127",
        
        # Extended checks
        "[::1]", "[::1]:80", "[::1]:443", "192.168.1.1", "10.0.0.1", "172.16.0.1",
        "127.0.0.1:80", "127.0.0.1:443", "127.0.0.1:8080", "127.0.0.1:3306", 
        "127.0.0.1:5432", "127.0.0.1:6379", "127.0.0.1:27017", "localhost:22", 
        "localhost:3389", "localhost:8080", "127.0.0.1.xip.io", "localtest.me", 
        "lvh.me", "127.0.0.1.traefik.me", f"127.0.0.1.{domain}",
        "0x7f000001", "017700000001", "2130706433", "127.000.000.1", 
        "127.0.0.01", "127.0.0.001", "customer1.app.localhost", "admin.127.0.0.1.nip.io",
        "127.0.0.1.", "127.0.0.1/", "127.0.0.1#", "127.0.0.1?",
        "metadata.google.internal", "169.254.169.254", "consul.service.consul", 
        "vault.service.consul", "127.0.0.1:80@evil.com", "127.0.0.1#evil.com",
        "127.0.0.1 evil.com", "http://127.0.0.1/", "https://admin.localhost/",
        "127.0.0.1%00.evil.com", "127.0.0.1%0A", "localhost%2eevil%2ecom"
    ]
    
    print(f"{Colors.CYAN} ├ Host analysis{Colors.RESET}")
    
    results_tracker = defaultdict(list)
    
    for lt in list_test:
        headers = {"Host": lt}
        try:
            req = s.get(url, headers=headers, verify=False, allow_redirects=False, timeout=10)
            if req.status_code in [301, 302]:
                try:
                    req_redirect = s.get(url, headers=headers, verify=False, allow_redirects=True, timeout=10, auth=authent)
                    location = req.headers.get('location', 'No location')
                    result_key = (req.status_code, 'redirect', location)
                    results_tracker[result_key].append(lt)
                except:
                    location = req.headers.get('location', 'No location')
                    result_key = (req.status_code, 'redirect', location)
                    results_tracker[result_key].append(lt)
            else:
                result_key = (req.status_code, len(req.content))
                results_tracker[result_key].append(lt)
        except:
            pass
    
    # Display deduplicated results
    displayed_groups = set()
    
    for result_key, hosts_list in results_tracker.items():
        if len(hosts_list) >= 3:
            if result_key not in displayed_groups:
                first_host = hosts_list[0]
                if len(result_key) == 3:  # redirect case
                    status_code, _, location = result_key
                    print(f" ├── Host: {first_host:<25}{'→':^3} {status_code:>3}{'→':^3}{location} ({Colors.CYAN}+{len(hosts_list)-1} similar{Colors.RESET})")
                else:  # normal case
                    status_code, content_length = result_key
                    print(f" ├── Host: {first_host:<25}{'→':^3} {status_code:>3} [{content_length} bytes] ({Colors.CYAN}+{len(hosts_list)-1} similar{Colors.RESET})")
                displayed_groups.add(result_key)
        else:
            for lt in hosts_list:
                if len(result_key) == 3:  # redirect case
                    status_code, _, location = result_key
                    print(f" ├── Host: {lt:<25}{'→':^3} {status_code:>3}{'→':^3}{location}")
                else:  # normal case
                    status_code, content_length = result_key
                    print(f" ├── Host: {lt:<25}{'→':^3} {status_code:>3} [{content_length} bytes]")