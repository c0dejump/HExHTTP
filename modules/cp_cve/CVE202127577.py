#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CVE-2021-27577 Detection Script
Apache Traffic Server URL Fragment Cache Poisoning Vulnerability
Affects: Apache Traffic Server 7.0.0-7.1.12, 8.0.0-8.1.1, 9.0.0-9.0.1
youst.in/posts/cache-poisoning-at-scale/
"""

import hashlib
from urllib.parse import urlparse
from utils.utils import configure_logger, requests, time, random, string
from utils.style import Colors

logger = configure_logger(__name__)

class CVE202127577Checker:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def generate_random_string(self, length=8):
        """Generate random string for unique identifiers"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    
    def detect_apache_traffic_server(self, url):
        """Detect if target is using Apache Traffic Server"""
        try:
            response = self.session.get(url, timeout=10)
            
            # Check Server header
            server_header = response.headers.get('Server', '').lower()
            if 'ats' in server_header or 'apache traffic server' in server_header:
                return True, f"Server header: {response.headers.get('Server')}"
            
            # Check for ATS-specific headers
            ats_headers = [
                'X-Cache-Status', 'X-Cache-Key', 'X-Cache-Generation',
                'ATS-Internal', 'X-ATS-Cache-Status'
            ]
            
            for header in ats_headers:
                if header in response.headers:
                    return True, f"ATS header detected: {header}"
            
            # Check Via header for ATS signature
            via_header = response.headers.get('Via', '').lower()
            if 'ats' in via_header or 'apache traffic server' in via_header:
                return True, f"Via header: {response.headers.get('Via')}"
                
            return False, "No ATS indicators found"
            
        except Exception as e:
            return False, f"Error detecting ATS: {e}"
    
    def test_fragment_cache_poisoning(self, url):
        """
        Test for CVE-2021-27577 URL fragment cache poisoning
        """
        results = []
        base_path = "/test_" + self.generate_random_string()
        
        # Test payloads with different fragment handling
        test_cases = [
            {
                'name': 'Basic Fragment Test',
                'url1': f"{url}{base_path}",
                'url2': f"{url}{base_path}#fragment",
                'description': 'Test if fragments affect cache keys'
            },
            {
                'name': 'Fragment with Cache-Busting',
                'url1': f"{url}{base_path}?v=1",
                'url2': f"{url}{base_path}?v=1#cachebust",
                'description': 'Test fragment impact on parameterized URLs'
            },
            {
                'name': 'Fragment Injection',
                'url1': f"{url}{base_path}",
                'url2': f"{url}{base_path}#/../admin",
                'description': 'Test path traversal via fragments'
            },
            {
                'name': 'Fragment with Special Characters',
                'url1': f"{url}{base_path}",
                'url2': f"{url}{base_path}#%2F..%2F",
                'description': 'Test encoded characters in fragments'
            },
            {
                'name': 'Fragment Cache Key Confusion',
                'url1': f"{url}{base_path}?cache=normal",
                'url2': f"{url}{base_path}?cache=normal#admin",
                'description': 'Test if fragments create different cache entries'
            }
        ]
        
        for test_case in test_cases:
            try:
                result = self.execute_fragment_test(test_case)
                results.append(result)
                time.sleep(0.5)  # Rate limiting
            except Exception as e:
                logger.error(f"Error in test {test_case['name']}: {e}")
                
        return results
    
    def execute_fragment_test(self, test_case):
        """Execute individual fragment cache poisoning test"""
        
        # Step 1: Prime cache with first URL
        try:
            resp1 = self.session.get(test_case['url1'], timeout=10)
            time.sleep(0.1)
            
            # Step 2: Request with fragment
            resp2 = self.session.get(test_case['url2'], timeout=10)
            time.sleep(0.1)
            
            # Step 3: Verify cache behavior
            resp3 = self.session.get(test_case['url1'], timeout=10)
            
            # Analyze responses
            analysis = self.analyze_fragment_responses(resp1, resp2, resp3, test_case)
            return analysis
            
        except Exception as e:
            return {
                'test_name': test_case['name'],
                'vulnerable': False,
                'error': str(e),
                'description': test_case['description']
            }
    
    def analyze_fragment_responses(self, resp1, resp2, resp3, test_case):
        """Analyze responses for cache poisoning indicators"""
        
        result = {
            'test_name': test_case['name'],
            'vulnerable': False,
            'confidence': 'Low',
            'details': {},
            'description': test_case['description']
        }
        
        # Check status codes
        statuses = [resp1.status_code, resp2.status_code, resp3.status_code]
        result['details']['status_codes'] = statuses
        
        # Check content lengths
        lengths = [len(resp1.content), len(resp2.content), len(resp3.content)]
        result['details']['content_lengths'] = lengths
        
        # Check cache headers
        cache_headers_1 = self.extract_cache_headers(resp1)
        cache_headers_2 = self.extract_cache_headers(resp2)
        cache_headers_3 = self.extract_cache_headers(resp3)
        
        result['details']['cache_headers'] = {
            'resp1': cache_headers_1,
            'resp2': cache_headers_2,
            'resp3': cache_headers_3
        }
        
        # Vulnerability indicators
        indicators = []
        
        # 1. Different cache status for URLs with/without fragments
        if (cache_headers_1.get('cache_status') != cache_headers_2.get('cache_status') and
            cache_headers_1.get('cache_status') and cache_headers_2.get('cache_status')):
            indicators.append("Different cache status for fragment URLs")
            result['vulnerable'] = True
        
        # 2. Fragment affecting cache key generation
        if (cache_headers_1.get('cache_key') != cache_headers_2.get('cache_key') and
            cache_headers_1.get('cache_key') and cache_headers_2.get('cache_key')):
            indicators.append("Fragments affecting cache key generation")
            result['vulnerable'] = True
        
        # 3. Response differences indicating cache confusion
        if (resp1.status_code == resp2.status_code == resp3.status_code and
            len(resp1.content) != len(resp2.content) and
            abs(len(resp1.content) - len(resp2.content)) > 100):
            indicators.append("Content length differences suggest cache confusion")
            result['vulnerable'] = True
        
        # 4. Cache hit/miss pattern anomalies
        cache_pattern = [
            cache_headers_1.get('cache_hit', False),
            cache_headers_2.get('cache_hit', False), 
            cache_headers_3.get('cache_hit', False)
        ]
        
        if cache_pattern == [False, False, True] or cache_pattern == [False, True, False]:
            indicators.append("Abnormal cache hit/miss pattern")
            result['vulnerable'] = True
        
        # 5. Age header inconsistencies
        ages = [
            cache_headers_1.get('age'),
            cache_headers_2.get('age'),
            cache_headers_3.get('age')
        ]
        
        if ages[0] is not None and ages[1] is not None:
            if abs(ages[0] - ages[1]) > 5:  # More than 5 seconds difference
                indicators.append("Age header inconsistencies")
                result['vulnerable'] = True
        
        result['indicators'] = indicators
        
        # Set confidence level
        if len(indicators) >= 3:
            result['confidence'] = 'High'
        elif len(indicators) >= 2:
            result['confidence'] = 'Medium'
        elif len(indicators) >= 1:
            result['confidence'] = 'Low'
            
        return result
    
    def extract_cache_headers(self, response):
        """Extract cache-related headers from response"""
        cache_info = {}
        
        # Cache status headers
        cache_status_headers = [
            'X-Cache-Status', 'X-Cache', 'CF-Cache-Status', 
            'X-Served-By', 'X-Cache-Lookup', 'X-ATS-Cache-Status'
        ]
        
        for header in cache_status_headers:
            if header in response.headers:
                cache_info['cache_status'] = response.headers[header]
                cache_info['cache_hit'] = 'hit' in response.headers[header].lower()
                break
        
        # Cache key
        if 'X-Cache-Key' in response.headers:
            cache_info['cache_key'] = response.headers['X-Cache-Key']
        
        # Age header
        if 'Age' in response.headers:
            try:
                cache_info['age'] = int(response.headers['Age'])
            except ValueError:
                pass
        
        # Via header for proxy detection
        if 'Via' in response.headers:
            cache_info['via'] = response.headers['Via']
            
        return cache_info
    
    def test_version_fingerprinting(self, url):
        """Attempt to fingerprint Apache Traffic Server version"""
        try:
            # Test with malformed requests that might reveal version info
            test_headers = {
                'X-Forwarded-For': '127.0.0.1',
                'Connection': 'close'
            }
            
            response = self.session.get(url, headers=test_headers, timeout=10)
            
            version_indicators = []
            
            # Check Server header for version
            server = response.headers.get('Server', '')
            if 'Apache Traffic Server' in server or 'ATS' in server:
                version_indicators.append(f"Server: {server}")
            
            # Check Via header for version info
            via = response.headers.get('Via', '')
            if 'ATS' in via:
                version_indicators.append(f"Via: {via}")
            
            return version_indicators
            
        except Exception as e:
            return [f"Version detection error: {e}"]

def apache_cp(url, authent=None):
    """
    Main function to check for CVE-2021-27577
    """
    #print(f"{Colors.CYAN} ├ CVE-2021-27577 Apache Traffic Server Cache Poisoning{Colors.RESET}")
    
    checker = CVE202127577Checker()
    
    # Step 1: Detect Apache Traffic Server
    is_ats, ats_info = checker.detect_apache_traffic_server(url)
    
    if not is_ats:
        return False
    
    print(f" ├── {Colors.GREEN}Apache Traffic Server detected{Colors.RESET}")
    print(f" │   └─ {ats_info}")
    
    # Step 2: Version fingerprinting
    version_info = checker.test_version_fingerprinting(url)
    if version_info:
        print(f" ├── Version indicators:")
        for info in version_info:
            print(f" │   └─ {info}")
    
    # Step 3: Test for URL fragment cache poisoning
    print(f" ├── Testing URL fragment cache poisoning...")
    
    test_results = checker.test_fragment_cache_poisoning(url)
    
    vulnerable_tests = [r for r in test_results if r.get('vulnerable', False)]
    
    if vulnerable_tests:
        print(f" ├── {Colors.RED}VULNERABLE to CVE-2021-27577{Colors.RESET}")
        print(f" │   └─ {len(vulnerable_tests)}/{len(test_results)} tests indicate vulnerability")
        
        for result in vulnerable_tests:
            print(f" ├── {Colors.RED}[{result['confidence']}]{Colors.RESET} {result['test_name']}")
            for indicator in result.get('indicators', []):
                print(f" │   └─ {indicator}")
                
        return True
    else:
        return False

# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python cve_2021_27577_check.py <URL>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    check_cve_2021_27577(target_url)