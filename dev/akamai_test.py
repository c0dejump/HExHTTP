import requests
from urllib.parse import urlencode

# Configuration des URL à tester
urls_to_test = [
    'https://www.dior.com',
    # Ajoutez d'autres URL à tester ici
]

# Headers spécifiques à tester
headers_to_test = [
    'User-Agent',
    'Referer',
    'Accept',
    'Origin'
]

# Valeurs à tester pour chaque header
test_values = {
    'User-Agent': ['bad-user-agent', 'Mozilla/5.0'],
    'Referer': ['invalid-url', 'https://www.example.com'],
    'Accept': ['application/invalid-type', 'text/html'],
    'Origin': ['invalid-origin', 'https://www.example.com']
}

# Génération de clés de cache fictives
def generate_cache_key(base_url, params):
    query_string = urlencode(params)
    cache_key = f"{base_url}?{query_string}"
    return cache_key

# Fonction pour tester une URL avec différents headers
def test_url_with_headers(url, headers, values):
    results = []
    for header, value_list in values.items():
        for value in value_list:
            response = requests.get(url, headers={header: value})
            result = {
                'url': url,
                'header': header,
                'value': value,
                'status_code': response.status_code,
                'headers': response.headers
            }
            results.append(result)
    return results

# Fonction pour analyser les résultats
def analyze_results(results):
    for result in results:
        url = result['url']
        header = result['header']
        value = result['value']
        status_code = result['status_code']
        response_headers = result['headers']

        print(f"URL: {url}")
        print(f"Header: {header}")
        print(f"Value: {value}")
        print(f"Status Code: {status_code}")
        
        if status_code >= 400:
            print("Potential issue detected: Response status code indicates an error.")
        
        # Vérification des headers spécifiques d'Akamai
        for akamai_header in ['x-cache', 'x-cache-key', 'x-true-cache-key', 'x-akamai-session-info']:
            if akamai_header in response_headers:
                print(f"{akamai_header}: {response_headers[akamai_header]}")
        
        print("-" * 40)

# Fonction principale
def main():
    for url in urls_to_test:
        # Génération de clés de cache fictives
        cache_key = generate_cache_key(url, {
            'PMUSER_X_DIOR_PCD_SFCC': 'FALSE',
            'PMUSER_IS_KNOWN_BOT': 'FALSE',
            'PMUSER_IS_INTERNET_EXPLORER': 'FALSE',
            'EDC_IS_MOBILE': 'false',
            'EDC_IS_TABLET': 'false'
        })
        print(f"Generated Cache Key: {cache_key}")

        # Test des URL avec différents headers
        results = test_url_with_headers(url, headers_to_test, test_values)
        
        # Analyse des résultats
        analyze_results(results)

if __name__ == "__main__":
    main()
