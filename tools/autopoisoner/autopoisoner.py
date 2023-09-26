import requests
import argparse
import random
import re
import os
import sys
import threading

currentPath = os.path.dirname(__file__)

from tools.autopoisoner.print_utils import *

parser = argparse.ArgumentParser()
parser.add_argument("--file", "-f", type=str, required=False, help="file containing URLs to be tested")
parser.add_argument("--url", "-u", type=str, required=False, help="url to be tested")
parser.add_argument("--threads", "-n", type=int, required=False, help= 'number of threads for the tool')
parser.add_argument("--output", "-o", type=str, required=False, help='output file path')
parser.add_argument("--verbose", "-v", action='store_true', help="activate verbose mode")
parser.add_argument("--behavior", "-b", action='store_true', help="activate a lighter version of verbose, highlighting interesting cache behavior")

args = parser.parse_args()

LOCK = threading.Lock()
TIMEOUT_DELAY = 10

if not (args.file or args.url):
    parser.error('No input selected: Please add --file or --url.')

if args.output:
    outputFile = open(args.output, "w")
else:
    outputFile = open("output.txt", "w")

if args.file :
    try:
        allURLs = [line.replace('\n', '') for line in open(args.file, "r")]
    except FileNotFoundError:
       	print("Error, input file not found")
        sys.exit()

CANARY = "ndvyepenbvtidpvyzh.com"

headersToFuzz = {
    "x-forwarded-scheme": "http",
    "x-forwarded-host": CANARY,
    "x-forwarded-proto": "http",
    "x-http-method-override": "POST",
    "x-amz-website-redirect-location": CANARY,
    "x-rewrite-url": CANARY,
    "x-host": CANARY,
    "user-agent": CANARY,
    "handle": CANARY,
    "h0st": CANARY,
    "Transfer-Encoding": CANARY,
    "x-original-url": CANARY,
    "x-forwarded-prefix": CANARY,
    "x-amz-server-side-encryption": CANARY,
    "trailer": CANARY,
    "fastly-ssl": CANARY,
    "fastly-host": CANARY,
    "fastly-ff": CANARY,
    "fastly-client-ip": CANARY,
    "content-type": CANARY,
    "api-version": CANARY,
    "acunetix-header": CANARY,
    "accept-version": CANARY,
    "Access-Control-Allow-Origin": CANARY,
    "Base-Url": CANARY,
    "Cache_info": CANARY,
    "Cf-Connecting-Ip": CANARY,
    "Client-IP": CANARY,
    "Coming_from": CANARY,
    "Connect_via_ip": CANARY,
    "Forwarded-For-IP": CANARY,
    "Forwarded-For": CANARY,
    "Forwarded": CANARY,
    "Forwarded_for": CANARY,
    "Forwarded_for_ip": CANARY,
    "Forward-For": CANARY,
    "Forward_for": CANARY,
    "Http-Client-Ip": CANARY,
    "Http-Forwarded-For-Ip": CANARY,
    "Http-Pc-Remote-Addr": CANARY,
    "Http-Proxy-Connection": CANARY,
    "Http-Url": CANARY,
    "Http-Via": CANARY,
    "Http-Xroxy-Connection": CANARY,
    "Http-X-Forwarded-For-Ip": CANARY,
    "Http-X-Imforwards": CANARY,
    "Origin": CANARY,
    "Pc_remote_addr": CANARY,
    "Pragma": CANARY,
    "Proxy-Client-Ip": CANARY,
    "Proxy-Host": CANARY,
    "Proxy-Url": CANARY,
    "Proxy": CANARY,
    "Proxy_authorization": CANARY,
    "Proxy_connection": CANARY,
    "Real-Ip": CANARY,
    "Redirect": CANARY,
    "Referer": CANARY,
    "Remote_addr": CANARY,
    "Request-Uri": CANARY,
    "Source-Ip": CANARY,
    "True-Client-Ip": CANARY,
    "Uri": CANARY,
    "Url": CANARY,
    "Via": CANARY,
    "Wl-Proxy-Client-Ip": CANARY,
    "Xonnection": CANARY,
    "Xproxy": CANARY,
    "Xroxy_connection": CANARY,
    "X-Backend-Host": CANARY,
    "X-Bluecoat-Via": CANARY,
    "X-Cache-Info": CANARY,
    "X-Client-IP": CANARY,
    "X-Custom-IP-Authorization": CANARY,
    "X-Forwarded-By": CANARY,
    "X-Forwarded-For-Original": CANARY,
    "X-Forwarded-For": CANARY,
    "X-Forwarded-Host": CANARY,
    "X-Forwarded-Server": CANARY,
    "X-Forwarder-For": CANARY,
    "X-Forward-For": CANARY,
    "X-Forwared-Host": CANARY,
    "X-From-Ip": CANARY,
    "X-From": CANARY,
    "X-Gateway-Host": CANARY,
    "X-Http-Destinationurl": CANARY,
    "X-Http-Host-Override": CANARY,
    "X-Ip": CANARY,
    "X-Originally-Forwarded-For": CANARY,
    "X-Original-Remote-Addr": CANARY,
    "X-Originating-IP": CANARY,
    "X-Proxymesh-Ip": CANARY,
    "X-Proxyuser-Ip": CANARY,
    "X-Proxy-Url": CANARY,
    "X-Real-Ip": CANARY,
    "X-Remote-Addr": CANARY,
    "X-Remote-IP": CANARY,
    "X-Rewrite-Url": CANARY,
    "X-True-IP": CANARY,
    "X_cluster_client_ip": CANARY,
    "X_coming_from": CANARY,
    "X_delegate_remote_host": CANARY,
    "X_forwarded": CANARY,
    "X_forwarded_for_ip": CANARY,
    "X_imforwards": CANARY,
    "X_locking": CANARY,
    "X_looking": CANARY,
    "X_real_ip": CANARY,
    "Zcache_control": CANARY,
    "Z-Forwarded-For": CANARY 
}

def splitURLS(threadsSize): #Multithreading

    splitted = []
    URLSsize = len(allURLs)
    width = int(URLSsize/threadsSize)
    if width == 0:
        width = 1
    endVal = 0
    i = 0
    while endVal != URLSsize:
        if URLSsize <= i + 2 * width:
            if len(splitted) == threadsSize - 2:
                endVal = int(i + (URLSsize - i)/2)
            else:
                endVal = URLSsize
        else:
            endVal = i + width

        splitted.append(allURLs[i: endVal])
        i += width

    return splitted

def canary_in_response(response : requests.Response):
    for val in response.headers.values():
        if CANARY in val:
            return True
    if CANARY in response.text:
        return True

    return False

def crawl_files(URL, response : requests.Response):
    responseText = response.text
    regexp1 = '(?<=src=")(\/[^\/].+?)(?=")'
    regexp2 = '(?<=href=")(\/[^\/].+?)(?=")'

    filesURL = re.findall(regexp1, responseText)
    filesURL += re.findall(regexp2, responseText)

    selectedFiles = []

    #Select two random extensions

    if len(filesURL) >= 2:
        selectedFiles = random.sample(filesURL,2)
    elif len(filesURL) == 1:
        selectedFiles = [filesURL[0]]

    for i in range(len(selectedFiles)):
        selectedFiles[i] = URL + selectedFiles[i]

    return selectedFiles

def use_caching(headers):
    if headers.get("X-Cache-Hits") or headers.get("X-Vercel-Cache") or headers.get("x-vercel-cache") or headers.get("X-Cache") or headers.get("x-drupal-cache") \
    or headers.get("X-HS-CF-Cache-Status") or headers.get("Age") or headers.get("x-vanilla-cache-control") or headers.get("Cf-Cache-Status") \
    or (headers.get("Cache-Control") or headers.get("X-HS-CF-Cache-Status") or headers.get("X-nananana") or headers.get("X-Micro-Cache") and ("public" in headers.get("Cache-Control"))):
        return True
    else:
        return False

def vulnerability_confirmed(responseCandidate : requests.Response, url, randNum, buster):
    try:
        confirmationResponse = requests.get(f"{url}?cacheBusterX{randNum}={buster}", allow_redirects=False, timeout=TIMEOUT_DELAY)
    except:
        return False
    if confirmationResponse.status_code == responseCandidate.status_code and confirmationResponse.text == responseCandidate.text:
        if canary_in_response(responseCandidate):
            if canary_in_response(confirmationResponse):
                return True
            else:
                return False
        else:
            return True
    else:
        return False

def base_request(url):
    randNum = str(random.randrange(999))
    buster = str(random.randrange(999))
    try:
        response = requests.get(f"{url}?cacheBusterX{randNum}={buster}", allow_redirects=False, timeout=TIMEOUT_DELAY)
    except:
        return None

    return response

def port_poisoning_check(url, initialResponse):
    randNum = str(random.randrange(999))
    buster = str(random.randrange(999))
    findingState = 0

    host = url.split("://")[1].split("/")[0]
    response = None
    try:
        response = requests.get(f"{url}?cacheBusterX{randNum}={buster}", headers={"Host": f"{host}:8888"}, allow_redirects=False, timeout=TIMEOUT_DELAY)
        uri = f"{url}?cacheBusterX{randNum}={buster}"
    except:
        return
    explicitCache = str(use_caching(response.headers)).upper()

    if response.status_code != initialResponse.status_code:
        findingState = 1
        potential_verbose_message("STATUS_CODE", args, url)
        if vulnerability_confirmed(response, url, randNum, buster):
            findingState = 2
            behavior_or_confirmed_message(uri, "CONFIRMED", "STATUS", explicitCache, url, outputFile=outputFile,LOCK = LOCK)
        else:
            potential_verbose_message("UNSUCCESSFUL", args, url)
            if args.behavior:
                behavior_or_confirmed_message(uri, "BEHAVIOR", "STATUS", explicitCache, url)

    elif abs(len(response.text) - len(initialResponse.text)) > 0.25 * len(initialResponse.text):
        findingState = 1
        potential_verbose_message("LENGTH", args, url)
        if vulnerability_confirmed(response, url, randNum, buster):
            findingState = 2
            behavior_or_confirmed_message(uri, "CONFIRMED", "LENGTH", explicitCache, url , outputFile=outputFile, LOCK = LOCK)

        else:
            potential_verbose_message("UNSUCCESSFUL", args,  url)
            if args.behavior:
                behavior_or_confirmed_message(uri, "BEHAVIOR", "LENGTH", explicitCache, url)

    if findingState == 1:
        return "UNCONFIRMED"

def headers_poisoning_check(url, initialResponse):
    findingState = 0
    for header in headersToFuzz.keys():
        payload = {header: headersToFuzz[header]}
        randNum = str(random.randrange(999))
        buster = str(random.randrange(999))
        response = None
        try:
            response = requests.get(f"{url}?cacheBusterX{randNum}={buster}", headers=payload, allow_redirects=False, timeout=TIMEOUT_DELAY)
            uri = f"{url}?cacheBusterX{randNum}={buster}"
        except:
            potential_verbose_message("ERROR", args, url)
            print("Request error... Skipping the URL.")
            continue
        explicitCache = str(use_caching(response.headers)).upper()

        if canary_in_response(response):
            findingState = 1
            potential_verbose_message("CANARY", args, url)
            if vulnerability_confirmed(response, url, randNum, buster):
                findingState = 2
                behavior_or_confirmed_message(uri, "CONFIRMED", "REFLECTION", explicitCache, url, header=payload, outputFile=outputFile, LOCK = LOCK)

            else:
                potential_verbose_message("UNSUCCESSFUL", args, url)
                if args.behavior:
                    behavior_or_confirmed_message(uri, "BEHAVIOR", "REFLECTION", explicitCache, url, header=payload)

        elif response.status_code != initialResponse.status_code:
            findingState = 1
            potential_verbose_message("STATUS_CODE", args, url)
            if vulnerability_confirmed(response, url, randNum, buster):
                findingState = 2
                behavior_or_confirmed_message(uri, "CONFIRMED", "STATUS", explicitCache, url, header=payload, outputFile=outputFile,LOCK = LOCK)
            else:
                potential_verbose_message("UNSUCCESSFUL", args, url)
                if args.behavior:
                    behavior_or_confirmed_message(uri, "BEHAVIOR", "STATUS", explicitCache, url, header=payload)

        elif abs(len(response.text) - len(initialResponse.text)) > 0.25 * len(initialResponse.text):
            findingState = 1
            potential_verbose_message("LENGTH", args, url)
            if vulnerability_confirmed(response, url, randNum, buster):
                findingState = 2
                behavior_or_confirmed_message(uri, "CONFIRMED", "LENGTH", explicitCache, url, header=payload, outputFile=outputFile, LOCK = LOCK)
            else:
                potential_verbose_message("UNSUCCESSFUL", args, url)
                if args.behavior:
                    behavior_or_confirmed_message(uri, "BEHAVIOR", "LENGTH", explicitCache, url, header=payload)

    if findingState == 1:
        return "UNCONFIRMED"

def crawl_and_scan(url, initialResponse):
    selectedURLS = crawl_files(url, initialResponse)
    for url in selectedURLS:
        potential_verbose_message("CRAWLING", args, url)
        initResponse = base_request(url)
        port_poisoning_check(url, initResponse)
        headers_poisoning_check(url, initResponse)


def cache_poisoning_check(url):
    initialResponse = base_request(url)
    if not initialResponse:
        potential_verbose_message("ERROR", args, url)
        return

    if initialResponse.status_code in (200, 304, 302, 301, 401, 402, 403):
        resultPort = port_poisoning_check(url, initialResponse)
        resultHeaders = headers_poisoning_check(url, initialResponse)
        if resultHeaders == "UNCONFIRMED" or resultPort == "UNCONFIRMED":
            crawl_and_scan(url, initialResponse)

def sequential_cache_poisoning_check(urlList):

    for url in urlList:
        cache_poisoning_check(url)

def check_cache_poisoning(url_by_hexhttp=False):
    print("\033[36m ├ Cache poisoning analyse\033[0m")

    url = args.url if not url_by_hexhttp else url_by_hexhttp
    if url:
        try:
            cache_poisoning_check(url)
        except:
            print("\nInvalid URL")
    elif args.file:

        if not args.threads or args.threads == 1:
            sequential_cache_poisoning_check(allURLs)
        else:
            workingThreads = []
            split = splitURLS(args.threads)
            for subList in split:
                t = threading.Thread(target=sequential_cache_poisoning_check, args=[subList])
                workingThreads.append(t)
            for thread in workingThreads:
                thread.start()
            for thread in workingThreads:
                thread.join()
    outputFile.close()

if __name__ == '__main__':
    check_cache_poisoning(url_by_hexhttp)
