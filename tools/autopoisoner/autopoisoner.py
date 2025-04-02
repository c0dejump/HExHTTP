import requests
import argparse
import random
import re, os, sys
import time
import threading
import traceback
from tools.autopoisoner.headerfuzz import headersToFuzz
from modules.utils import human_time

currentPath = os.path.dirname(__file__)

from tools.autopoisoner.print_utils import *


LOCK = threading.Lock()
TIMEOUT_DELAY = 10

CANARY = "ndvyepenbvtidpvyzh.com"
CANARY_2 = "31337"

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
        if CANARY in val or CANARY_2 in val:
            return True
    if CANARY in response.text or CANARY_2 in response.text:
        return True

    return False

def crawl_files(URL, response : requests.Response):
    responseText = response.text
    regexp1 = r'(?<=src=")(\/[^\/].+?)(?=")'
    regexp2 = r'(?<=href=")(\/[^\/].+?)(?=")'

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
    if headers.get("X-Cache-Hits") or headers.get("X-Age") or headers.get("X-Nextjs-Cache") or headers.get("x-nextjs-cache") or headers.get("X-Vercel-Cache") or headers.get("x-vercel-cache") or headers.get("X-Cache") \
    or headers.get("x-drupal-cache") or headers.get("X-HS-CF-Cache-Status") or headers.get("Age") or headers.get("x-vanilla-cache-control") or headers.get("Cf-Cache-Status") \
    or headers.get("X-Proxy-Cache") or headers.get("X-TZLA-EDGE-Cache-Hit") or headers.get("X-nananana") or headers.get("x-spip-cache") or headers.get("CDN-Cache") \
    or headers.get("x-pangle-cache-from") or headers.get("X-Deploy-Web-Server-Cache-Hit") or headers.get("X-Micro-Cache") or headers.get("X-Deploy-Web-Server-Cache-Hit") \
    or (headers.get("Cache-Control") and ("public" in headers.get("Cache-Control"))):
        return True
    else:
        return False

def vulnerability_confirmed(responseCandidate : requests.Response, url, randNum, buster, custom_header):
    try:
        confirmationResponse = requests.get(f"{url}?cacheBusterX{randNum}={buster}", allow_redirects=False, verify=False, timeout=TIMEOUT_DELAY, headers=custom_header)
    except requests.Timeout:
        if behavior:
            print(f"Request timeout with {url} URL with {custom_header}")
        return False
    except Exception as e:
        #print(f"Error 95 line: {e}")
        ##traceback.print_exc()
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

def base_request(url, custom_header):
    randNum = str(random.randrange(999))
    buster = str(random.randrange(999))
    try:
        response = requests.get(f"{url}?cacheBusterX{randNum}={buster}", verify=False, allow_redirects=False, timeout=TIMEOUT_DELAY, headers=custom_header)
        #print(response)
        return response
    except Exception as e:
        #print(f"Error line 117 : {e}")
        #traceback.print_exc()
        return 1337


def port_poisoning_check(url, initialResponse, custom_header, human):
    randNum = str(random.randrange(999))
    buster = str(random.randrange(999))
    findingState = 0

    host = url.split("://")[1].split("/")[0]
    response = None
    custom_head = {
            "Host": f"{host}:8888",
            }
    uri = f"{url}?cacheBusterX{randNum}={buster}"
    if custom_header:
        custom_head = custom_head.update(custom_header)
    try:
        response = requests.get(f"{url}?cacheBusterX{randNum}={buster}", headers=custom_head, verify=False, allow_redirects=False, timeout=TIMEOUT_DELAY)
        human_time(human)
        explicitCache = str(use_caching(response.headers)).upper()

        if response.status_code != initialResponse.status_code and response.status_code != 429:
            status_codes = f"{initialResponse.status_code} → {response.status_code}"
            findingState = 1
            potential_verbose_message("STATUS_CODE", url)
            if vulnerability_confirmed(response, url, randNum, buster, custom_header):
                findingState = 2
                behavior_or_confirmed_message(uri, "CONFIRMED", "STATUS", explicitCache, url, status_codes=status_codes, header=custom_head, LOCK = LOCK)
            else:
                potential_verbose_message("UNSUCCESSFUL", url)
                if behavior:
                    behavior_or_confirmed_message(uri, "BEHAVIOR", "STATUS", explicitCache, url, status_codes=status_codes, header=custom_head)

        elif abs(len(response.text) - len(initialResponse.text)) > 0.85 * len(initialResponse.text):
            findingState = 1
            potential_verbose_message("LENGTH", url)
            if vulnerability_confirmed(response, url, randNum, buster, custom_header):
                findingState = 2
                behavior_or_confirmed_message(uri, "CONFIRMED", "LENGTH", explicitCache, url, header=custom_head, LOCK = LOCK)

        else:
            potential_verbose_message("UNSUCCESSFUL",  url)
            if behavior:
                behavior_or_confirmed_message(uri, "BEHAVIOR", "LENGTH", explicitCache, url, header=custom_head)

        if findingState == 1:
            return "UNCONFIRMED"
    except requests.Timeout:
        if behavior:
            print(f"Request timeout with {uri} URL with {custom_head}")
    except:
        print(f" └── Error with Host: {host}:8888 header")
        #traceback.print_exc()
        return None
    

def headers_poisoning_check(url, initialResponse, custom_header, human):
    findingState = 0
    for header in headersToFuzz.keys():
        payload = {header: headersToFuzz[header]}
        pp = payload.copy()
        pp.update({"user-agent": "xxxxxxxx"})
        randNum = str(random.randrange(999))
        buster = str(random.randrange(999))
        uri = f"{url}?cacheBusterX{randNum}={buster}"
        response = None
        try:
            response = requests.get(uri, headers=pp, verify=False, allow_redirects=False, timeout=TIMEOUT_DELAY)
            human_time(human)
        except KeyboardInterrupt:
            pass
        except requests.Timeout:
            if behavior:
                print(f"Request timeout with {uri} URL with {payload}")
            continue
        except requests.ConnectionError:
            continue
        except:
            if behavior:
                potential_verbose_message("ERROR", url)
                print(f"Request error with {uri} URL with {payload}")
                print("Error on the 179 Lines")
                #traceback.print_exc()
            continue
        explicitCache = str(use_caching(response.headers)).upper()
        sys.stdout.write(f"\033[34m  {header}\033[0m\r")
        sys.stdout.write("\033[K")

        if canary_in_response(response):
            findingState = 1
            potential_verbose_message("CANARY", url)
            if vulnerability_confirmed(response, url, randNum, buster, custom_header):
                findingState = 2
                behavior_or_confirmed_message(uri, "CONFIRMED", "REFLECTION", explicitCache, url, header=payload, LOCK = LOCK)

            else:
                potential_verbose_message("UNSUCCESSFUL", url)
                if behavior:
                    behavior_or_confirmed_message(uri, "BEHAVIOR", "REFLECTION", explicitCache, url, header=payload)

        elif response.status_code != initialResponse.status_code and response.status_code != 429:
            if response.status_code == 403:
                req = requests.get(url, allow_redirects=False, verify=False, timeout=TIMEOUT_DELAY, headers=custom_header)
                if req.status_code != 403:
                    status_codes = f"{initialResponse.status_code} → {response.status_code}"
                    findingState = 1
                    potential_verbose_message("STATUS_CODE", url)
                    if vulnerability_confirmed(response, url, randNum, buster, custom_header):
                        findingState = 2
                        behavior_or_confirmed_message(uri, "CONFIRMED", "STATUS", explicitCache, url, status_codes=status_codes, header=payload,LOCK = LOCK)
                    else:
                        potential_verbose_message("UNSUCCESSFUL", url)
                        if behavior:
                            behavior_or_confirmed_message(uri, "BEHAVIOR", "STATUS", explicitCache, url, status_codes=status_codes, header=payload)
                else:
                    pass
            else:        
                status_codes = f"{initialResponse.status_code} → {response.status_code}"
                findingState = 1
                potential_verbose_message("STATUS_CODE", url)
                if vulnerability_confirmed(response, url, randNum, buster, custom_header):
                    findingState = 2
                    behavior_or_confirmed_message(uri, "CONFIRMED", "STATUS", explicitCache, url, status_codes=status_codes, header=payload,LOCK = LOCK)
                else:
                    potential_verbose_message("UNSUCCESSFUL", url)
                    if behavior:
                        behavior_or_confirmed_message(uri, "BEHAVIOR", "STATUS", explicitCache, url, status_codes=status_codes, header=payload)

        elif abs(len(response.text) - len(initialResponse.text)) > 0.85 * len(initialResponse.text):
            findingState = 1
            potential_verbose_message("LENGTH", url)
            if vulnerability_confirmed(response, url, randNum, buster, custom_header):
                findingState = 2
                behavior_or_confirmed_message(uri, "CONFIRMED", "LENGTH", explicitCache, url, header=payload, LOCK = LOCK)
            else:
                potential_verbose_message("UNSUCCESSFUL", url)
                if behavior:
                    behavior_or_confirmed_message(uri, "BEHAVIOR", "LENGTH", explicitCache, url, header=payload)

    if findingState == 1:
        return "UNCONFIRMED"

def crawl_and_scan(url, initialResponse, custom_header, human):
    selectedURLS = crawl_files(url, initialResponse)
    for url in selectedURLS:
        potential_verbose_message("CRAWLING", url)
        initResponse = base_request(url, custom_header)
        port_poisoning_check(url, initResponse, custom_header, human)
        headers_poisoning_check(url, initResponse, custom_header, human)


def cache_poisoning_check(url, custom_header, human):
    initialResponse = base_request(url, custom_header)

    if initialResponse != 1337:
        if initialResponse.status_code in (200, 206, 301, 302, 303, 304, 307, 308, 400, 401, 402, 403, 404, 405, 406, 416, 500, 502, 503, 505, 520):
            resultPort = port_poisoning_check(url, initialResponse, custom_header, human)
            resultHeaders = headers_poisoning_check(url, initialResponse, custom_header, human)
            if resultHeaders == "UNCONFIRMED" or resultPort == "UNCONFIRMED":
                crawl_and_scan(url, initialResponse, custom_header, human)
        elif initialResponse and initialResponse.status_code == 429:
            time.sleep(3)
        else:
            print(f"Error 261: {initialResponse}")
            #traceback.print_exc()
            potential_verbose_message("ERROR", url)
            #return "ERROR"

"""def sequential_cache_poisoning_check(urlList):
    for url in urlList:
        cache_poisoning_check(url)"""

def check_cache_poisoning(url, custom_header, behavior_, authent, human):
    print("\033[36m ├ Cache poisoning analysis\033[0m")

    global behavior
    behavior = behavior_

    if url:
        try:
            cache_poisoning_check(url, custom_header, human)
        except KeyboardInterrupt:
            print(" ! Canceled by keyboard interrupt (Ctrl-C)")
            sys.exit()
        except Exception as e:
            print(f"Error 1: {e}")
            #traceback.print_exc()
    """elif file:
        try:
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
        except KeyboardInterrupt:
            print(" ! Canceled by keyboard interrupt (Ctrl-C)")
            sys.exit()"""

"""if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument("--file", "-f", type=str, required=False, help="file containing URLs to be tested")
    parser.add_argument("--url", "-u", type=str, required=False, help="url to be tested")
    parser.add_argument("--threads", "-n", type=int, required=False, help= 'number of threads for the tool')
    parser.add_argument("--output", "-o", type=str, required=False, help='output file path')
    parser.add_argument("--verbose", "-v", required=False, action='store_true', help="activate verbose mode")
    parser.add_argument("--behavior", "-b", required=False, action='store_true', help="activate a lighter version of verbose, highlighting interesting cache behavior") 

    args = parser.parse_args()
    if not (args.file or args.url):
        parser.error('No input selected: Please add --file or --url.')

    # if args.output:
    #     outputFile = open(args.output, "w")
    # else:
    #     pass
        # outputFile = open("output.txt", "w")

    if args.file :
        try:
            allURLs = [line.replace('\n', '') for line in open(args.file, "r")]
        except FileNotFoundError:
            print("Error, input file not found")
            sys.exit()
    check_cache_poisoning(args.url)"""
