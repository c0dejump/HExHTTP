#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import traceback

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def basic_poisoning(url, matching_forward):
	headers = {
	    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
	    'X-Forwarded-Host': matching_forward,
		}

	params = {
	    'cp': '1337',
		}
	res_header = {}
	#print(" - {}?cp={}".format(url, params["cp"])) #Debug

	for i in range(10):
		res = requests.get(url, params=params, headers=headers, verify=False, allow_redirects=False)
		for cs in res.headers:
			if "Cache-Status" in cs or "X-Cache" in cs or "x-drupal-cache" in cs:
				#print(res.headers) #Debug
				if res.headers[cs] == "HIT" or res.headers[cs] == "hit":
					#print("HEADSHOT !!!") #Debug
					res_header = res.headers

	#print(res_header) Debug

	if res_header:
		print(" --├ {}?cp={} response with a HIT Cache-Status".format(url, params["cp"]))	
		url_param = "{}?cp={}".format(url, params["cp"])

		req_verify_redirect = requests.get(url, params=params, verify=False)
		req_verify_url = requests.get(url, verify=False, allow_redirects=True)

		if req_verify_redirect.status_code in [301, 302] or req_verify_url.status_code in [301, 302]:
			if matching_forward in req_verify_redirect.url or matching_forward in req_verify_url.url:
				print("  \033[31m └── Cache poisoning on {} seem work, the redirection to \"google.com\" seems work ! \033[0m".format(url_param))

		elif matching_forward in req_verify_redirect.text or matching_forward in req_verify_url.text:
			print("  \033[31m └── Cache poisoning on {} seem work, double-check on the page to see if \"google.com\" is staying and have fun ! \033[0m".format(url_param))
		#print(req_verify_redirect.status_code) #Debug



def check_cache_poisoning(uri):
	
	print("\033[36m ├ Basic cache poisoning analyse\033[0m")

	matching_forward = "google.com"

	for endpoints in ["test.js", "test.css",""]:
		url = "{}{}".format(uri, endpoints)
		basic_poisoning(url, matching_forward)