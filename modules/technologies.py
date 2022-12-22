#! /usr/bin/env python3
# -*- coding: utf-8 -*-

class technology:
	"""
	forwarded:
		nginx:
        	X-Real-IP
        	Forwarded
    	apache:
        	X-Forwarded-Server
        	X-Real-IP
        	Max-Forwards
    	Envoy:
        	X-Envoy-external-adress
        	X-Envoy-internal
        	X-Envoy-Original-Dst-Host
    Unkeyed Query Exploitation:
    	Apache: // | //?"><script>
		Nginx: /%2F | /%2F?"><u>
		PHP: /index.php/xyz
		.NET: /(A(xyz))/
    """

	def apache(self, url, s):
		print("\033[36m --├ Apache analyse\033[0m")
		uqe_url = '{}/?"><u>plop123</u>'.format(url)
		uqe_req = s.get(uqe_url, verify=False, timeout=6)
		if uqe_req not in [403, 401, 400, 500]:
			if "plop123" in uqe_req.text:
				print("coucou")
		apache_headers = [{"X-Forwarded-Server": "plop123"}, {"X-Real-IP": "plop123"}, {"Max-Forwards": "plop123"}]
		for aph in apache_headers:
			x_req = s.get(url, headers=aph, verify=False, timeout=10)
			print(f" └── {aph}{'→':^3} {x_req.status_code:>3}")
			if "plop123" in x_req.text:
				print("wooow")

	def nginx(self, url, s):
		# Unkeyed Query Exploitation:
		print("\033[36m --├ Nginx analyse\033[0m")
		uqe_url = '{}%2F?"><u>plop123</u>'.format(url)
		uqe_req = s.get(uqe_url, verify=False, timeout=6)
		if uqe_req not in [403, 401, 400, 500]:
			if "plop123" in uqe_req.text:
				print("coucou")
		nginx_headers = [{"X-Real-IP": "plop123"}, {"Forwarded": "plop123"}]
		for ngh in nginx_headers:
			x_req = s.get(url, headers=ngh, verify=False, timeout=10)
			print(f" └── {ngh}{'→':^3} {x_req.status_code:>3}")
			if "plop123" in x_req.text:
				print("wooow")
