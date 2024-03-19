#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import traceback


requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def waf_rules(url, s, main_status_code, authent):
    # Checking if the waf block doesn't in cache, ex: user-agent: sqlmap > blocked by waf > cached it
    bad_ua = ["360Spider", "acapbot", "acoonbot", "ahrefs", "alexibot", "asterias", "attackbot", "backdorbot", "becomebot", "binlar", "blackwidow", "blekkobot", "blexbot", "blowfish", "bullseye", "bunnys", "butterfly", "careerbot", "casper", "checkpriv", "cheesebot", "cherrypick", "chinaclaw", "choppy", "clshttp", "cmsworld", "copernic", "copyrightcheck", "cosmos", "crescent", "cy_cho", "datacha", "demon", "diavol", "discobot", "dittospyder", "dotbot", "dotnetdotcom", "dumbot", "emailcollector", "emailsiphon", "emailwolf", "exabot", "extract", "eyenetie", "feedfinder", "flaming", "flashget", "flicky", "foobot", "g00g1e", "getright", "gigabot", "gozilla", "grabnet", "grafula", "harvest", "heritrix", "httrack", "icarus6j", "jetbot", "jetcar", "jikespider", "kmccrew", "leechftp", "libweb", "linkextractor", "linkscan", "linkwalker", "loader", "masscan", "miner", "majestic", "mechanize", "mj12bot", "morfeus", "moveoverbot", "netmechanic", "netspider", "nicerspro", "nikto", "ninja", "nutch", "octopus", "pagegrabber", "planetwork", "postrank", "proximic", "purebot", "pycurl", "python", "queryn", "queryseeker", "radian6", "radiation", "realdownload", "rogerbot", "scooter", "seekerspider", "semalt", "siclab", "sindice", "sistrix", "sitebot", "siteexplorer", "sitesnagger", "skygrid", "smartdownload", "snoopy", "sosospider", "spankbot", "spbot", "sqlmap", "stackrambler", "stripper", "sucker", "surftbot", "sux0r", "suzukacz", "suzuran", "takeout", "teleport", "telesoft", "true_robots", "turingos", "turnit", "vampire", "vikspider", "voideye", "webleacher", "webreaper", "webstripper", "webvac", "webviewer", "webwhacker", "winhttp", "wwwoffle", "woxbot", "xaldon", "xxxyy", "yamanalab", "yioopbot", "youda", "zeus", "zmeu", "zune", "zyborg"]
    block_res = False
    cache_block_res = False

    list_block_ua = []
    list_cache_block_ua = []

    if main_status_code != 403:
        for bua in bad_ua:
            headers = {
            "user-agent": bua
            }
            req_ua = s.get(url, headers=headers, verify=False, timeout=10, auth=authent, allow_redirects=False)
            if req_ua.status_code == 403:
                list_block_ua.append(bua)
                for rf in req_ua.headers:
                    if "cache" in rf.lower():
                        list_cache_block_ua.append(bua)
        if list_block_ua:
            if len(list_block_ua) > 1:
                print("{} 403 with {}".format(url, len(list_block_ua)))
            else:
                print("{} 403 with {}".format(url, list_block_ua))
        if list_cache_block_ua:
            if len(list_cache_block_ua) > 1:
                print("{} cached the 403 response with {} {}".format(url, len(list_cache_block_ua), list_cache_block_ua[1]))
            else:
                print("{} cached the 403 response with {}".format(url, list_cache_block_ua))