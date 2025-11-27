Changelog:
----------

- 2.4
---------
	Updated:
	- New payloads
	- Fix bugs
	News:
	- CFP module: change format page poisoning (html > json....)
---------

- 2.3
---------
	Updated:
	- Renames files and directory
	- Linting
	- Fixed proxy bugs
	- fixed basic_cpdos bugs
	Deleted:
	- tools/*
	- modules/lists/lowercase-headers.lst
	- modules/lists/paraminer-wordlist.lst
	News:
	- cache_poisoning.py 
	- modules/lists/wcp_headers.lst
---------

- 2.2
---------
	Updated:
	- Menu in README.md
	- Add payloads
	- Remake paraminer list
	- Linting
	- Fixed bugs
	News:
	- print_utils.py in utils directory
---------

- 2.1
---------
	Updated:
	- Fixed cpdos_main: Reworking the source code to avoid FP and improve detection, as well as being able to send headers not authorized by the basic requests library & recreating a “fresh” session before launching the cpdos modules
	- New payloads
	- Fixed logic and style bug
	News:
	- CVE-2025-57822 module check
	- Add random user-agent during cpdos to avoid overly strict waf
---------

- 2.0
---------
	New:
	- HTTP proxy module, you can send behavior and confirmed request directly in burp (or other HTTP proxy) now (utils/proxy.py)
	- Check CVE-2021-27577 by Claude AI
	- Multiple method poisoning analysis (modules/cp_check/methods_poisoning)
		- Fat methods poisoning
		- Cross Mixed Methods CPDoS (Cross-method cache poisoning, negative caching, Mix methods)
	- Origin CORS DoS by Geluchat
	- Uncommon header analysis (retrieves the non-common headers from the request and replays them for testing purposes)
	- Debug headers checks
	- PR and push are now checked against formatting, linting, type checking, security checking and regression testing (quality workflow)
	- Version handles beta versioning now
	- DX : Small Test Bed to verify regression
	Updated:
	- setup and requirements consolidated into pyproject.toml
	- dockerfile is now in sync with how hexhttp is installed
	- headerfuzz dictionary was overwriting its payloads using the same key
	- Banner and version concerns are now separated
	- technologies module got renamed to align with class name
	- Proxy and Burp options allows to specify proxy server to pass issues or whole traffic
	- Fixed bugs
	- Remake server_error checks
	- Remake Helper (-h) & README.md
	- Unrisk page checking on the last CVE
	- New payloads
		- upgrade H2C DoS by Geluchat
	- BIG Linting
		- Added "utils" repository
		- Moving certain files/folders/functions to linting
		- Implementation of the cli.py file to lighten hexhttp.py
	- HTTP Version & protocol analysis updated
	- Vhosts misconfiguration analysis updated
	- Methods analysis updated
	Deleted:
	- Cookies reflection tests (already completed in other modules)
	- vuln_notify feature never really implemented and was too platform specific
---------

- 1.9.2
---------
	News
	- New cve module to check Next.js CPDoS by Zhero research and Wlayzz PoC (CVE-2025-49826)
	Updated:
	- Updated TODO list
	- Updated HTTP method checks (+50 added)
	- Fixed bugs
---------

- 1.9.1
---------
	News
	- Added only cache poisoning option (--ocp)
	Updated:
	- Linting of the http methods module and addition of +50 new methods to be check
	- Fixed bugs
---------

- 1.9
---------
	News
	- New module to check cache poisoning via backslash transformation
	- New Akamai check (https://web.archive.org/web/20230101082612/https://spyclub.tech/2022/12/14/unusual-cache-poisoning-akamai-s3/#How-to-prevent) + Linting
	Updated:
	- Cleaning and tidying up threads
	- Fixed header add by -H option, now you can add multiple headers, exemple: -H "toto: titi" -H "plop: plip"
	- News payloads
	- Fixed bugs/FP
---------

- 1.8
---------
	News
	- New cve module to check Next.js CPDoS Zhero research (CVE-2025-29927)
	- New module to check cache poisoning via path traversal (Thanks to 0xrth !)
	- Proxy features (-p option)
	Updated:
	- News payloads
	- Fixed bugs/FP
	- Linting
	- requirement.txt
---------

- 1.7.6
---------
	News
	- Check your HExHTTP version 
	- New cve module to check Nuxt.js CPDoS Zhero research (CVE-2025-27415)
	Updated:
	- News payloads (headers, methods and http version)
	- Fixed bugs/FP
	- Linting
---------


- 1.7.5
---------
	News
	- Add a folder/check containing more-less well-known CVEs linked to headers or cache
	- Add proxy feature [In Progress]
	Updated:
	- News payloads (~1k)
	- Fixed bugs/FP
	- Linting
---------


- 1.7.4
---------
	News:
	- New cve module to check Nextjs cache poisoning Zhero research
	Updated:
	- Reduce FP
	- Change "CACHE" by "CACHETAG" to avoid confusion
	- Clean-up and remodeling of module file/folder architecture
	- cache_poisoining_file => cache_poisoining__nf_file: total reconstruction of the module, to check on source files (js/css) that do not exist whether it is possible to inject text into the header or body and cache it

---------

- 1.7.3
---------
	News:
	- Sponsors button
	Updated:
	- News payloads and fix on HMO modules (~800)
	- Fixed issues

---------

- 1.7.2
---------
	News:
	- New module for "human" scan, personal timesleep or random (0-5s) to each requests
	Updated:
	- News payloads
	- Rename module modules/cpdos/cache_error.py -> modules/cpdos/basic_cpdos.py 

---------

- 1.7.1
---------
	News:
	- New module for multiple headers cache error based on @0xrth observations (mutliple_headers.py)
	- New file __init__.py in lists directory to add functionality to load payloads from files
	Updated:
	- commenting on the notification (notify-py)
	- News payloads
	- Linting
	- Fixed bugs
---------


- 1.7
---------
	News:
	- Logging management
	- Error logs management
	Updated:
	- ANSI banner at startup
	- Fixed bugs
	- Cache tag color
	- Big linting and refactoring
	- News payloads

---------

- 1.6.3
---------
	Updated:
	- News payload error endpoints (+600)
	- Fixed errors and FP
	- big start of refacto/lint from @Kharaone 
---------

- 1.6.2
---------
	Updated:
	- News payload error endpoints (+500)
	- CPDoS live tracking
	- Fixed and reducted FP
---------

- 1.6.1
---------
	Updated:
	- News payload error endpoints (+400)
---------

- 1.6
---------
	Updated:
	- New file "payloads_errors.py" which lets you directly add payloads for CPDoS, and currently offers more than 200 payloads with various technologies
	- Check js/css url during the CPDoS check
	- Reduct FP
---------


- 1.5.9
---------
	Updated:
	- Fix hho & hmo modules
	- update README screenshot
	- Reduct FP
---------

- 1.5.8
---------
	Updated:
	- News endpoints for CPDoS
	- fixed any bugs (cookie problems)
	- Updated Akamai tests
	Deleted:
	- range_check.py (directly in cache_error tests)
---------

- 1.5.7
---------
	Updated:
	- News endpoints for CPDoS
	- fixed any bugs
	- New banner
---------

- 1.5.6
---------
	Updated:
	- News endpoints based on https://zhero-web-sec.github.io/research-and-things/nextjs-and-cache-poisoning-a-quest-for-the-black-hole
	- Updated CPDoS with different response size
---------

- 1.5.5
---------
	Updated:
	- New endpoints on cache_error.py
	- Fix display bugs
	News:
	- Vercel tests
---------

- 1.5.4
---------
	Updated:
	- New endpoints on headerfuzz, HMO, HMC & HMO module
	- Fix of header argument missing in some functions
	- Fix on CPDoS module, deleted old tests, reduce FP
---------

- 1.5.3
---------
	Updated:
	- all file's imports for code optimization
	- short description for vulnerabilities and link reference
	- minors bug fix 
	New: 
	- modules/utils.py file for code optimization
---------

- 1.5.2
---------
	Updated:
	- Add check on Akamai module
	- fix hbh fp
---------

- 1.5.1
---------
	Updated:
	- Rename of folder for differents lists 
	- Fix of readme versioning
	New :
	- Hop-By-Hop check for CP-DoS 
	- New list for testing HTTP Headers
	Deleted :
	- broken github workflow for pypi package, need re-verify
---------

- 1.5
---------
	Updated:
	- Try to reduce fp numbers
	- Adding multiple endpoints in cache_error + headerfuzz + method module
	- Fixing some display bugs 
---------

- 1.4.1
---------
	New files: 
	- modules/UAmobile.py # Change brought about by mobile user-agent
	- modules/user-agent/mobile-user-agent.lst
	- modules/cpdos/cache_error.py # HTTP response error cached check
	- modules/technos/vercel.py
	- CHANGELOG.md
	Deleted:
	- modules/cpdos/refererdos.py #Replace by cache_error.py
---------
