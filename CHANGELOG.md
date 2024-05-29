Changelog:
----------

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
