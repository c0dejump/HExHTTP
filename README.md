# HExHTTP

![logo](./docs/_media/logo-v1.png)

> HExHTTP is a tool designed to perform tests on HTTP headers and analyze the results to identify vulnerabilities and interesting behaviors.

<div align="center">
<img src="https://img.shields.io/github/v/release/c0dejump/HExHTTP" alt="release version">
<img alt="Python3.7" src="https://img.shields.io/badge/Python-3.7+-informational">
</div>

## Installation

### Python

```bash
pip install -r requirements.txt
./hexhttp.py -u 'https://target.tld/'
# OR
python3 hexhttp.py -u 'https://target.tld/'
```

### Docker

```bash
docker build -t hexhttp:latest .
docker run --rm -it --net=host -v "$PWD:/hexhttp/" hexhttp:latest -u 'https://target.tld/'
```

## Usage

```bash
Usage: hexhttp.py [-h] [-u URL] [-f URL_FILE] [-H CUSTOM_HEADER] [-A USER_AGENT] [-F] [-a AUTH] [-b]

HExHTTP is a tool designed to perform tests on HTTP headers.

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     URL to test [required]
  -f URL_FILE, --file URL_FILE
                        File of URLs
  -H CUSTOM_HEADER, --header CUSTOM_HEADER
                        Add a custom HTTP Header
  -A USER_AGENT, --user-agent USER_AGENT
                        Add a custom User Agent
  -F, --full            Display the full HTTP Header
  -a AUTH, --auth AUTH  Add an HTTP authentication. Ex: --auth admin:admin
  -b, --behavior        Activates a simplified version of verbose, highlighting interesting cache behaviors
  -hu HUMANS, --humans HUMANS
                        Performs a timesleep to reproduce human behavior (Default: 0s)
  -t THREADS, --threads THREADS
                        Threads numbers for multiple URLs. Default: 10
  -l LOG, --log LOG     Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
  -L LOG_FILE, --log-file LOG_FILE
                        The file path pattern for the log file. Default: logs/
  -v, --verbose         Increase verbosity (can be used multiple times)

```

### Arguments

```bash
# Scan only one domain
» ./hexhttp.py -u 'https://target.tld/'

# Scan a list of domains with behavior feature
» ./hexhttp.py -b -f domains.lst

# Add custom User-Agent
» ./hexhttp.py -u 'https://target.tld/' --user-agent "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64) Firefox/123.0-BugBounty"

# Use a custom Header and authentication
» ./hexhttp.py --header 'Foo: bar' --auth 'user:passwd' -u 'https://target.tld/' 

# Loop on domains, grep for vulnerabilities only and send result with notify (from projectdiscovery)
» for domain in $(cat domains.lst); do ./hexhttp.py -u "$domain" | grep -Eio "(INTERESTING|CONFIRMED)(.*)PAYLOAD.?:(.*){5,20}$" | notify -silent; done
```

## Examples

### Example on a public target
![example 1](./docs/_media/example_01.png)

### Example with a confirmed Cache Poisoning vulnerability
You can test this tool on the Web Security Academy's vulnerable labs, like [Web cache poisoning with an unkeyed header](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws/lab-web-cache-poisoning-with-an-unkeyed-header). The expected result should be the same as below.

![example poisoner](./docs/_media/example_02.png)

## Features

- Server Error response checking
- Localhost header response analysis
- Vhosts checking
- Methods response analysis
- HTTP Version analysis **[Experimental]**
- Cache Poisoning DoS (CPDoS) techniques
- Web cache poisoning
- Range poisoning/error (416 response error) **[Experimental]**
- Cookie Reflection
- CDN/proxies Analysis (Envoy/Apache/Akamai/Nginx) **[IP]**

## TODO

- [ ] Try with mobile user-agent [WIP]
- [ ] Filter False Positive on WAF blocking [WIP]
- [ ] Code Linting & Optimization [WIP]
- [ ] Human scan (rate limiting + timeout randomization ) [WIP] -- works but cleaning, linting etc...
- [ ] Tests Bed for regression testing
- [ ] Pypi package (src/ layout + tests/ + tox)
- [ ] Different Output formats (eg, JSON, JSONL, TXT)

### Based on
- [YWH HTTP Header Exploitation](https://blog.yeswehack.com/yeswerhackers/http-header-exploitation/)
- [Cache Poisoning at Scale](https://youst.in/posts/cache-poisoning-at-scale/)
- [abusing http hop-by-hop request headers](https://nathandavison.com/blog/abusing-http-hop-by-hop-request-headers)
- [Web Cache Entanglement: Novel Pathways to Poisoning](https://portswigger.net/research/web-cache-entanglement)
- [Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)
- [Exploiting cache design flaws](https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws)
- [Responsible denial of service with web cache poisoning](https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning)
- [CPDoS.org](https://cpdos.org/)
- [Autopoisoner](https://github.com/Th0h0/autopoisoner)
- [Rachid.A research](https://zhero-web-sec.github.io/research-and-things/nextjs-and-cache-poisoning-a-quest-for-the-black-hole)

## Contributing

Pull requests are welcome. Feel free to contribute to this tool and make improvements!