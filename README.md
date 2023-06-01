# HExHTTP
Header Exploitation HTTP

*HTTP header behavior analysis tool*

### Beta version


## Usage

	usage: hexhttp.py [-h] [-u URL] [--full]
	
	-h, --help   show this help message and exit
	-u URL       URL to test [required]
	-f URL_FILE  URL file to test
	--full       To display full header


## Examples

![alt tag](https://github.com/c0dejump/HExHTTP/blob/main/static/example_1.png)
![alt tag](https://github.com/c0dejump/HExHTTP/blob/main/static/example_2.png)

## Features

- Server Error response checking [IP]
- Localhost header response analysis
- Methods response analysis
- CPDoS technique
- CND Analysis
- Technologies analysis (Ngninx - Envoy - Apache) [IP]
- Header cache reaction analysis [IP]


### Based on :
- YWH HTTP Header Exploitation: https://blog.yeswehack.com/yeswerhackers/http-header-exploitation/
- Cache Poisoning at Scale https://youst.in/posts/cache-poisoning-at-scale/
- Web Cache Entanglement: Novel Pathways to Poisoning https://portswigger.net/research/web-cache-entanglement
- Practical Web Cache Poisoning https://portswigger.net/research/practical-web-cache-poisoning
- Responsible denial of service with web cache poisoning https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning
- https://cpdos.org/