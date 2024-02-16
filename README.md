# HExHTTP
Header Exploitation HTTP

*HTTP header behavior analysis tool*

### V 1.1


## Usage

	usage: hexhttp.py [-h] [-u URL] [--full]
	
	-h, --help        show this help message and exit
	-u URL            URL to test [required]
	-f URL_FILE       URL file to test
	-H CUSTOM_HEADER  Header HTTP custom
	--full            To display full header
	--auth AUTH       HTTP authentification. Ex: --auth admin:admin
	--behavior, -b    activate a lighter version of verbose, highlighting interesting cache behavior

*if notifypy dosn't work try ```python3 -m pip install notify-py```*

```
> $ python3 hexhttp.py -u url.com
> $ python3 hexhttp.py -f urls.txt -b | grep -i -E "url:|confirmed|behavior"
	
```

## Examples

![alt tag](https://github.com/c0dejump/HExHTTP/blob/main/static/example_1.png)
![alt tag](https://github.com/c0dejump/HExHTTP/blob/main/static/example_2.png)
![alt tag](https://github.com/c0dejump/HExHTTP/blob/main/static/poisoner.png)

## Features

- Server Error response checking
- Localhost header response analysis
- Vhosts checking
- Methods response analysis
- HTTP version analysis [Experimental]
- CPDoS technique
- CND Analysis
- Web cache poisoning
- Range poisoning/error (416 response error) [Experimental]
- Cookie Reflection
- Technologies analysis (Ngninx - Envoy - Apache) [IP]

## TODO

- Try with mobile user-agent 


### Based on :
- YWH HTTP Header Exploitation: https://blog.yeswehack.com/yeswerhackers/http-header-exploitation/
- Cache Poisoning at Scale https://youst.in/posts/cache-poisoning-at-scale/
- Web Cache Entanglement: Novel Pathways to Poisoning https://portswigger.net/research/web-cache-entanglement
- Practical Web Cache Poisoning https://portswigger.net/research/practical-web-cache-poisoning
- Exploiting cache design flaws https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws
- Responsible denial of service with web cache poisoning https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning
- https://cpdos.org/
- Cache poisoning https://github.com/Th0h0/autopoisoner 