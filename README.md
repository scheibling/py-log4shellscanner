<h1 align="center">PY-Log4ShellScanner</h1>
<h4 align="center">A simple, one-file DNSLog server with HTTP endpoint for log retrieval</h4>

# Credit
Based on the Log4jScanner by fullhunt.io, modified with multithreading and custom DNS Callback server

# Features
- Support for lists of URLs
- Fuzzing for more than 60 HTTP request headers, with ability to add custom ones
- Fuzzing for HTTP POST Data parameters
- Fuzzing for JSON data parameters
- Multithreaded searches
- DNS Callback via self-hosted [scheibling/py-dnslogserver](https://github.com/scheibling/py-dnslogserver)
- WAF Bypass payloads

# Usage
## Preparations
```shell
pip3 install -r requirements.txt
```

## CLI
```shell
$ python3 py-log4shellscanner.py -h
[•] CVE-2021-44228 - Apache Log4j RCE Scanner
[•] Provided by https://github.com/scheibling
[•] Originally developed by FullHunt.io
[•] Version 1.0
usage: py-log4shellscanner.py [-h] -d DNSLOG_DOMAIN [-t TARGETS_FILE] [-i HEADERS_FILE] [-c CONCURRENT_REQUESTS] [--skip-waf-bypass] [-p PROXY_SERVER]

options:
  -h, --help            show this help message and exit
  -d DNSLOG_DOMAIN, --dnslog-domain DNSLOG_DOMAIN
                        The DNSLog domain to use for the requests
  -t TARGETS_FILE, --targets-file TARGETS_FILE
                        The hosts file to use for the requests (default: targets.txt)
  -i HEADERS_FILE, --headers HEADERS_FILE
                        The file containing the headers for the requests (Default: headers.txt)
  -c CONCURRENT_REQUESTS, --concurrent-requests CONCURRENT_REQUESTS
                        The number of concurrent requests to use (Default: 10)
  -p PROXY_SERVER, --proxy-server PROXY_SERVER
                        Proxy server to use for the scans
  --skip-waf-bypass     Skip the WAF bypass payloads

```

## Examples
```shell
# Run a scan against the hosts in targets.txt with default headers and waf bypass payloads (10 concurrent requests)
python3 py-log4shellscanner.py -d dnslog.example.com -t targets.txt -c 10

# Run a scan against the hosts in targets.txt with custom headers and without waf bypass payloads (10 concurrent requests)
python3 py-log4shellscanner.py -d dnslog.example.com -t targets.txt -i custom-headers.txt -c 10 --skip-waf-bypass

# Run a scan through a proxy server with custom headers, 20 concurrent requests and with waf bypass payloads
python3 py-log4shellscanner.py -d dnslog.example.com -t targets.txt -i headers-large.txt -c 20 -p proxy.example.com

```

# Legal Disclaimer
This project is made for testing purposes only. Usage of py-dnslogserver for attacking targets without prior mutual consent could be illegal.


# License
The project is licensed under MIT License.