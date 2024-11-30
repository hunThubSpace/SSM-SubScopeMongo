from colorama import Fore, Style, Back
from urllib.parse import urlparse
from datetime import datetime
import subprocess
import requests
import os

def extract_subdomain(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    if hostname:
        subdomain = hostname.split('.')[0]
        return subdomain
    return None

def bb_chaos_download_and_extract():
    url = "https://chaos-data.projectdiscovery.io/index.json"
    response = requests.get(url)
    
    if response.status_code != 200:
        pass

    data = response.json()
    subdomains = set()
    for entry in data:
        url = entry.get("URL")
        if url:
            subdomain = extract_subdomain(url)
            if subdomain:
                subdomains.add(subdomain)

    sorted_subdomains = sorted(subdomains)

    with open("static_dns_chaos.txt", "w") as file:
        file.write("\n".join(sorted_subdomains))

def resfile_gen():
    resolver_file = os.path.expanduser("~/.resolvers")
    resolvers = [
        "8.8.4.4",
        "129.250.35.251",
        "129.250.35.251"
    ]
    with open(resolver_file, 'w') as file:
        for resolver in resolvers:
            file.write(resolver + "\n")

def run_chaos(domains):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK}   job   {Style.RESET_ALL}| Fetching and remove duplicate lines from chaos wordlist")
    bb_chaos_download_and_extract()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| Fetched and removed duplicate lines from chaos wordlist")

    resfile_gen()
    
    wordlist_file = '/opt/wordlists/static_dns_chaos.txt'
    result = '/tmp/subs.txt'
    
    for domain in domains:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK}   job   {Style.RESET_ALL}| Running chaos on domain: {domain['domain']}")

        with open(wordlist_file, 'r') as infile, open('/tmp/dns_per_target.txt', 'w') as outfile:
            for line in infile:
                outfile.write(line.strip() + f".{domain['domain']}\n")
        subprocess.run([
            'puredns', 'resolve', '/tmp/dns_per_target.txt', 
            '--rate-limit', '900', 
            '-r', os.path.expanduser('~/.resolvers')
        ])

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| Resolved domains are written to {result}")
