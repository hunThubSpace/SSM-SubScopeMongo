from colorama import Fore, Style, Back
from datetime import datetime
import subprocess
import requests
import os

def jhaddix_wl():
    original_dir = os.getcwd()

    url = "https://gist.githubusercontent.com/jhaddix/f64c97d0863a78454e44c2f7119c2a6a/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt"
    wordlist_file = "/opt/wordlists/static_dns_jhaddix.txt"
    os.chdir("/opt/wordlists/")

    try:
        response = requests.get(url)
        with open(wordlist_file, 'wb') as file:
            file.write(response.content)

        with open(wordlist_file, 'r') as file:
            lines = file.readlines()
        
        unique_lines = sorted(set(line.strip() for line in lines))

        with open(wordlist_file, 'w') as file:
            file.write("\n".join(unique_lines))

    except requests.RequestException as e:
        pass
    
    os.chdir(original_dir)

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

def run_jhaddix(domains):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK}   job   {Style.RESET_ALL}| Fetching and remove duplicate lines from jhaddix (all.txt) wordlist")
    jhaddix_wl()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| Fetched and removed duplicate lines from jhaddix (all.txt) wordlist")

    resfile_gen()
    
    wordlist_file = '/opt/wordlists/static_dns_jhaddix.txt'
    result = '/tmp/subs.txt'
    
    for domain in domains:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK}   job   {Style.RESET_ALL}| Running jhaddix on domain: {domain['domain']}")

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
