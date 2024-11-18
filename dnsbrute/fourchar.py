from colorama import Fore, Style, Back
from datetime import datetime
import subprocess
import itertools
import os

def fourchar_wl():
    charset = "abcdefghijklmnopqrstuvwxyz1234567890-"
    output_file = '/opt/wordlists/static_dns_4char.txt'

    with open(output_file, 'w') as f:
        for combo in itertools.product(charset, repeat=4):
            f.write(''.join(combo) + '\n')

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

def run_4char(domains):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK}   job   {Style.RESET_ALL}| Generating 4 characters wordlist")
    fourchar_wl()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| Fetched generating 4 characters wordlist")

    resfile_gen()
    
    wordlist_file = '/opt/wordlists/static_dns_4char.txt'
    result = '/tmp/subs.txt'
    
    for domain in domains:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK}   job   {Style.RESET_ALL}| Running 4char on domain: {domain['domain']}")

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
