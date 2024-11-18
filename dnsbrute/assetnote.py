from colorama import Fore, Style, Back
from datetime import datetime
import subprocess
import requests
import os

def assetnote_wl():
    original_dir = os.getcwd()
    
    # Define the wordlist URLs
    urls = [
        "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt",
        "https://wordlists-cdn.assetnote.io/data/manual/2m-subdomains.txt"
    ]
    
    # Directory to save the wordlists
    wordlist_dir = "/opt/wordlists/"
    
    # Change to the specified directory
    os.chdir(wordlist_dir)
    
    # Download the wordlists
    for url in urls:
        response = requests.get(url)
        filename = url.split("/")[-1]
        with open(filename, 'wb') as file:
            file.write(response.content)
    
    # Merge, convert to lowercase, and remove duplicates
    with open("best-dns-wordlist.txt", 'r') as file1, open("2m-subdomains.txt", 'r') as file2:
        words = file1.readlines() + file2.readlines()
    
    # Process the words (convert to lowercase and remove duplicates)
    words = set(word.strip().lower() for word in words)
    
    # Write the processed words to a new file
    with open("static_dns_assetnote.txt", 'w') as outfile:
        outfile.write("\n".join(sorted(words)))
    
    # Clean up downloaded files
    os.remove("best-dns-wordlist.txt")
    os.remove("2m-subdomains.txt")
    
    # Return to the original directory
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

def run_assetnote(domains):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK}   job   {Style.RESET_ALL}| Fetching and merging assetnote wordlists")
    assetnote_wl()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| Fetched and merged assetnote wordlists")

    resfile_gen()
    
    wordlist_file = '/opt/wordlists/static_dns_assetnote.txt'
    result = '/tmp/subs.txt'
    
    for domain in domains:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK}   job   {Style.RESET_ALL}| Running assetnote on domain: {domain['domain']}")

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
