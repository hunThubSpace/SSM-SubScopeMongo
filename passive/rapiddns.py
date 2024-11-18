from colorama import Fore, Style, Back
from datetime import datetime
import requests
import re

def run_rapiddns(domains):    
    for domain in domains:
        domain_name = domain.get('domain')
        if domain_name:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK}   job   {Style.RESET_ALL}| Running Rapiddns for domain: {domain_name}")

            grep_pattern = re.escape(domain_name)

            url = f"https://rapiddns.io/subdomain/{domain_name}?full=1"
            response = requests.get(url)

            if response.status_code == 200:
                subdomains = re.findall(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', response.text)

                filtered_subdomains = [sub for sub in subdomains if re.search(f"({grep_pattern})$", sub)]

                unique_subdomains = sorted(set(filtered_subdomains))

                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| Finished rapiddns")
                print("\n".join(unique_subdomains))
