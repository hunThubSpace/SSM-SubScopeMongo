from colorama import Fore, Style, Back
from datetime import datetime
import subprocess

def run_assetfinder(domains):  
    for domain in domains:
        domain_name = domain.get('domain')
        if domain_name:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK}   job   {Style.RESET_ALL}| Running assetfinder for domain: {domain_name}")

            result = subprocess.run(['assetfinder', '--subs-only', domain_name], capture_output=True, text=True)

            subdomains = result.stdout.strip().splitlines()
            unique_subdomains = sorted(set(subdomains))

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| Finished assetfinder") 
            print("\n".join(unique_subdomains))
