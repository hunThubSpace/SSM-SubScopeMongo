from colorama import Fore, Style, Back
from datetime import datetime
import subprocess

def run_subfinder(domains):
    for domain in domains:
        domain_name = domain.get('domain')
        if domain_name:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK}   job   {Style.RESET_ALL}| Running subfinder for domain: {domain_name}")
            result = subprocess.run(['subfinder', '-silent', '-all', '-duc', '-d', domain_name], capture_output=True, text=True)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| Finished subfinder")
            print(result.stdout)