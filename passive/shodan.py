from colorama import Fore, Style, Back
from datetime import datetime
import subprocess

def run_shodan(domains):    
    for domain in domains:
        domain_name = domain.get('domain')
        if domain_name:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK}   job   {Style.RESET_ALL}| Running shodan for domain: {domain_name}")
            print(f"Running Shodan for domain: {domain_name}")

            result = subprocess.run(['shosubgo', '-d', domain_name, '-s', 'pHHlgpFt8Ka3Stb5UlTxcaEwciOeF2QM'], capture_output=True, text=True)

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| Finished shodan")
            print(result.stdout)
