from colorama import Fore, Style, Back
from datetime import datetime
import subprocess

def run_wayback(domains):    
    for domain in domains:
        domain_name = domain.get('domain')
        if domain_name:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK}   job   {Style.RESET_ALL}| Running wayback for domain: {domain_name}")
            result = subprocess.run(['gauplus', '-t', '1', '-subs', domain_name, '-random-agent'], capture_output=True, text=True)
            output = result.stdout
            output = output.replace('\r', '')
            output = '\n'.join(line.lstrip('*.') for line in output.splitlines())            
            processed_lines = []
            for line in output.splitlines():
                parts = line.split('/')
                if len(parts) > 2:
                    domain = parts[2].split(':')[0]
                    processed_lines.append(domain)

            unique_lines = sorted(set(processed_lines))

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| Finished wayback")
            print("\n".join(unique_lines))
