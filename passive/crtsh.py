from colorama import Fore, Style, Back
from datetime import datetime
from pycrtsh import Crtsh
from typing import List
import time
import re


def bb_crtsh_subs(domain: str) -> List[str]:
    max_retries = 5
    attempt = 0

    while attempt < max_retries:
        try:
            crtsh = Crtsh()
            query = f"""
                SELECT ci.NAME_VALUE 
                FROM certificate_and_identities ci 
                WHERE plainto_tsquery('certwatch', '{domain}') @@ identities(ci.CERTIFICATE)
            """
            name_values = crtsh.psql_query(query)

            if name_values:
                subs = set()
                for name_tuple in name_values:
                    name = name_tuple[0] if isinstance(name_tuple, tuple) else name_tuple
                    subdomain = re.sub(r'\*\.', '', name.strip()).lower()
                    if subdomain.endswith(domain) and subdomain != domain:
                        subs.add(subdomain)

                return sorted(subs)
            else:
                return []

        except Exception as e:
            attempt += 1
            print(f"Attempt {attempt}/{max_retries} failed for domain {domain}: {e}")
            
            if "conflict with recovery" in str(e):
                wait_time = 2 ** attempt
                print(f"Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
            else:
                break
    return []

def run_crtsh(domains: List[dict]) -> None:
    for entry in domains:
        domain = entry.get('domain')
        if not domain:
            continue

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK}   job   {Style.RESET_ALL}| Running crtsh for domain: {domain}")
        
        subdomains = bb_crtsh_subs(domain)
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| Finished crtsh")
        
        if subdomains:
            for subdomain in subdomains:
                print(f"{subdomain}")
