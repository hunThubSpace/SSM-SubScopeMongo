from colorama import Fore, Style, Back
from datetime import datetime
import requests
import re

def run_abuseipdb(domains):  
    for domain in domains:
        domain_name = domain.get('domain')

        if domain_name:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK}   job   {Style.RESET_ALL}| Running abuseipdb for domain: {domain_name}")

            abuseipdb_cookie = "abuseipdb_session=eyJpdiI6InJ3SGdpZkFRYzR1RmpwakZmbW9vMmc9PSIsInZhbHVlIjoiYzJGaDZ1VGdEZHFORFhvMU1iMDRGV1p1RGRvcjlPXC9UcjdWb2cycUlVVTBhQ21KYmp5Rm9BNllOSkxmeVdtWTQiLCJtYWMiOiI5YjY5YjAxMWU3Y2RiMzY3NzI5MGE5NTQxNjg4M2YwZjkzYzA4MTg3NDdmMTE2OTVjZWE4N2JlZDJmNDU3NzNkIn0%3D"
            headers = {
                "cookie": abuseipdb_cookie,
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
            }

            url = f"https://www.abuseipdb.com/whois/{domain_name}"
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                subdomains = re.findall(r'<li>\w.*</li>', response.text)
                cleaned_subdomains = [re.sub(r'</?li>', '', subdomain) + f".{domain_name}" for subdomain in subdomains]

                unique_subdomains = sorted(set(cleaned_subdomains))

                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| Finished Abuseipdb")
                print("\n".join(unique_subdomains))
