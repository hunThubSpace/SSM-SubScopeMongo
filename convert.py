import json
import csv

def json_to_csv(json_file, csv_file):
    """
    Convert a JSON file to a CSV file based on various dataset structures.

    Parameters:
    json_file (str): The path to the input JSON file.
    csv_file (str): The path to the output CSV file.
    """
    try:
        with open(json_file, 'r') as f:
            data = f.read().strip()  # Read as a string

        # Load the JSON data
        json_data = json.loads(data)

        if isinstance(json_data, list):
            # program
            if "domains" in json_data[0]:
                process_programs_data(json_data, csv_file)
            
            # domain
            elif "scope" in json_data[0] and "subdomains" in json_data[0]:
                process_domains_data(json_data, csv_file)
                
            # subdomains
            elif "source" in json_data[0]:
                process_subdomains_data(json_data, csv_file)
            
            # url
            elif "scheme" in json_data[0]:
                process_urls_data(json_data, csv_file)
            
            # cidrs
            elif "asn" in json_data[0]:
                process_ips_data(json_data, csv_file)
            
            else:
                print("Error: Unknown data format in list.")
                return

        else:
            print("Error: Unrecognized data format.")
            return

    except FileNotFoundError:
        print(f"Error: The file {json_file} does not exist.")
    except json.JSONDecodeError:
        print("Error: Failed to decode JSON. Please check the file content.")
    except Exception as e:
        print(f"An error occurred: {e}")


def process_programs_data(programs_data, csv_file):
    """
    Process the 'programs' section of the JSON and write to CSV.

    Parameters:
    programs_data (list): List of program data.
    csv_file (str): The path to the output CSV file.
    """
    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)

        # Write header row
        headers = ["program", "domains", "subdomains", "urls", "ips", "created_at"]
        writer.writerow(headers)

        # Write the data rows
        for item in programs_data:
            writer.writerow([item["program"], item["domains"], item["subdomains"], item["urls"], item["ips"], item["created_at"]])

    print(f'CSV file created for programs: {csv_file}')


def process_domains_data(domains_data, csv_file):
    """
    Process the 'domains' section of the JSON and write to CSV.

    Parameters:
    domains_data (list): List of domain data.
    csv_file (str): The path to the output CSV file.
    """
    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)

        # Write header row
        headers = ["domain", "program", "scope", "subdomains", "urls", "created_at", "updated_at"]
        writer.writerow(headers)

        # Write the data rows
        for item in domains_data:
            writer.writerow([item["domain"], item["program"], item["scope"], item["subdomains"], item["urls"], item["created_at"], item["updated_at"]])

    print(f'CSV file created for domains: {csv_file}')


def process_subdomains_data(subdomains_data, csv_file):
    """
    Process the subdomains data and write to CSV.

    Parameters:
    subdomains_data (list): List of subdomain data.
    csv_file (str): The path to the output CSV file.
    """
    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)

        # Write header row
        headers = ["subdomain", "domain", "program", "source", "scope", "urls", "resolved", "ip_address", "cdn_status", "cdn_name", "created_at", "updated_at"]
        writer.writerow(headers)

        # Write the data rows
        for item in subdomains_data:
            writer.writerow([item["subdomain"], item["domain"], item["program"], item["source"], item["scope"],
                             item["urls"], item["resolved"], item["ip_address"], item["cdn_status"],
                             item["cdn_name"], item["created_at"], item["updated_at"]])

    print(f'CSV file created for subdomains: {csv_file}')


def process_ips_data(ips_data, csv_file):
    """
    Process the IPs data and write to CSV.

    Parameters:
    ips_data (list): List of IP data.
    csv_file (str): The path to the output CSV file.
    """
    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)

        # Write header row
        headers = ["ip", "program", "cidr", "asn", "port", "hostname", "domain", "organization", "data", "ssl", "isp", "os", "product", "version", "cves", "created_at", "updated_at"]
        writer.writerow(headers)

        # Write the data rows
        for item in ips_data:
            writer.writerow([item["ip"], item["program"], item["cidr"], item["asn"], item["port"], item["hostname"],
                             item["domain"], item["organization"], item["data"], item["ssl"], item["isp"],
                             item["os"], item["product"], item["version"], item["cves"], item["created_at"], item["updated_at"]])

    print(f'CSV file created for IPs: {csv_file}')


def process_urls_data(urls_data, csv_file):
    """
    Process the URLs data and write to CSV.

    Parameters:
    urls_data (list): List of URL data.
    csv_file (str): The path to the output CSV file.
    """
    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)

        # Write header row
        headers = ["url", "subdomain", "domain", "program", "scheme", "method", "port", "path", "flag", "status_code", "scope", "content_length", "ip_address", "cdn_status", "cdn_name", "title", "webserver", "webtech", "cname", "location", "created_at", "updated_at"]
        writer.writerow(headers)

        # Write the data rows
        for item in urls_data:
            writer.writerow([item["url"], item["subdomain"], item["domain"], item["program"], item["scheme"], item["method"], item["port"], item["path"], item["flag"],
                             item["status_code"], item["scope"], item["content_length"], item["ip_address"], item["cdn_status"], item["cdn_name"], item["title"], item["webserver"],
                             item["webtech"], item["cname"], item["location"], item["created_at"], item["updated_at"]])

    print(f'CSV file created for URLs: {csv_file}')
