import xml.etree.ElementTree as ET
import json
import csv
import bson
import os

os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

def bson_to_xml(bson_file, xml_file):
    try:
        with open(bson_file, 'rb') as f:
            # Read the BSON file content
            bson_data = bson.decode_all(f.read())

        # Check if any documents were decoded
        if not bson_data:
            print(f"No data found in {bson_file}.")
            return

        # Create the root element for the XML
        root = ET.Element("root")

        # Iterate over each document in the BSON file and add it to the XML
        for idx, doc in enumerate(bson_data):
            # Create an element for each document
            doc_element = ET.SubElement(root, f"document_{idx + 1}")

            # Iterate over key-value pairs in the document
            for key, value in doc.items():
                # Create a sub-element for each field in the document
                field_element = ET.SubElement(doc_element, key)
                field_element.text = str(value)

        # Create an ElementTree object from the root element
        tree = ET.ElementTree(root)

        # Write the XML to a file
        tree.write(xml_file, encoding="utf-8", xml_declaration=True)

        print(f"XML file created: {xml_file}")

    except bson.errors.InvalidBSON:
        print(f"Error: The file {bson_file} is not a valid BSON file.")
    except Exception as e:
        print(f"An error occurred: {e}")


def bson_to_csv(bson_file, csv_file):
    """
    Convert BSON file to CSV.

    Parameters:
    bson_file (str): The path to the input BSON file.
    csv_file (str): The path to the output CSV file.
    """
    try:
        with open(bson_file, 'rb') as f:
            # Read the BSON file content
            bson_data = bson.decode_all(f.read())

        # Check if any documents were decoded
        if not bson_data:
            print(f"No data found in {bson_file}.")
            return

        # Open CSV file to write
        with open(csv_file, mode='w', newline='') as file:
            writer = csv.writer(file)

            # Write header row using the first document's keys
            headers = bson_data[0].keys()
            writer.writerow(headers)

            # Write data rows
            for doc in bson_data:
                row = [doc.get(header, '') for header in headers]
                writer.writerow(row)

        print(f'CSV file created: {csv_file}')

    except bson.errors.InvalidBSON:
        print(f"Error: The file {bson_file} is not a valid BSON file.")
    except Exception as e:
        print(f"An error occurred: {e}")
        
def json_to_xml(json_file, xml_file):
    try:
        with open(json_file, 'r') as f:
            data = f.read().strip()  # Read as a string

        # Load the JSON data
        json_data = json.loads(data)

        # Create the root element
        root = ET.Element("root")

        # Recursively convert JSON to XML
        def json_to_xml_recursive(json_obj, parent):
            if isinstance(json_obj, dict):
                for key, value in json_obj.items():
                    # Create a new XML element for each key
                    child = ET.SubElement(parent, key)
                    json_to_xml_recursive(value, child)  # Recurse for nested data
            elif isinstance(json_obj, list):
                for item in json_obj:
                    # For lists, create a new element for each item
                    list_item = ET.SubElement(parent, "item")
                    json_to_xml_recursive(item, list_item)  # Recurse for each list item
            else:
                # Add the text value if it's a primitive type
                parent.text = str(json_obj)

        # Call the recursive function
        json_to_xml_recursive(json_data, root)

        # Create an ElementTree object from the XML structure
        tree = ET.ElementTree(root)

        # Write the XML data to the output file
        tree.write(xml_file, encoding='utf-8', xml_declaration=True)

        print(f'XML file created: {xml_file}')
    
    except FileNotFoundError:
        print(f"Error: The file {json_file} does not exist.")
    except json.JSONDecodeError:
        print("Error: Failed to decode JSON. Please check the file content.")
    except Exception as e:
        print(f"An error occurred: {e}")


def json_to_csv(json_file, csv_file):
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
