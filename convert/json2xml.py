import xml.etree.ElementTree as ET
import json
    
def json2xml(json_file, xml_file):
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