import xml.etree.ElementTree as ET
import bson

def bson2xml(bson_file, xml_file):
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
