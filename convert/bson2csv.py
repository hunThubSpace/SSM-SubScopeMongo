import xml.etree.ElementTree as ET
import csv
import bson

def bson2csv(bson_file, csv_file):
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
