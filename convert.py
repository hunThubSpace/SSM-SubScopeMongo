import json
import csv

def json_to_csv(json_file, csv_file):
    """
    Convert a JSON file to a CSV file.

    Parameters:
    json_file (str): The path to the input JSON file.
    csv_file (str): The path to the output CSV file.
    """
    try:
        with open(json_file, 'r') as f:
            data = f.read().strip()  # Read as a string

        # Load the JSON data
        json_data = json.loads(data)

        # Extract the list from the 'domains' key
        if "domains" in json_data:
            data = json_data["domains"]
        else:
            print("Error: 'domains' key not found in JSON data.")
            return

        # Check if data is a list
        if not isinstance(data, list) or len(data) == 0:
            print("Error: JSON data is not a non-empty list.")
            return

        # Open the CSV file for writing
        with open(csv_file, mode='w', newline='') as csv_file:
            writer = csv.writer(csv_file)

            # Write header row
            headers = data[0].keys()
            writer.writerow(headers)

            # Write the data rows
            for item in data:
                writer.writerow(item.values())

        print(f'CSV file created: {csv_file}')

    except FileNotFoundError:
        print(f"Error: The file {json_file} does not exist.")
    except json.JSONDecodeError:
        print("Error: Failed to decode JSON. Please check the file content.")
    except Exception as e:
        print(f"An error occurred: {e}")