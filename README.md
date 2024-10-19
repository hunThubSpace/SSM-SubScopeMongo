# SubScopeMon

**SubScopeMon** is a Python-based command-line tool (like SubScope) but in MongoDB database.

## Requirements
- Python 3.x
- Installed MongoDB

## Installation
1. Install MongoDB (https://www.mongodb.com/docs/manual/installation/)
2. Install pymongo
  
    ```bash
    pip install pymongo
    ```

3. Clone the repository:

   ```bash
   git clone https://github.com/hunThubSpace/SubScopeMongo.git && cd SubScopeMongo
   ```
   
4. Run the script:

    ```bash
    chmod +x subscopemongo.py
    ./subscopemongo.py -h
    ```
    
    This will display usage information:

    ```
   usage: ./subscopemongo.py [-h] {program,domain,subdomain,url,ip} ...
   
   Manage programs, domains, subdomains, and IPs
   
   positional arguments:
     {program,domain,subdomain,url,ip}
       program             Manage programs
       domain              Manage domains in a program
       subdomain           Manage subdomains in a program
       url                 Manage urls
       ip                  Manage IPs in a program
   
   options:
     -h, --help            show this help message and exit
    ```
