# SubScopeMongo

**SubScopeMongo** is a Python-based command-line tool (like SubScope) but in MongoDB database.

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
    python3 subscopemongo.py -h
    ```
    
    This will display usage information:

    ```
    usage: subscopemongo.py [-h] {program,domain,subdomain,url,ip,setup,importdb,exportdb,convert} ...
    
    Manage programs, domains, subdomains, and IPs
    
    positional arguments:
      {program,domain,subdomain,url,ip,setup,importdb,exportdb,convert}
        program             Manage programs or companies
        domain              Manage domains in a program
        subdomain           Manage subdomains in a program
        url                 Manage urls
        ip                  Manage IPs in a program
        setup               Installing mondodb and enable authentication
        importdb            Import database
        exportdb            Export database
        convert             convert json to csv
    
    options:
      -h, --help            show this help message and exit
    ```
