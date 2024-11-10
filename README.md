<div align=center>
 <img src="https://github.com/user-attachments/assets/7ea510c6-dc2e-4e35-b4a8-23635980582f">
</div>

# SubScopeMongo

**SubScopeMongo** is a Python-based command-line tool (like SubScope) but in MongoDB database.

## Requirements
- Python 3.x
- Installed MongoDB

## Installation
1. Clone the repository:

```bash
git clone https://github.com/hunThubSpace/SubScopeMongo.git && cd SubScopeMongo
```

2. Install requirements

```bash
pip install -r requirements.txt
```

3. Add your desired credential in `auth.txt`

```bash
user:pass
```

4. Run the setup.py for installing MongoDB database and set your credentials on DB

```bash
python3 setup.py
```

5. Run the script:

```bash
python3 subscopemongo.py -h
```

This will display usage information:

```bash
usage: subscopemongo.py [-h] {program,domain,subdomain,url,ip,setup,importdb,exportdb,convert} ...

Manage programs, domains, subdomains, and IPs

positional arguments:
 {program,domain,subdomain,url,ip,setup,importdb,exportdb,convert}
   program             Manage programs or companies
   domain              Manage domains in a program
   subdomain           Manage subdomains in a program
   url                 Manage urls
   ip                  Manage IPs in a program
   importdb            Import database
   exportdb            Export database
   convert             convert json to csv

options:
 -h, --help            show this help message and exit
```
