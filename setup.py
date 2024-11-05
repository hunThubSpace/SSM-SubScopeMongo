import os
from datetime import datetime
from colorama import Fore, Style, Back

def setup():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        # install pymongo
        com=f"pip install pymongo bson --break-system-packages"
        os.system(com)
        
        from pymongo import MongoClient
        
        # update packages
        com=f"sudo apt update"
        os.system(com)
        
        # install gnupg and curl
        com=f"sudo apt-get install gnupg curl"
        os.system(com)
                
        com=f"curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor"
        os.system(com)
        com=f'echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list'
        os.system(com)

        com=f"sudo apt-get update; sudo apt-get install -y mongodb-org"
        os.system(com)

        com=f"sudo systemctl start mongod &> /dev/null; sudo systemctl daemon-reload &> /dev/null; sudo systemctl enable mongod &> /dev/null"
        os.system(com)

        # create database
        client = MongoClient('localhost', 27017)
        db = client['scopes']

        # add authentication
        com = (
            'mongosh scopes --eval '
            '\'db.createUser({ user: "hunthub", pwd: "eeec497c78400d2189dc1e3c4c808bbc67e316a8cc6be80e68abae13ac029918", roles: [{ role: "readWrite", db: "scopes" }] })\''
        )
        os.system(com)
    except Exception as E:
        print(E)

