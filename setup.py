import os
from pymongo import MongoClient

def setup(user, password):
    try:                
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
            f'mongosh scopes --eval '
            f"'db.createUser({{ user: \"{user}\", pwd: \"{password}\", roles: [{{ role: \"readWrite\", db: \"scopes\" }}] }})'"
        )
        os.system(com)
        
    except Exception as E:
        print(E)

if __name__ == "__main__":
    with open('auth.txt', 'r') as file:
            auth_line = file.readline().strip()
    user, password = auth_line.split(':')
    setup(user, password)
