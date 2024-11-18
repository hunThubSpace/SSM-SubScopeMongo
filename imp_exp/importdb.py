import os
from datetime import datetime

def importdb(username, password, directory):
    timestamp = datetime.now().strftime("%Y-%m-%d")
    try:
        com=f"mongorestore --host localhost --port 27017 --db scopes {directory} --username {username} --password {password} --authenticationDatabase scopes"
        os.system(com)
    except Exception as E:
        print(E)