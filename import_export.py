import os
from datetime import datetime
from colorama import Fore, Style, Back

def importdb(username, password):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        com=f"mongorestore --host localhost --port 27017 --db scopes scopes/ --username {username} --password {password} --authenticationDatabase scopes"
        os.system(com)
    except Exception as E:
        print(E)
        
def exportdb(username, password):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        com=f"mongodump --host localhost --port 27017 --db scopes --out . --username {username} --password {password} --authenticationDatabase scopes"
        os.system(com)
    except Exception as E:
        print(E)
