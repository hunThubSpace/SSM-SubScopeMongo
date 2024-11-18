import os
from datetime import datetime
        
def exportdb(username, password):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        com=f"mongodump --host localhost --port 27017 --db scopes --out . --username {username} --password {password} --authenticationDatabase scopes"
        os.system(com)
        
        timestamp_safe = timestamp.replace(":", "_").replace(" ", "_")
        com = f"mv scopes scopes_{timestamp_safe}.txt"
        os.system(com)
        print(f"Export completed. File saved as scopes_{timestamp_safe}")

    except Exception as E:
        print(E)
