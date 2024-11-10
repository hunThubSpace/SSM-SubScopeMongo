import os
import sys
import subprocess
from pymongo import MongoClient
from datetime import datetime
from colorama import Fore, Style, Back

def run_command(command, silent=False):
    """Run a shell command and handle exceptions, with an option to silence the output."""
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        result = subprocess.run(
            command, 
            check=True, 
            shell=True, 
            text=True, 
            stdout=subprocess.PIPE if not silent else subprocess.DEVNULL, 
            stderr=subprocess.PIPE if not silent else subprocess.DEVNULL
        )
        if not silent:
            print(result.stdout)
        return result
    except subprocess.CalledProcessError as e:
        if not silent:
            print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| Error executing command: {e.cmd}")
            print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| Error output: {e.stderr}")
        sys.exit(1)

def setup(user, password):
    try:
        
        # Update system packages
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK}   job   {Style.RESET_ALL}| Updating system packages")
        run_command("sudo apt update", silent=True)
        print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| Updated system packages")

        # Install necessary packages
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK}   job   {Style.RESET_ALL}| Installing required packages (gnupg, curl)")
        run_command("sudo apt-get install -y gnupg curl", silent=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| Installed required packages (gnupg, curl)")

        # Add MongoDB repository key
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK}   job   {Style.RESET_ALL}| Adding MongoDB repository key")
        run_command("curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor", silent=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| Added MongoDB repository key")

        # Add MongoDB repository to apt sources list
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK}   job   {Style.RESET_ALL}| Adding MongoDB repository to sources list")
        run_command(
            'echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list',
            silent=True
        )
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| Added MongoDB repository to sources list")

        # Install MongoDB
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK}   job   {Style.RESET_ALL}| Installing MongoDB")
        run_command("sudo apt-get update && sudo apt-get install -y mongodb-org", silent=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| Installed MongoDB")

        # Start and enable MongoDB service
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK}   job   {Style.RESET_ALL}| Starting and enabling MongoDB service")
        run_command("sudo systemctl start mongod", silent=True)
        run_command("sudo systemctl enable mongod", silent=True)
        run_command("sudo systemctl daemon-reload", silent=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| Started and enabled MongoDB service")

        # Create MongoDB database and user
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK}   job   {Style.RESET_ALL}| Creating MongoDB user with username: {user}")
        client = MongoClient('localhost', 27017)
        db = client['scopes']

        # Add authentication user
        auth_command = (
            f"mongosh scopes --eval "
            f"'db.createUser({{ user: \"{user}\", pwd: \"{password}\", roles: [{{ role: \"readWrite\", db: \"scopes\" }}] }})'"
        )
        run_command(auth_command, silent=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| Created MongoDB user with username: {user}")

    except Exception as e:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| error: {e}")
        sys.exit(1)

def main():
    auth_line = os.getenv('ssm_cred')
    if not auth_line:
        print("Error: The 'ssm_cred' environment variable is not set.")
        sys.exit(1)

    try:
        user, password = auth_line.split(':')
    except ValueError:
        print("Error: The 'ssm_cred' environment variable must be in the format 'user:pass'.")
        sys.exit(1)

    setup(user, password)

if __name__ == "__main__":
    main()
