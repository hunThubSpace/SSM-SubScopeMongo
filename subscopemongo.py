#!/usr/bin/python3

import re
import os
import json
import argparse
import colorama
from datetime import datetime
from pymongo import MongoClient # type: ignore
from colorama import Fore, Style, Back
from datetime import datetime, timedelta

colorama.init()

def setup():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        # install mongodb
        com=f"sudo apt update &> /dev/null && sudo apt-get install gnupg curl &> /dev/null"
        os.system(com)
        print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| installing | the {Fore.BLUE}{Style.BRIGHT}gnupg and curl{Style.RESET_ALL} installed")

        com=f"curl -fsSL https://www.mongodb.org/static/pgp/server-8.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor &> /dev/null"
        os.system(com)        
        com=f'echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/8.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list &> /dev/null'
        os.system(com)
        print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| installing | the {Fore.BLUE}{Style.BRIGHT}mongo key{Style.RESET_ALL} created")

        com=f"sudo apt-get update &> /dev/null && sudo apt-get install -y mongodb-org &> /dev/null"
        os.system(com)
        print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| installing | the {Fore.BLUE}{Style.BRIGHT}mongodb{Style.RESET_ALL} installed")
        
        com=f"sudo systemctl start mongod &> /dev/null; sudo systemctl daemon-reload &> /dev/null; sudo systemctl enable mongod &> /dev/null"
        os.system(com)
        print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| installing | the {Fore.BLUE}{Style.BRIGHT}mongodb service{Style.RESET_ALL} started")

        # install pymongo
        com=f"pip install pymongo bson --break-system-packages &> /dev/null"
        os.system(com)
        print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| installing | the {Fore.BLUE}{Style.BRIGHT}pymongo{Style.RESET_ALL} installed")
        
        # create database
        client = MongoClient('localhost', 27017)
        db = client['scopes']
        
        # add authentication
        com = (
            'mongo scopes --eval '
            '\'db.createUser({ user: "user", pwd: "password", roles: [{ role: "readWrite", db: "scopes" }] })\''
        )
        os.system(com)
        print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| installing | the {Fore.BLUE}{Style.BRIGHT}scopes database{Style.RESET_ALL} has authentication")

        # note > mongorestore --host localhost --port 27017 --db scopes scopes --username user --password 'password' --authenticationDatabase scopes
    except Exception as E:
        print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| installing | {E}")

client = MongoClient('mongodb://user:password@localhost:27017/scopes')
#client = MongoClient('localhost', 27017)  # Adjust as needed

db = client['scopes']
programs_collection = db['programs']
domains_collection = db['domains']
subdomains_collection = db['subdomains']
urls_collection = db['urls']
cidrs_collection = db['cidrs']

def update_counts_program(program):
    collections = {'domains': domains_collection,'subdomains': subdomains_collection,'urls': urls_collection,'ips': cidrs_collection,}
    counts_program = {key: collection.count_documents({"program": program}) for key, collection in collections.items()}
    programs_collection.update_one({"program": program},{"$set": counts_program})

def update_counts_domain(program, domain):
    collections = {'subdomains': subdomains_collection,'urls': urls_collection,}
    counts_domain = {key: collection.count_documents({"program": program, "domain": domain}) for key, collection in collections.items()}
    domains_collection.update_one({"program": program, "domain": domain},{"$set": counts_domain})

def update_counts_subdomain(program, domain, subdomain):
    counts_subdomain = {'urls': urls_collection.count_documents({"program": program, "domain": domain, "subdomain": subdomain}),}
    subdomains_collection.update_one({"program": program, "domain": domain, "subdomain": subdomain},{"$set": counts_subdomain})

def add_program(program):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Check if program is a file path
    if isinstance(program, str):
        try:
            # Attempt to open the program as a file
            with open(program, 'r') as file:
                programs = [line.strip() for line in file if line.strip()]  # Read and strip empty lines
        except FileNotFoundError:
            # If it's not a file, treat it as a single program
            programs = [program]
        except Exception as e:
            print(f"Error reading from file: {e}")
            return
    elif isinstance(program, list):
        programs = program
    else:
        raise ValueError("Input must be a program name (str) or a path to a file (str) or a list of programs.")

    try:
        # Prepare a list for new program documents
        new_programs = []

        for program in programs:
            # Check if the program already exists
            exists = programs_collection.count_documents({"program": program}) > 0

            if exists:
                print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| adding program | program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL} already exists")
                continue  # Skip this program if it already exists

            # Count related documents
            collections = {
                'domains': domains_collection,
                'subdomains': subdomains_collection,
                'urls': urls_collection,
                'ips': cidrs_collection,
            }

            counts = {key: collection.count_documents({"program": program}) for key, collection in collections.items()}

            # Prepare the new program document
            program_document = {
                "program": program,
                "domains": counts['domains'],
                "subdomains": counts['subdomains'],
                "urls": counts['urls'],
                "ips": counts['ips'],
                "created_at": timestamp
            }
            new_programs.append(program_document)

        # Insert all new program documents at once
        if new_programs:
            programs_collection.insert_many(new_programs)
            program_names = ', '.join(program['program'] for program in new_programs)  # Get program names
            print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| adding program | added {Fore.BLUE}{Style.BRIGHT}{program_names}{Style.RESET_ALL} program(s)")

    except Exception as e:
        print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| adding programs | error: {e}")

def list_programs(program='*', brief=False, count=False):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # For potential logging
    try:
        # Fetch programs from the database
        if program == '*':
            programs = list(programs_collection.find({}, {"_id": 0}))  # Exclude the MongoDB _id field
        else:
            programs = list(programs_collection.find({"program": program}, {"_id": 0}))

        # If no programs exist, display a message
        if not programs:
            print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| listing program | program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL} not found")
            return

        # Handle counting records
        if count:
            count_result = len(programs)
            print(count_result)
            return

        # Brief mode: print only program names
        if brief:
            for ws in programs:
                print(ws['program'])  # Print each program name in brief mode
        else:
            # Detailed mode: print program with created_at, domain count, subdomain count, URL count, and IP count as JSON
            print(json.dumps({"programs": programs}, indent=4))

    except Exception as e:
        print(f"{Fore.RED}error{Style.RESET_ALL} | listing programs | error: {e}")

def delete_program(program, delete_all=False):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def count_entries(program=None):
        if program == '*':
            # Count all entries in related collections
            ip_count = cidrs_collection.count_documents({})
            url_count = urls_collection.count_documents({})
            subdomain_count = subdomains_collection.count_documents({})
            domain_count = domains_collection.count_documents({})
            program_count = programs_collection.count_documents({})
        else:
            ip_count = cidrs_collection.count_documents({"program": program})
            url_count = urls_collection.count_documents({"program": program})
            subdomain_count = subdomains_collection.count_documents({"program": program})
            domain_count = domains_collection.count_documents({"program": program})
            program_count = programs_collection.count_documents({"program": program})

        return program_count, domain_count, subdomain_count, url_count, ip_count

    try:
        if program == '*':
            if delete_all:
                # Delete all related data for all programs
                program_count, domain_count, subdomain_count, url_count, ip_count = count_entries('*')

                cidrs_collection.delete_many({})
                urls_collection.delete_many({})
                subdomains_collection.delete_many({})
                domains_collection.delete_many({})
                programs_collection.delete_many({})
                
                print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| deleting all programs | all programs with program: {program_count}, domains: {domain_count}, subdomains: {subdomain_count}, urls: {url_count}, ips: {ip_count}")
            else:
                # Only delete all programs
                programs_collection.delete_many({})
                print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| deleting programs | deleted all programs")
        
        else:
            if delete_all:
                # Delete all related data for the specified program
                program_count, domain_count, subdomain_count, url_count, ip_count = count_entries(program)

                cidrs_collection.delete_many({"program": program})
                urls_collection.delete_many({"program": program})
                subdomains_collection.delete_many({"program": program})
                domains_collection.delete_many({"program": program})
                programs_collection.delete_one({"program": program})

                print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| deleting all program of {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL} | program: {program_count}, domains: {domain_count}, subdomains: {subdomain_count}, urls: {url_count}, ips: {ip_count}")
                return

            # Check if the program exists
            if programs_collection.count_documents({"program": program}) == 0:
                print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| deleting program | program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL} not found")
                return
            else:
                programs_collection.delete_one({"program": program})
                print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| deleting program | program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL} deleted")

    except Exception as e:
        print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| deleting program | error: {e}")

def add_domain(domain_or_file, program, scope=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Check if the program exists
    if programs_collection.count_documents({"program": program}) == 0:
        print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| adding domain | program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL} does not exist")
        return

    # Determine if the input is a file or a single domain
    if os.path.isfile(domain_or_file):
        with open(domain_or_file, 'r') as file:
            domains = [line.strip() for line in file if line.strip()]
    else:
        domains = [domain_or_file]

    new_domains = []
    
    for domain in domains:
        existing_domain = domains_collection.find_one({"domain": domain, "program": program})

        subdomains_counts = subdomains_collection.count_documents({"domain": domain})
        urls_counts = urls_collection.count_documents({"domain": domain})

        if existing_domain:
            current_scope = existing_domain.get("scope")  # Get current scope

            # Update the scope if a new one is provided and differs
            if scope is not None and current_scope != scope:
                domains_collection.update_one(
                    {"domain": domain, "program": program},
                    {"$set": {"scope": scope, "updated_at": timestamp}}
                )
                print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| updating domain | domain {Fore.BLUE}{Style.BRIGHT}{domain}{Style.RESET_ALL} updated to {scope}")
            else:
                print(f"{timestamp} | {Fore.YELLOW}notice{Style.RESET_ALL} | domain {Fore.BLUE}{Style.BRIGHT}{domain}{Style.RESET_ALL} unchanged")
        else:
            new_scope = scope if scope is not None else 'inscope'
            new_domains.append({
                "domain": domain,
                "program": program,
                "scope": new_scope,
                "subdomains": subdomains_counts,
                "urls": urls_counts,
                "created_at": timestamp,
                "updated_at": timestamp
            })

    if new_domains:
        # Insert all new domains at once
        domains_collection.insert_many(new_domains)
        update_counts_program(program)  # Update counts for the program after insertion
        
        for domain in new_domains:
            print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| adding domain | domain {Fore.BLUE}{Style.BRIGHT}{domain['domain']}{Style.RESET_ALL} added to program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL}")

def list_domains(domain='*', program='*', brief=False, count=False, scope=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # For potential logging

    # Check if the program exists if a specific program is requested
    if program != '*':
        if programs_collection.count_documents({"program": program}) == 0:
            print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| listing domain | program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL} does not exist")
            return

        query = {"program": program}
    else:
        query = {}

    if domain != '*':
        query["domain"] = domain

    if scope:
        query["scope"] = scope

    domains = list(domains_collection.find(query, {
        "_id": 0,  # Exclude the MongoDB _id field
        "domain": 1,
        "program": 1,
        "scope": 1,
        "subdomains": 1,
        "urls": 1,
        "created_at": 1,
        "updated_at": 1
    }))

    if not domains:
        print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| listing domain | no domains found")
        return

    if count:
        count_result = len(domains)
        print(count_result)
        return

    if brief:
        for domain in domains:
            print(domain['domain'])  # Print only the domain name
    else:
        print(json.dumps({"domains": domains}, indent=4))

def delete_domain(domain='*', program='*', scope=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # For potential logging

    if program != '*':
        if programs_collection.count_documents({"program": program}) == 0:
            print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| deleting domain | program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL} does not exist")
            return

    if domain == '*':
        # Deleting all records
        counts = {
            'urls': urls_collection.count_documents({}),
            'subdomains': subdomains_collection.count_documents({}),
            'domains': domains_collection.count_documents({})
        }

        # Delete records based on scope or all if scope is None
        if scope is None:
            urls_collection.delete_many({})
            subdomains_collection.delete_many({})
            domains_collection.delete_many({})
        else:
            urls_collection.delete_many({"scope": scope})
            subdomains_collection.delete_many({"scope": scope})
            domains_collection.delete_many({"scope": scope})

        if counts['domains'] == 0:
            print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| deleting domain | domain table is empty")
        else:
            update_counts_program(program)
            print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| deleting domain | deleted {Fore.BLUE}{Style.BRIGHT}{counts['domains']}{Style.RESET_ALL} domains, {Fore.BLUE}{Style.BRIGHT}{counts['subdomains']}{Style.RESET_ALL} subdomains, and {Fore.BLUE}{Style.BRIGHT}{counts['urls']}{Style.RESET_ALL} urls")
    
    else:
        if program == '*':
            # Deleting records across all programs
            counts = {
                'urls': urls_collection.count_documents({"domain": domain}),
                'subdomains': subdomains_collection.count_documents({"domain": domain}),
                'domains': domains_collection.count_documents({"domain": domain})
            }

            # Delete based on scope or all if scope is None
            if scope is None:
                subdomains_collection.delete_many({"domain": domain})
                urls_collection.delete_many({"domain": domain})
                domains_collection.delete_many({"domain": domain})
            else:
                subdomains_collection.delete_many({"domain": domain, "scope": scope})
                urls_collection.delete_many({"domain": domain, "scope": scope})
                domains_collection.delete_many({"domain": domain, "scope": scope})

            if counts['domains'] == 0:
                print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| deleting domain | domain {Fore.BLUE}{Style.BRIGHT}{domain}{Style.RESET_ALL} does not exist")
            else:
                update_counts_program(program)
                print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| deleting domain | deleted {Fore.BLUE}{Style.BRIGHT}{domain}{Style.RESET_ALL} with {Fore.BLUE}{Style.BRIGHT}{counts['subdomains']}{Style.RESET_ALL} subdomains and {Fore.BLUE}{Style.BRIGHT}{counts['urls']}{Style.RESET_ALL} urls")
        
        else:
            # Deleting records in a specific program
            counts = {
                'urls': urls_collection.count_documents({"domain": domain, "program": program}),
                'subdomains': subdomains_collection.count_documents({"domain": domain, "program": program}),
                'domains': domains_collection.count_documents({"domain": domain, "program": program})
            }

            # Delete based on scope or all if scope is None
            if scope is None:
                subdomains_collection.delete_many({"domain": domain, "program": program})
                domains_collection.delete_many({"domain": domain, "program": program})
            else:
                subdomains_collection.delete_many({"domain": domain, "program": program, "scope": scope})
                domains_collection.delete_many({"domain": domain, "program": program, "scope": scope})

            if counts['domains'] == 0:
                print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| deleting domain | domain {Fore.BLUE}{Style.BRIGHT}{domain}{Style.RESET_ALL} does not exist")
            else:
                update_counts_program(program)
                print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| deleting domain | deleted {Fore.BLUE}{Style.BRIGHT}{domain}{Style.RESET_ALL} from {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL} with {Fore.BLUE}{Style.BRIGHT}{counts['subdomains']}{Style.RESET_ALL} subdomains and {Fore.BLUE}{Style.BRIGHT}{counts['urls']}{Style.RESET_ALL} urls")

def add_subdomain(subdomain_or_file, domain, program, sources=None, unsources=None, scope=None, resolved=None,
                  ip_address=None, cdn_status=None, cdn_name=None, unip=None, uncdn_name=None):
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Check if the program exists
    if programs_collection.count_documents({"program": program}) == 0:
        print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| adding subdomain | program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL} does not exist")
        return

    # Check if the domain exists
    if domains_collection.count_documents({"domain": domain, "program": program}) == 0:
        print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| adding subdomain | domain {Fore.BLUE}{Style.BRIGHT}{domain}{Style.RESET_ALL} does not exist in program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL}")
        return

    # Check if the input is a file
    if os.path.isfile(subdomain_or_file):
        with open(subdomain_or_file, 'r') as file:
            subdomains = [line.strip() for line in file if line.strip()]
    else:
        subdomains = [subdomain_or_file]

    new_subdomains = []  # List to hold new subdomain entries
    
    for subdomain in subdomains:
        existing = subdomains_collection.find_one({"subdomain": subdomain, "domain": domain, "program": program})

        urls_counts = urls_collection.count_documents({"program": program, "domain": domain, "subdomain": subdomain})

        update_fields = {}
        if existing:
            # Update fields if parameters are provided
            if sources:
                current_sources = existing.get('source', "").split(", ") if existing.get('source') else []
                current_sources_set = set(current_sources)
                new_sources = [src.strip() for src in sources if src.strip()]
                current_sources_set.update(new_sources)
                updated_sources = ", ".join(sorted(current_sources_set)) if current_sources_set else ""
                if updated_sources != existing['source']:  # Check if sources have changed
                    update_fields['source'] = updated_sources

            if unsources:
                current_sources = existing.get('source', "").split(", ") if existing.get('source') else []
                for unsource in unsources:
                    unsource = unsource.strip()
                    if unsource in current_sources:
                        current_sources.remove(unsource)
                updated_sources = ", ".join(current_sources) if current_sources else ""
                if updated_sources != existing['source']:  # Check if sources have changed
                    update_fields['source'] = updated_sources

            if scope is not None and scope != existing.get('scope'):
                update_fields['scope'] = scope

            if resolved is not None and resolved != existing.get('resolved'):
                update_fields['resolved'] = resolved

            if ip_address is not None and ip_address != existing.get('ip_address'):
                update_fields['ip_address'] = ip_address

            if unip and existing.get('ip_address') != 'none':
                update_fields['ip_address'] = 'none'

            if cdn_status is not None and cdn_status != existing.get('cdn_status'):
                update_fields['cdn_status'] = cdn_status

            if uncdn_name and existing.get('cdn_name') != 'none':
                update_fields['cdn_name'] = 'none'

            if cdn_name is not None and cdn_name != existing.get('cdn_name'):
                update_fields['cdn_name'] = cdn_name

            if update_fields:
                update_fields['updated_at'] = timestamp
                subdomains_collection.update_one({"subdomain": subdomain, "domain": domain, "program": program}, {"$set": update_fields})
                print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| updating subdomain | subdomain {Fore.BLUE}{Style.BRIGHT}{subdomain}{Style.RESET_ALL} in domain {Fore.BLUE}{Style.BRIGHT}{domain}{Style.RESET_ALL} in program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL} with updates: {Fore.BLUE}{Style.BRIGHT}{update_fields}{Style.RESET_ALL}")
            else:
                print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK} apprise {Style.RESET_ALL}| updating subdomain | No updates for subdomain {Fore.BLUE}{Style.BRIGHT}{subdomain}{Style.RESET_ALL} in domain {Fore.BLUE}{Style.BRIGHT}{domain}{Style.RESET_ALL} in program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL}")

        else:
            # Prepare new subdomain entry
            new_source_str = ", ".join(sources) if sources else ""
            new_subdomains.append({
                "subdomain": subdomain,
                "domain": domain,
                "program": program,
                "source": new_source_str,
                "scope": scope if scope is not None else "inscope",
                "urls": urls_counts,
                "resolved": resolved if resolved is not None else "no",
                "ip_address": ip_address if ip_address is not None else "none",
                "cdn_status": cdn_status if cdn_status is not None else "no",
                "cdn_name": cdn_name if cdn_name is not None else "none",
                "created_at": timestamp,
                "updated_at": timestamp
            })

    if new_subdomains:
        # Insert all new subdomains at once
        subdomains_collection.insert_many(new_subdomains)
        
        # Update counts for the program and domain after insertion
        update_counts_program(program)
        update_counts_domain(program, domain)

        for subdomain in new_subdomains:
            print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| adding subdomain | Subdomain {Fore.BLUE}{Style.BRIGHT}{subdomain['subdomain']}{Style.RESET_ALL} added to domain {Fore.BLUE}{Style.BRIGHT}{domain}{Style.RESET_ALL} in program {Fore.BLUE}{Style.BRIGHT}{program}{Style.BRIGHT} with sources: {Fore.BLUE}{Style.BRIGHT}{subdomain['source']}{Style.RESET_ALL}, scope: {Fore.BLUE}{Style.BRIGHT}{subdomain['scope']}{Style.RESET_ALL}, resolved: {Fore.BLUE}{Style.BRIGHT}{subdomain['resolved']}{Style.RESET_ALL}, IP: {Fore.BLUE}{Style.BRIGHT}{subdomain['ip_address']}{Style.RESET_ALL}, cdn_status: {Fore.BLUE}{Style.BRIGHT}{subdomain['cdn_status']}{Style.RESET_ALL}, CDN Name: {Fore.BLUE}{Style.BRIGHT}{subdomain['cdn_name']}{Style.RESET_ALL}")

def list_subdomains(subdomain='*', domain='*', program='*', sources=None, scope=None, resolved=None, brief=False, source_only=False,
                    cdn_status=None, ip=None, cdn_name=None, create_time=None, update_time=None, count=False, stats_source=False,
                    stats_scope=False, stats_cdn_status=False, stats_cdn_name=False, stats_resolved=False, stats_ip_address=False,
                    stats_program=False, stats_domain=False, stats_created_at=False, stats_updated_at=False):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Check if program exists if specified
    if program != '*':
        if programs_collection.count_documents({"program": program}) == 0:
            print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| listing subdomain | program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL} does not exist")
            return

    # Build filters
    filters = {}
    if program != '*':
        filters['program'] = program
    if domain != '*':
        filters['domain'] = domain
    if subdomain != '*':
        filters['subdomain'] = subdomain
    if scope:
        filters['scope'] = scope
    if resolved:
        filters['resolved'] = resolved
    if cdn_status:
        filters['cdn_status'] = cdn_status
    if ip:
        filters['ip_address'] = ip
    if cdn_name:
        filters['cdn_name'] = cdn_name

    # Handle create_time filtering
    if create_time:
        try:
            start_time, end_time = parse_time_range(create_time)
            filters['created_at'] = {"$gte": start_time, "$lte": end_time}
        except Exception as e:
            print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| Invalid create_time format: {e}")
            return

    # Handle update_time filtering
    if update_time:
        try:
            start_time, end_time = parse_time_range(update_time)
            filters['updated_at'] = {"$gte": start_time, "$lte": end_time}
        except Exception as e:
            print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| Invalid update_time format: {e}")
            return

    # Execute the query
    subdomains_cursor = subdomains_collection.find(filters)

    # Convert cursor to list
    subdomains = list(subdomains_cursor)

    # Initialize filtered_subdomains
    filtered_subdomains = subdomains  

    # Handle counting records based on filters
    if count:
        if source_only and sources:
            filtered_subdomains = [
                sub for sub in subdomains 
                if sub.get('source', '').strip() == sources[0]  # Exact match for source
            ]
        else:
            if sources:
                filtered_subdomains = [
                    sub for sub in subdomains 
                    if any(source in sub.get('source', '').split(',') for source in sources)
                ]
        print(len(filtered_subdomains))
        return

    # Further filtering for brief output if sources are provided
    if sources:
        # Normalize the sources input to a set for efficient lookup
        source_set = set(src.strip() for src in sources)
        
        if source_only:
            filtered_subdomains = [
                sub for sub in filtered_subdomains 
                if sub.get('source', '').strip() == sources[0]  # Exact match for source
            ]
        else:
            filtered_subdomains = [
                sub for sub in filtered_subdomains 
                if any(src.strip() in source_set for src in sub.get('source', '').split(','))
            ]

   
    # Statistics calculations
    def print_statistics(filtered, key_name, title):
        count_map = {}
        for sub in filtered:
            key_value = sub.get(key_name)
            if key_value:
                key_value = key_value.strip() if isinstance(key_value, str) else key_value
                count_map[key_value] = count_map.get(key_value, 0) + 1

        total_count = len(filtered)
        print(f"{title} statistics:")
        for key, count in count_map.items():
            percentage = (count / total_count) * 100 if total_count > 0 else 0
            print(f"{key}: {count} ({percentage:.2f}%)")

    # Output statistics if requested
    if stats_source:
        print_statistics(filtered_subdomains, 'source', "Source")
        return
    if stats_scope:
        print_statistics(filtered_subdomains, 'scope', "Scope")
        return
    if stats_cdn_status:
        print_statistics(filtered_subdomains, 'cdn_status', "CDN Status")
        return
    if stats_cdn_name:
        print_statistics(filtered_subdomains, 'cdn_name', "CDN Name")
        return
    if stats_resolved:
        print_statistics(filtered_subdomains, 'resolved', "Resolved Status")
        return
    if stats_ip_address:
        print_statistics(filtered_subdomains, 'ip_address', "IP Address")
        return
    if stats_program:
        print_statistics(filtered_subdomains, 'program', "Program")
        return
    if stats_domain:
        print_statistics(filtered_subdomains, 'domain', "Domain")
        return
    if stats_created_at:
        print_statistics(filtered_subdomains, 'created_at', "Created At")
        return
    if stats_updated_at:
        print_statistics(filtered_subdomains, 'updated_at', "Updated At")
        return

    # Output results in brief mode
    if filtered_subdomains:
        if brief:
            print("\n".join(sub['subdomain'] for sub in filtered_subdomains))
        else:
            for sub in filtered_subdomains:
                sub.pop('_id', None)  # Remove _id field
            print(json.dumps(filtered_subdomains, indent=4))

def delete_subdomain(sub='*', domain='*', program='*', scope=None, source=None, resolved=None, ip_address=None, cdn_status=None, cdn_name=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Check if program exists
    if program != '*':
        if programs_collection.count_documents({"program": program}) == 0:
            print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| deleting subdomain | program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL} does not exist")
            return

    # Check if domain exists
    if domain != '*':
        if domains_collection.count_documents({"domain": domain}) == 0:
            print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| deleting subdomain | domain {Fore.BLUE}{Style.BRIGHT}{domain}{Style.RESET_ALL} does not exist")
            return

    # Check if subdomain exists before deletion
    if sub != '*':
        if subdomains_collection.count_documents({"subdomain": sub, "domain": domain, "program": program}) == 0:
            print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| deleting subdomain | subdomain {Fore.BLUE}{Style.BRIGHT}{sub}{Style.RESET_ALL} does not exist in domain {Fore.BLUE}{Style.BRIGHT}{domain}{Style.RESET_ALL} and program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL}")
            return

    # Build the filter message to display which filters were used
    filter_msg = f"subdomain={sub}"
    if domain != "*":
        filter_msg += f", domain={domain}"
    if program != "*":
        filter_msg += f", program={program}"
    if scope:
        filter_msg += f", scope={scope}"
    if source:
        filter_msg += f", source={source}"
    if resolved:
        filter_msg += f", resolved={resolved}"
    if ip_address:
        filter_msg += f", ip_address={ip_address}"
    if cdn_status:
        filter_msg += f", cdn_status={cdn_status}"
    if cdn_name:
        filter_msg += f", cdn_name={cdn_name}"

    # Continue with the deletion process in the subdomains collection
    total_deleted = 0  # Keep track of total deletions

    if sub == '*':
        # Deleting all subdomains from all domains and programs
        query = {}

        if domain != '*':
            query['domain'] = domain

        if program != '*':
            query['program'] = program

        # Add filtering for source
        if source:
            query['source'] = {"$regex": source}

        # Add filtering for resolved status
        if resolved:
            query['resolved'] = resolved

        # Add filtering for scope
        if scope:
            query['scope'] = scope

        # Add filtering for IP address
        if ip_address:
            query['ip_address'] = ip_address

        # Add filtering for cdn_status
        if cdn_status:
            query['cdn_status'] = cdn_status

        # Add filtering for CDN name
        if cdn_name:
            query['cdn_name'] = cdn_name

        # Execute delete query for the subdomains collection
        result = subdomains_collection.delete_many(query)
        total_deleted = result.deleted_count

        if total_deleted > 0:
            update_counts_program(program)
            update_counts_domain(program, domain)
            print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| deleting subdomain | deleted {total_deleted} matching entries from {Fore.BLUE}{Style.BRIGHT}subdomains{Style.RESET_ALL} collection with filters: {Fore.BLUE}{Style.BRIGHT}{filter_msg}{Style.RESET_ALL}")

    else:
        # Delete a single subdomain with optional filters
        query = {"subdomain": sub}

        if domain != '*':
            query['domain'] = domain

        if program != '*':
            query['program'] = program

        # Add filtering for resolved status
        if resolved:
            query['resolved'] = resolved

        # Add filtering for scope
        if scope:
            query['scope'] = scope

        # Add filtering for IP address
        if ip_address:
            query['ip_address'] = ip_address

        # Add filtering for cdn_status
        if cdn_status:
            query['cdn_status'] = cdn_status

        # Add filtering for CDN name
        if cdn_name:
            query['cdn_name'] = cdn_name

        # Execute delete query for the subdomains collection
        result = subdomains_collection.delete_one(query)
        total_deleted = 1 if result.deleted_count > 0 else 0

        if total_deleted > 0:
            update_counts_program(program)
            update_counts_domain(program, domain)
            print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| deleting subdomain | deleted {total_deleted} matching entry from {Fore.BLUE}{Style.BRIGHT}subdomains{Style.RESET_ALL} collection with filters: {Fore.BLUE}{Style.BRIGHT}{filter_msg}{Style.RESET_ALL}")

    if total_deleted == 0:
        print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK} apprise {Style.RESET_ALL}| deleting subdomain | no subdomains were deleted with filters: {Fore.BLUE}{Style.BRIGHT}{filter_msg}{Style.RESET_ALL}")

def add_url(url, subdomain, domain, program, scheme=None, method=None, port=None, status_code=None, scope=None,
            ip_address=None, cdn_status=None, cdn_name=None, title=None, webserver=None, webtech=None, cname=None,
            location=None, flag=None, content_length=None, path=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Check if the program exists
    if not programs_collection.find_one({"program": program}):
        print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| adding url | program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL} does not exist")
        return

    # Check if the domain exists
    if not domains_collection.find_one({"domain": domain, "program": program}):
        print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| adding url | domain {Fore.BLUE}{Style.BRIGHT}{domain}{Style.RESET_ALL} does not exist in program '{program}'")
        return

    # Check if the subdomain exists
    if not subdomains_collection.find_one({"subdomain": subdomain, "domain": domain, "program": program}):
        print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| adding url | subdomain {Fore.BLUE}{Style.BRIGHT}{subdomain}{Style.RESET_ALL} in domain {Fore.BLUE}{Style.BRIGHT}{domain}{Style.RESET_ALL} does not exist in program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL}")
        return

    # Check if the url exists for the given method
    existing = urls_collection.find_one({"url": url, "subdomain": subdomain, "domain": domain, "program": program, "method": method})

    if existing:
        update_fields = {}
        
        # Check for updates in other fields
        if scheme is not None and scheme != existing.get("scheme"):
            update_fields['scheme'] = scheme
        if port is not None and port != existing.get("port"):
            update_fields['port'] = port
        if path is not None and path != existing.get("path"):
            update_fields['path'] = path
        if flag is not None and flag != existing.get("flag"):
            update_fields['flag'] = flag
        if status_code is not None and status_code != existing.get("status_code"):
            update_fields['status_code'] = status_code
        if scope is not None and scope != existing.get("scope"):
            update_fields['scope'] = scope
        if content_length is not None and content_length != existing.get("content_length"):
            update_fields['content_length'] = content_length
        if ip_address is not None and ip_address != existing.get("ip_address"):
            update_fields['ip_address'] = ip_address
        if cdn_status is not None and cdn_status != existing.get("cdn_status"):
            update_fields['cdn_status'] = cdn_status
        if cdn_name is not None and cdn_name != existing.get("cdn_name"):
            update_fields['cdn_name'] = cdn_name
        if title is not None and title != existing.get("title"):
            update_fields['title'] = title
        if webserver is not None and webserver != existing.get("webserver"):
            update_fields['webserver'] = webserver
        if webtech is not None and webtech != existing.get("webtech"):
            update_fields['webtech'] = webtech
        if cname is not None and cname != existing.get("cname"):
            update_fields['cname'] = cname
        if location is not None and location != existing.get("location"):
            update_fields['location'] = location

        # Always update the timestamp
        if update_fields:
            update_fields["updated_at"] = timestamp
            urls_collection.update_one(
                {"url": url, "subdomain": subdomain, "domain": domain, "program": program, "method": method},
                {"$set": update_fields}
            )
            print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| updating url | url {Fore.BLUE}{Style.BRIGHT}{url}{Style.RESET_ALL} in subdomain {Fore.BLUE}{Style.BRIGHT}{subdomain}{Style.RESET_ALL} in domain {Fore.BLUE}{Style.BRIGHT}{domain}{Style.RESET_ALL} in program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL} with updates: {Fore.BLUE}{Style.BRIGHT}{update_fields}{Style.RESET_ALL}")
        else:
            print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK} apprise {Style.RESET_ALL}| updating url | No update for url {Fore.BLUE}{Style.BRIGHT}{url}{Style.RESET_ALL}")
    else:
        # Insert new url, regardless of existing records
        new_url_data = {
            "url": url,
            "subdomain": subdomain,
            "domain": domain,
            "program": program,
            "scheme": scheme if scheme is not None else "none",
            "method": method if method is not None else "none",
            "port": port if port is not None else "none",
            "path": path if path is not None else "/",
            "flag": flag if flag is not None else "none",
            "status_code": status_code if status_code is not None else "none",
            "scope": scope if scope is not None else "inscope",
            "content_length": content_length if content_length is not None else "none",
            "ip_address": ip_address if ip_address is not None else "none",
            "cdn_status": cdn_status if cdn_status is not None else "no",
            "cdn_name": cdn_name if cdn_name is not None else "none",
            "title": title if title is not None else "none",
            "webserver": webserver if webserver is not None else "none",
            "webtech": webtech if webtech is not None else "none",
            "cname": cname if cname is not None else "none",
            "location": location if location is not None else "none",
            "created_at": timestamp,
            "updated_at": timestamp
        }

        urls_collection.insert_one(new_url_data)
        update_counts_program(program)
        update_counts_domain(program, domain)
        update_counts_subdomain(program, domain, subdomain)
        print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| adding url | url {Fore.BLUE}{Style.BRIGHT}{url}{Style.RESET_ALL} added to subdomain {Fore.BLUE}{Style.BRIGHT}{subdomain}{Style.RESET_ALL} in domain {Fore.BLUE}{Style.BRIGHT}{domain}{Style.RESET_ALL} in program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL} with details: scheme={Fore.BLUE}{Style.BRIGHT}{scheme}{Style.RESET_ALL}, method={Fore.BLUE}{Style.BRIGHT}{method}{Style.RESET_ALL}, port={Fore.BLUE}{Style.BRIGHT}{port}{Style.RESET_ALL}, status_code={Fore.BLUE}{Style.BRIGHT}{status_code}{Style.RESET_ALL}, location={Fore.BLUE}{Style.BRIGHT}{location}{Style.RESET_ALL}, scope={Fore.BLUE}{Style.BRIGHT}{scope}{Style.RESET_ALL}, cdn_status={Fore.BLUE}{Style.BRIGHT}{cdn_status}{Style.RESET_ALL}, cdn_name={Fore.BLUE}{Style.BRIGHT}{cdn_name}{Style.RESET_ALL}, title={Fore.BLUE}{Style.BRIGHT}{title}{Style.RESET_ALL}, webserver={Fore.BLUE}{Style.BRIGHT}{webserver}{Style.RESET_ALL}, webtech={Fore.BLUE}{Style.BRIGHT}{webtech}{Style.RESET_ALL}, cname={Fore.BLUE}{Style.BRIGHT}{cname}{Style.RESET_ALL}")

def list_urls(url='*', subdomain='*', domain='*', program='*', scheme=None, method=None, port=None, 
               status_code=None, ip=None, cdn_status=None, cdn_name=None, title=None, webserver=None,
               webtech=None, cname=None, create_time=None, update_time=None, brief=False, scope=None,
               location=None, count=False, stats_subdomain=False, stats_domain=False, stats_program=False,
               stats_scheme=False, stats_method=False, stats_port=False, stats_status_code=False, stats_scope=False, 
               stats_title=False, stats_ip_address=False, stats_cdn_status=False, stats_cdn_name=False, stats_webserver=False,
               stats_webtech=False, stats_cname=False, stats_location=False, stats_created_at=False, stats_updated_at=False, 
               flag=None, content_length=None, path=None, stats_flag=None, stats_content_length=None, stats_path=None):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Check if the program exists if program is not '*'
    if program != '*':
        if not programs_collection.find_one({"program": program}):
            print(f"{timestamp} | error | listing url | program {program} does not exist")
            return

    # Building the MongoDB query
    query = {}
    if program != '*':
        query["program"] = program
    if url != '*':
        query["url"] = url
    if subdomain != '*':
        query["subdomain"] = subdomain
    if domain != '*':
        query["domain"] = domain
    if scope:
        query["scope"] = scope
    if scheme:
        query["scheme"] = scheme
    if method:
        query["method"] = method
    if port:
        query["port"] = port
    if status_code:
        query["status_code"] = status_code
    if ip:
        query["ip_address"] = ip
    if cdn_status:
        query["cdn_status"] = cdn_status
    if cdn_name:
        query["cdn_name"] = cdn_name
    if title:
        query["title"] = title
    if webserver:
        query["webserver"] = webserver
    if webtech:
        query["webtech"] = {"$regex": webtech}  # Using regex for partial match
    if cname:
        query["cname"] = cname
    if location:
        query["location"] = location
    if flag:
        query["flag"] = flag
    if path:
        query["path"] = path
    if content_length:
        query["content_length"] = content_length

    # Time filters
    if create_time:
        start_time, end_time = parse_time_range(create_time)
        query["created_at"] = {"$gte": start_time, "$lte": end_time}
    if update_time:
        start_time, end_time = parse_time_range(update_time)
        query["updated_at"] = {"$gte": start_time, "$lte": end_time}

    # If count is requested
    if count:
        count_result = urls_collection.count_documents(query)
        print(count_result)
        return

    # Execute the query
    live_urls = list(urls_collection.find(query))

    # Remove _id from each document
    for url in live_urls:
        url.pop('_id', None)

    # Handle output for statistics
    total_count = len(live_urls)

    def print_statistics(statistics):
        for stat_name, count in statistics.items():
            percentage = (count / total_count) * 100 if total_count > 0 else 0
            print(f"{stat_name}: {count} ({percentage:.2f}%)")
    
    # Collect statistics
    if stats_subdomain:
        subdomain_count = {}
        for sub in live_urls:
            subdom = sub.get('subdomain', '').strip()
            subdomain_count[subdom] = subdomain_count.get(subdom, 0) + 1
        print("Subdomain statistics:")
        print_statistics(subdomain_count)
        return

    if stats_domain:
        domain_count = {}
        for sub in live_urls:
            dom = sub.get('domain', '').strip()
            domain_count[dom] = domain_count.get(dom, 0) + 1
        print("Domain statistics:")
        print_statistics(domain_count)
        return

    if stats_program:
        program_count = {}
        for sub in live_urls:
            prog = sub.get('program', '').strip()
            program_count[prog] = program_count.get(prog, 0) + 1
        print("Program statistics:")
        print_statistics(program_count)
        return

    if stats_scheme:
        scheme_count = {}
        for sub in live_urls:
            sch = sub.get('scheme', '').strip()
            scheme_count[sch] = scheme_count.get(sch, 0) + 1
        print("Scheme statistics:")
        print_statistics(scheme_count)
        return

    if stats_method:
        method_count = {}
        for sub in live_urls:
            meth = sub.get('method', '').strip()
            method_count[meth] = method_count.get(meth, 0) + 1
        print("Method statistics:")
        print_statistics(method_count)
        return

    if stats_port:
        port_count = {}
        for sub in live_urls:
            prt = sub.get('port')
            port_count[prt] = port_count.get(prt, 0) + 1
        print("Port statistics:")
        print_statistics(port_count)
        return

    if stats_status_code:
        status_code_count = {}
        for sub in live_urls:
            status = sub.get('status_code')
            status_code_count[status] = status_code_count.get(status, 0) + 1
        print("Status Code statistics:")
        print_statistics(status_code_count)
        return

    if stats_scope:
        scope_count = {}
        for sub in live_urls:
            sc = sub.get('scope', '').strip()
            scope_count[sc] = scope_count.get(sc, 0) + 1
        print("Scope statistics:")
        print_statistics(scope_count)
        return

    if stats_title:
        title_count = {}
        for sub in live_urls:
            title_val = sub.get('title', '').strip()
            title_count[title_val] = title_count.get(title_val, 0) + 1
        print("Title statistics:")
        print_statistics(title_count)
        return

    if stats_ip_address:
        ip_count = {}
        for sub in live_urls:
            ip_val = sub.get('ip_address', '').strip()
            ip_count[ip_val] = ip_count.get(ip_val, 0) + 1
        print("IP Address statistics:")
        print_statistics(ip_count)
        return

    if stats_cdn_status:
        cdn_status_count = {}
        for sub in live_urls:
            cdn_status_val = sub.get('cdn_status', '').strip()
            cdn_status_count[cdn_status_val] = cdn_status_count.get(cdn_status_val, 0) + 1
        print("CDN Status statistics:")
        print_statistics(cdn_status_count)
        return

    if stats_cdn_name:
        cdn_name_count = {}
        for sub in live_urls:
            cdn_name_val = sub.get('cdn_name', '').strip()
            cdn_name_count[cdn_name_val] = cdn_name_count.get(cdn_name_val, 0) + 1
        print("CDN Name statistics:")
        print_statistics(cdn_name_count)
        return

    if stats_webserver:
        webserver_count = {}
        for sub in live_urls:
            webserver_val = sub.get('webserver', '').strip()
            webserver_count[webserver_val] = webserver_count.get(webserver_val, 0) + 1
        print("Webserver statistics:")
        print_statistics(webserver_count)
        return

    if stats_webtech:
        webtech_count = {}
        for sub in live_urls:
            webtech_val = sub.get('webtech', '').strip()
            webtech_count[webtech_val] = webtech_count.get(webtech_val, 0) + 1
        print("Webtech statistics:")
        print_statistics(webtech_count)
        return

    if stats_cname:
        cname_count = {}
        for sub in live_urls:
            cname_val = sub.get('cname', '').strip()
            cname_count[cname_val] = cname_count.get(cname_val, 0) + 1
        print("CNAME statistics:")
        print_statistics(cname_count)
        return

    if stats_location:
        location_count = {}
        for sub in live_urls:
            location_val = sub.get('location', '').strip()
            location_count[location_val] = location_count.get(location_val, 0) + 1
        print("Location statistics:")
        print_statistics(location_count)
        return

    if stats_created_at:
        created_at_count = {}
        for sub in live_urls:
            created_at_val = sub.get('created_at')
            created_at_count[created_at_val] = created_at_count.get(created_at_val, 0) + 1
        print("Created At statistics:")
        print_statistics(created_at_count)
        return

    if stats_updated_at:
        updated_at_count = {}
        for sub in live_urls:
            updated_at_val = sub.get('updated_at')
            updated_at_count[updated_at_val] = updated_at_count.get(updated_at_val, 0) + 1
        print("Updated At statistics:")
        print_statistics(updated_at_count)
        return

    if stats_flag:
        flag_count = {}
        for sub in live_urls:
            flag_val = sub.get('flag')
            flag_count[flag_val] = flag_count.get(flag_val, 0) + 1
        print("Flag statistics:")
        print_statistics(flag_count)
        return

    if stats_content_length:
        content_length_count = {}
        for sub in live_urls:
            content_length_val = sub.get('content_length')
            content_length_count[content_length_val] = content_length_count.get(content_length_val, 0) + 1
        print("Content Length statistics:")
        print_statistics(content_length_count)
        return

    if stats_path:
        path_count = {}
        for sub in live_urls:
            path_val = sub.get('path')
            path_count[path_val] = path_count.get(path_val, 0) + 1
        print("Path statistics:")
        print_statistics(path_count)
        return

    # Print the URLs
    if brief:
        for url in live_urls:
            print(url.get('url'))
    else:
        print(json.dumps(live_urls, indent=2))

def delete_url(url='*', subdomain='*', domain='*', program='*', scope=None, scheme=None, 
               method=None, port=None, status_code=None, ip_address=None,
               cdn_status=None, cdn_name=None, title=None, webserver=None, 
               webtech=None, cname=None, location=None, flag=None, path=None, content_length=None):
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Check if the program exists if program is not '*'
    if program != '*':
        if not programs_collection.find_one({"program": program}):
            print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| deleting url | program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL} does not exist")
            return

    # Start building the delete query
    query = {}
    
    # Handle filtering for each parameter
    if program != '*':
        query["program"] = program
    if subdomain != '*':
        query["subdomain"] = subdomain
    if domain != '*':
        query["domain"] = domain
    if url != '*':
        query["url"] = url
    if scope:
        query["scope"] = scope
    if scheme:
        query["scheme"] = scheme
    if method:
        query["method"] = method
    if port:
        query["port"] = port
    if status_code:
        query["status_code"] = status_code
    if ip_address:
        query["ip_address"] = ip_address
    if cdn_status:
        query["cdn_status"] = cdn_status
    if cdn_name:
        query["cdn_name"] = cdn_name
    if title:
        query["title"] = title
    if webserver:
        query["webserver"] = webserver
    if webtech:
        query["webtech"] = webtech
    if cname:
        query["cname"] = cname
    if location:
        query["location"] = location
    if flag:
        query["flag"] = flag
    if path:
        query["path"] = path
    if content_length:
        query["content_length"] = content_length

    # Execute the delete query
    result = urls_collection.delete_many(query)
    
    update_counts_program(program)
    update_counts_domain(program, domain)
    update_counts_subdomain(program, domain, subdomain)
    
    # Confirm deletion
    if result.deleted_count > 0:
        print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| deleting url | deleted {result.deleted_count} live entries for program {program} with filters: "
              f"subdomain={subdomain}, domain={domain}, url={url}, scope={scope}, "
              f"scheme={scheme}, method={method}, "
              f"port={port}, status_code={status_code}, ip_address={ip_address}, cdn_status={cdn_status}, "
              f"cdn_name={cdn_name}, title={title}, "
              f"webserver={webserver}, webtech={webtech}, "
              f"cname={cname}, flag={flag}, path={path}, content_length={content_length}")

def is_valid_ip(ip):
    # Simple regex to validate an IP address
    ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    return ip_pattern.match(ip)

def add_ips(input_value, program, cidr=None, asn=None, port=None, service=None, cves=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Check if the program exists
    if not programs_collection.find_one({"program": program}):
        print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| adding ip | program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL} does not exist")
        return

    # Process CVEs as a list (if provided)
    cves_list = ', '.join(cves) if cves else None

    # Convert ports to a list of strings if provided and remove duplicates
    ports = list(map(str, port)) if port else None
    if ports:
        ports = list(set(ports))  # Remove duplicates
        ports.sort()

    # Handle input as either a file or a single IP address
    ips = []

    if is_valid_ip(input_value):
        ips.append(input_value)
    else:
        try:
            with open(input_value, 'r') as file:
                for line in file:
                    ip = line.strip()
                    if is_valid_ip(ip):
                        ips.append(ip)
                    else:
                        print(f"Invalid IP address in file: {ip}")
        except Exception as e:
            print(f"Error reading file {input_value}: {e}")
            return

    for ip in ips:
        # Check if the IP already exists in the specified program
        existing_entry = cidrs_collection.find_one({"ip": ip, "program": program})

        update_fields = {}

        if existing_entry:
            existing_ports = existing_entry.get("port", "")
            existing_service = existing_entry.get("service")
            existing_cves = existing_entry.get("cves")
            existing_cidr = existing_entry.get("cidr")
            existing_asn = existing_entry.get("asn")

            # Update fields if parameters are provided
            if ports is not None:
                ports_str = ', '.join(ports)
                if sorted(existing_ports.split(',')) != sorted(ports):
                    update_fields['port'] = ports_str

            if service is not None and service != existing_service:
                update_fields['service'] = service
            
            if cves_list is not None and cves_list != existing_cves:
                update_fields['cves'] = cves_list
            
            if cidr is not None and cidr != existing_cidr:
                update_fields['cidr'] = cidr
            
            if asn is not None and asn != existing_asn:
                update_fields['asn'] = asn

            # Update the entry only if there are changes
            if update_fields:
                update_fields['updated_at'] = timestamp
                cidrs_collection.update_one(
                    {"ip": ip, "program": program},
                    {"$set": update_fields}
                )
                print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| updating ip | IP {Fore.BLUE}{Style.BRIGHT}{ip}{Style.RESET_ALL} updated in program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL} with updates: {Fore.BLUE}{Style.BRIGHT}{update_fields}{Style.RESET_ALL}")
            else:
                print(f"{timestamp} |{Back.YELLOW}{Fore.BLACK} apprise {Style.RESET_ALL}| updating ip | IP {Fore.BLUE}{Style.BRIGHT}{ip}{Style.RESET_ALL} is unchanged in program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL}")
        else:
            # Insert a new record with the current timestamp
            ports_str = ', '.join(ports) if ports else None
            new_entry = {
                "ip": ip,
                "program": program,
                "cidr": cidr if cidr is not None else "none",
                "asn": asn if asn is not None else "none",
                "port": ports_str if ports_str is not None else "none",
                "service": service if service is not None else "none",
                "cves": cves_list if cves_list is not None else "none",
                "created_at": timestamp,
                "updated_at": timestamp
            }

            update_counts_program(program)
            cidrs_collection.insert_one(new_entry)
            print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| adding ip | IP {Fore.BLUE}{Style.BRIGHT}{ip}{Style.RESET_ALL} added to program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL} with {{ 'port': {Fore.BLUE}{Style.BRIGHT}{ports_str}{Style.RESET_ALL} }}")

def list_ip(ip='*', program='*', cidr=None, asn=None, port=None, service=None, 
            cves=None, brief=False, create_time=None, update_time=None, count=False, 
            stats_domain=False, stats_cidr=False, stats_asn=False, stats_port=False):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Check if the program exists if program is not '*'
    if program != '*':
        if not programs_collection.find_one({"program": program}):
            print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| listing ip | program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL} does not exist")
            return

    # Base query for listing IPs
    query = {}
    
    # Building the query filters
    if program != '*':
        query['program'] = program
    if ip != '*':
        query['ip'] = ip
    if cidr:
        query['cidr'] = cidr
    if asn:
        query['asn'] = asn
    if service:
        query['service'] = service
    if cves:
        if isinstance(cves, str):  # Ensure cves is a string
            query['cves'] = {"$regex": cves}
    if create_time:
        start_time, end_time = parse_time_range(create_time)
        query['created_at'] = {"$gte": start_time, "$lte": end_time}
    if update_time:
        start_time, end_time = parse_time_range(update_time)
        query['updated_at'] = {"$gte": start_time, "$lte": end_time}
    
    # Handling port filtering
    if port:
        if isinstance(port, list):
            query['port'] = {"$in": [str(p) for p in port]}  # Ensure all ports are strings
        else:
            # Convert port to string if it's not already
            port_str = str(port)
            query['$or'] = [
                {"port": port_str},
                {"port": {"$regex": port_str}}
            ]

    # If count is requested, modify the query
    if count:
        count_result = cidrs_collection.count_documents(query)
        print(count_result)
        return

    # Execute the final query and exclude the _id field
    ips = list(cidrs_collection.find(query, {"_id": 0}))

    # Handle statistics
    def print_statistics(stat_type, key_index):
        count_map = {}
        total_count = len(ips)
        for ip_record in ips:
            key_value = ip_record[key_index]
            count_map[key_value] = count_map.get(key_value, 0) + 1
        
        print(f"{stat_type} statistics:")
        for key_value, count in count_map.items():
            percentage = (count / total_count) * 100 if total_count > 0 else 0
            print(f"{key_value}: {count} ({percentage:.2f}%)")

    if stats_domain:
        print_statistics("Domain", "program")  # Adjust index based on your data structure
        return
    if stats_cidr:
        print_statistics("CIDR", "cidr")  # Adjust index based on your data structure
        return
    if stats_asn:
        print_statistics("ASN", "asn")  # Adjust index based on your data structure
        return
    if stats_port:
        print_statistics("Port", "port")  # Adjust index based on your data structure
        return

    # Handle output
    if ips:
        if brief:
            unique_ips = set(ip_record['ip'] for ip_record in ips)  # Use a set for unique IPs
            print("\n".join(unique_ips))  # Print unique IP addresses
        else:
            print(json.dumps(ips, default=str, indent=4))  # Print the full records

def delete_ip(ip='*', program='*', asn=None, cidr=None, port=None, service=None, cves=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build the base query for deletion
    query = {}

    # Handle program filtering
    if program != '*':
        query['program'] = program

    # Handle IP filtering
    if ip != '*':
        query['ip'] = ip

    # Handle additional filters
    if asn:
        query['asn'] = asn

    if cidr:
        query['cidr'] = cidr

    # Handle port filtering
    if port:
        query['$or'] = [
            {"port": port},
            {"port": {"$regex": port}}  # Allow partial matches for ports
        ]

    if service:
        query['service'] = service

    if cves:
        query['cves'] = {"$regex": cves}  # Assuming CVEs are stored in a way that supports regex

    # Check if any documents match the criteria before deletion
    if cidrs_collection.count_documents(query) == 0:
        print(f"{timestamp} | error | No matching IP found for deletion with specified filters.")
        return

    # Perform the deletion
    delete_result = cidrs_collection.delete_many(query)
    if delete_result.deleted_count > 0:
        update_counts_program(program)  # Implement this function as needed
        print(f"{timestamp} |{Back.GREEN}{Fore.BLACK} success {Style.RESET_ALL}| deleting ip | IP(s) deleted from program {Fore.BLUE}{Style.BRIGHT}{program}{Style.RESET_ALL} with specified filters.")
    else:
        print(f"{timestamp} |{Back.RED}{Fore.BLACK}  error  {Style.RESET_ALL}| deleting ip | No IPs were deleted with the specified filters")

def parse_time_range(time_range_str):
    # Handle time ranges in the format 'start_time,end_time'
    times = time_range_str.split(',')
    if len(times) == 1:
        # If only one time is provided, assume the end time is the end of that day
        start_time, end_time = parse_single_time(times[0])
        end_time = end_time.replace(hour=23, minute=59, second=59)  # Adjust end time to end of the day
    elif len(times) == 2:
        # If two times are provided, parse the start and end times
        start_time = parse_single_time(times[0])[0]
        end_time = parse_single_time(times[1])[1]
    else:
        raise ValueError(f"Invalid time range format: {time_range_str}")
    return start_time, end_time

def parse_single_time(time_str):
    # Parse a single time and return start and end times
    formats = ['%Y-%m-%d-%H:%M', '%Y-%m-%d-%H', '%Y-%m-%d', '%Y-%m', '%Y']
    for fmt in formats:
        try:
            start_time = datetime.strptime(time_str, fmt)
            if fmt == '%Y-%m-%d-%H:%M':
                end_time = start_time + timedelta(minutes=1) - timedelta(seconds=1)
            elif fmt == '%Y-%m-%d-%H':
                end_time = start_time + timedelta(hours=1) - timedelta(seconds=1)
            elif fmt == '%Y-%m-%d':
                end_time = start_time + timedelta(days=1) - timedelta(seconds=1)
            elif fmt == '%Y-%m':
                # Handle month transition correctly
                if start_time.month == 12:
                    end_time = start_time.replace(year=start_time.year + 1, month=1, day=1) - timedelta(seconds=1)
                else:
                    end_time = start_time.replace(month=start_time.month + 1, day=1) - timedelta(seconds=1)
            elif fmt == '%Y':
                end_time = start_time.replace(year=start_time.year + 1, month=1, day=1) - timedelta(seconds=1)
            return start_time, end_time
        except ValueError:
            continue
    raise ValueError(f"Invalid time format: {time_str}")

def main():
    parser = argparse.ArgumentParser(description='Manage programs, domains, subdomains, and IPs')
    sub_parser = parser.add_subparsers(dest='command')

    # program commands
    program_parser = sub_parser.add_parser('program', help='Manage programs')
    program_action_parser = program_parser.add_subparsers(dest='action')

    program_action_parser.add_parser('add', help='add a new program').add_argument('program', help='Name of the program')

    list_programs_parser = program_action_parser.add_parser('list', help='List programs')
    list_programs_parser.add_argument('program', help="program name or wildcard '*' for all programs")
    list_programs_parser.add_argument('--brief', action='store_true', help='Show only program names')
    list_programs_parser.add_argument('--count', action='store_true', help='Count the number of returned records')


    delete_programs_parser = program_action_parser.add_parser('delete', help='Delete a program')
    delete_programs_parser.add_argument('program', help='Name of the program')
    delete_programs_parser.add_argument('--all', action='store_true', help='Delete all data related to the program')


    # Domain commands
    domain_parser = sub_parser.add_parser('domain', help='Manage domains in a program')
    domain_action_parser = domain_parser.add_subparsers(dest='action')

    add_domain_parser = domain_action_parser.add_parser('add', help='Add a domain')
    add_domain_parser.add_argument('domain', help='Domain name')
    add_domain_parser.add_argument('program', help='Program name')
    add_domain_parser.add_argument('--scope', choices=['inscope', 'outscope'], help='Scope of the domain (leave empty to keep current scope)')


    list_domains_parser = domain_action_parser.add_parser('list', help='List domains in a program')
    list_domains_parser.add_argument('domain', help='Domain name (use "*" for all domains)')
    list_domains_parser.add_argument('program', help='program name (use "*" for all programs)')
    list_domains_parser.add_argument('--scope', choices=['inscope', 'outscope'], help='Filter domains by scope')
    list_domains_parser.add_argument('--brief', action='store_true', help='Show only domain names')
    list_domains_parser.add_argument('--count', action='store_true', help='Count the number of returned records')


    delete_domain_parser = domain_action_parser.add_parser('delete', help='Delete a domain')
    delete_domain_parser.add_argument('domain', help='Domain name')
    delete_domain_parser.add_argument('program', help='program name')
    delete_domain_parser.add_argument('--scope', choices=['inscope', 'outscope'], help='Scope of the domain (default: inscope)')

    # Subdomain commands
    subdomain_parser = sub_parser.add_parser('subdomain', help='Manage subdomains in a program')
    subdomain_action_parser = subdomain_parser.add_subparsers(dest='action')

    add_subdomain_parser = subdomain_action_parser.add_parser('add', help='Add a subdomain')
    add_subdomain_parser.add_argument('subdomain', help='Subdomain name')
    add_subdomain_parser.add_argument('domain', help='Domain name')
    add_subdomain_parser.add_argument('program', help='program name')
    add_subdomain_parser.add_argument('--source', nargs='*', help='Source(s) (comma-separated)')
    add_subdomain_parser.add_argument('--unsource', nargs='*', help='Source(s) to remove (comma-separated)')
    add_subdomain_parser.add_argument('--scope', choices=['inscope', 'outscope'], help='Scope')
    add_subdomain_parser.add_argument('--resolved', choices=['yes', 'no'], help='Resolved status')
    add_subdomain_parser.add_argument('--ip', help='IP address of the subdomain')
    add_subdomain_parser.add_argument('--unip', action='store_true', help='Remove IP address from the subdomain')
    add_subdomain_parser.add_argument('--cdn_status', choices=['yes', 'no'], help='CDN status')
    add_subdomain_parser.add_argument('--cdn_name', help='Name of the CDN provider')
    add_subdomain_parser.add_argument('--uncdn_name', action='store_true', help='Remove CDN name from the subdomain')

    list_subdomains_parser = subdomain_action_parser.add_parser('list', help='List subdomains')
    list_subdomains_parser.add_argument('subdomain', help='Subdomain name or wildcard')
    list_subdomains_parser.add_argument('domain', help='Domain name or wildcard')
    list_subdomains_parser.add_argument('program', help='Program name')
    list_subdomains_parser.add_argument('--source', nargs='*', help='Filter by source(s)')
    list_subdomains_parser.add_argument('--source-only', action='store_true', help='Show only matching subdomains')
    list_subdomains_parser.add_argument('--scope', choices=['inscope', 'outscope'], help='Filter by scope')
    list_subdomains_parser.add_argument('--resolved', choices=['yes', 'no'], help='Filter by resolved status')
    list_subdomains_parser.add_argument('--cdn_status', choices=['yes', 'no'], help='Filter by CDN status')
    list_subdomains_parser.add_argument('--ip', help='Filter by IP address')
    list_subdomains_parser.add_argument('--cdn_name', help='Filter by CDN provider name')
    list_subdomains_parser.add_argument('--brief', action='store_true', help='Show only subdomain names')
    list_subdomains_parser.add_argument('--create_time', help='Filter by creation time')
    list_subdomains_parser.add_argument('--update_time', help='Filter by last update time')
    list_subdomains_parser.add_argument('--count', action='store_true', help='Count the number of returned records')
    list_subdomains_parser.add_argument('--stats-source', action='store_true', help='Show statistics based on source')
    list_subdomains_parser.add_argument('--stats-scope', action='store_true', help='Show statistics based on scope')
    list_subdomains_parser.add_argument('--stats-cdn-status', action='store_true', help='Show statistics based on CDN status')
    list_subdomains_parser.add_argument('--stats-cdn-name', action='store_true', help='Show statistics based on CDN name')
    list_subdomains_parser.add_argument('--stats-resolved', action='store_true', help='Show statistics based on resolved status')
    list_subdomains_parser.add_argument('--stats-ip-address', action='store_true', help='Show statistics based on IP address')
    list_subdomains_parser.add_argument('--stats-program', action='store_true', help='Show statistics based on program')
    list_subdomains_parser.add_argument('--stats-domain', action='store_true', help='Show statistics based on domain')
    list_subdomains_parser.add_argument('--stats-created-at', action='store_true', help='Show statistics based on created time')
    list_subdomains_parser.add_argument('--stats-updated-at', action='store_true', help='Show statistics based on updated time')


    delete_subdomain_parser = subdomain_action_parser.add_parser('delete', help='Delete subdomains')
    delete_subdomain_parser.add_argument('subdomain', help='Subdomain to delete (use * to delete all)')
    delete_subdomain_parser.add_argument('domain', help='Domain name')
    delete_subdomain_parser.add_argument('program', help='program name')
    delete_subdomain_parser.add_argument('--resolved', choices=['yes', 'no'], help='Filter by resolved status')
    delete_subdomain_parser.add_argument('--source', help='Filter by source')
    delete_subdomain_parser.add_argument('--scope', choices=['inscope', 'outscope'], help='Filter by scope')
    delete_subdomain_parser.add_argument('--ip', help='Filter by IP address')
    delete_subdomain_parser.add_argument('--cdn_status', choices=['yes', 'no'], help='Filter by CDN status')
    delete_subdomain_parser.add_argument('--cdn_name', help='Filter by CDN provider name')

    # url commands
    url_parser = sub_parser.add_parser('url', help='Manage urls')
    live_action_parser = url_parser.add_subparsers(dest='action')

    add_url_parser = live_action_parser.add_parser('add', help='Add a live subdomain')
    add_url_parser.add_argument('url', help='URL of the live subdomain')
    add_url_parser.add_argument('subdomain', help='Subdomain')
    add_url_parser.add_argument('domain', help='Domain')
    add_url_parser.add_argument('program', help='program')
    add_url_parser.add_argument('--scheme', help='Scheme (http or https)')
    add_url_parser.add_argument('--method', help='HTTP method')
    add_url_parser.add_argument('--port', type=int, help='Port number')
    add_url_parser.add_argument('--status_code', type=int, help='HTTP status code')
    add_url_parser.add_argument('--scope', choices=['inscope', 'outscope'], help='Scope')
    add_url_parser.add_argument('--ip', help='IP address')
    add_url_parser.add_argument('--cdn_status', choices=['yes', 'no'], help='CDN status')
    add_url_parser.add_argument('--cdn_name', help='Name of the CDN provider')
    add_url_parser.add_argument('--title', help='Title of the live subdomain')
    add_url_parser.add_argument('--webserver', help='Web server type')
    add_url_parser.add_argument('--webtech', help='Web technologies (comma-separated)')
    add_url_parser.add_argument('--cname', help='CNAME of the live subdomain')
    add_url_parser.add_argument('--location', help='Redirect location')
    add_url_parser.add_argument('--flag', help='Specify a flag for url (blank, login, default_page)')
    add_url_parser.add_argument('--path', help='the path of url')
    add_url_parser.add_argument('--content_length', help='content_length of url')


    list_url_parser = live_action_parser.add_parser('list', help='List urls')
    list_url_parser.add_argument('url', help='URL of the live subdomain')
    list_url_parser.add_argument('subdomain', help='Subdomain name or wildcard')
    list_url_parser.add_argument('domain', help='Domain name or wildcard')
    list_url_parser.add_argument('program', help='program name')
    list_url_parser.add_argument('--scheme', help='Filter by scheme')
    list_url_parser.add_argument('--method', help='Filter by HTTP method')
    list_url_parser.add_argument('--port', type=int, help='Filter by port')
    list_url_parser.add_argument('--status_code', type=int, help='Filter by HTTP status code')
    list_url_parser.add_argument('--ip', help='Filter by IP address')
    list_url_parser.add_argument('--cdn_status', choices=['yes', 'no'], help='Filter by CDN status')
    list_url_parser.add_argument('--cdn_name', help='Filter by CDN name')
    list_url_parser.add_argument('--title', help='Filter by title')
    list_url_parser.add_argument('--webserver', help='Filter by webserver')
    list_url_parser.add_argument('--webtech', help='Filter by web technologies')
    list_url_parser.add_argument('--cname', help='Filter by CNAME')
    list_url_parser.add_argument('--create_time', help='Filter by creation time')
    list_url_parser.add_argument('--update_time', help='Filter by update time')
    list_url_parser.add_argument('--brief', action='store_true', help='Show only subdomain names')
    list_url_parser.add_argument('--scope', help='Filter by scope')
    list_url_parser.add_argument('--flag', help='Filter by flag')
    list_url_parser.add_argument('--path', help='Filter by path')
    list_url_parser.add_argument('--content_length', help='Filter by content_length')
    list_url_parser.add_argument('--location', help='Filter by redirect location')
    list_url_parser.add_argument('--count', action='store_true', help='Count the number of matching URLs')
    list_url_parser.add_argument('--stats-subdomain', action='store_true', help='Show statistics based on subdomain')
    list_url_parser.add_argument('--stats-domain', action='store_true', help='Show statistics based on domain')
    list_url_parser.add_argument('--stats-program', action='store_true', help='Show statistics based on program')
    list_url_parser.add_argument('--stats-scheme', action='store_true', help='Show statistics based on scheme')
    list_url_parser.add_argument('--stats-method', action='store_true', help='Show statistics based on HTTP method')
    list_url_parser.add_argument('--stats-port', action='store_true', help='Show statistics based on port')
    list_url_parser.add_argument('--stats-status-code', action='store_true', help='Show statistics based on status code')
    list_url_parser.add_argument('--stats-scope', action='store_true', help='Show statistics based on scope')
    list_url_parser.add_argument('--stats-title', action='store_true', help='Show statistics based on title')
    list_url_parser.add_argument('--stats-ip-address', action='store_true', help='Show statistics based on IP address')
    list_url_parser.add_argument('--stats-cdn-status', action='store_true', help='Show statistics based on CDN status')
    list_url_parser.add_argument('--stats-cdn-name', action='store_true', help='Show statistics based on CDN name')
    list_url_parser.add_argument('--stats-webserver', action='store_true', help='Show statistics based on webserver')
    list_url_parser.add_argument('--stats-webtech', action='store_true', help='Show statistics based on web technologies')
    list_url_parser.add_argument('--stats-cname', action='store_true', help='Show statistics based on CNAME')
    list_url_parser.add_argument('--stats-location', action='store_true', help='Show statistics based on location')
    list_url_parser.add_argument('--stats-flag', action='store_true', help='Show statistics based on flag')
    list_url_parser.add_argument('--stats-path', action='store_true', help='Show statistics based on path')
    list_url_parser.add_argument('--stats-content-length', action='store_true', help='Show statistics based on content_length')
    list_url_parser.add_argument('--stats-created-at', action='store_true', help='Show statistics based on creation time')
    list_url_parser.add_argument('--stats-updated-at', action='store_true', help='Show statistics based on update time')

    
    delete_url_parser = live_action_parser.add_parser('delete', help='Delete urls')
    delete_url_parser.add_argument('url', help='URL of the live subdomain')
    delete_url_parser.add_argument('subdomain', help='Subdomain')
    delete_url_parser.add_argument('domain', help='Domain')
    delete_url_parser.add_argument('program', help='program')
    delete_url_parser.add_argument('--scope', help='Filter by scope')
    delete_url_parser.add_argument('--cdn_status', choices=['yes', 'no'], help='Filter by CDN status')
    delete_url_parser.add_argument('--port', help='Filter by port')
    delete_url_parser.add_argument('--cdn_name', help='Filter by cdn name')
    delete_url_parser.add_argument('--scheme', help='Filter by scheme')
    delete_url_parser.add_argument('--method', help='Filter by HTTP method')
    delete_url_parser.add_argument('--path', help='Filter by path')
    delete_url_parser.add_argument('--flag', help='Filter by flag')
    delete_url_parser.add_argument('--status_code', help='Filter by HTTP status code')
    delete_url_parser.add_argument('--content_length', help='Filter by content_length')
    delete_url_parser.add_argument('--ip', help='Filter by ip address')
    delete_url_parser.add_argument('--title', help='Filter by title')
    delete_url_parser.add_argument('--webserver', help='Filter by webserver')
    delete_url_parser.add_argument('--webtech', help='Filter by webtech')
    delete_url_parser.add_argument('--cname', help='Filter by cname')
    delete_url_parser.add_argument('--location', help='Filter by location')

    # IP commands
    ip_parser = sub_parser.add_parser('ip', help='Manage IPs in a program')
    ip_action_parser = ip_parser.add_subparsers(dest='action')

    add_ip_parser = ip_action_parser.add_parser('add', help='Add an IP to a program')
    add_ip_parser.add_argument('ip', help='IP address')
    add_ip_parser.add_argument('program', help='Program name')
    add_ip_parser.add_argument('--cidr', help='CIDR notation')
    add_ip_parser.add_argument('--asn', help='Autonomous System Number')
    add_ip_parser.add_argument('--port', type=int, nargs='+', help='One or more port numbers')
    add_ip_parser.add_argument('--service', help='Service on the IP')
    add_ip_parser.add_argument('--cves', nargs='+', help='Comma-separated CVEs associated with the IP')

    list_ips_parser = ip_action_parser.add_parser('list', help='List IPs in a program')
    list_ips_parser.add_argument('ip', help='IP or CIDR (use * for all IPs)')
    list_ips_parser.add_argument('program', help='program (use * for all programs)')
    list_ips_parser.add_argument('--cidr', help='Filter by CIDR')
    list_ips_parser.add_argument('--asn', help='Filter by ASN')
    list_ips_parser.add_argument('--port', type=int, help='Filter by port')
    list_ips_parser.add_argument('--service', help='Filter by service')
    list_ips_parser.add_argument('--cves', help='Filter by CVEs')  # Added this line
    list_ips_parser.add_argument('--brief', action='store_true', help='Show only IP addresses')
    list_ips_parser.add_argument('--create_time', help='Filter by creation time')
    list_ips_parser.add_argument('--update_time', help='Filter by update time')
    list_ips_parser.add_argument('--count', action='store_true', help='Show count of matching IPs')
    list_ips_parser.add_argument('--stats-domain', action='store_true', help='Show statistics by domain')
    list_ips_parser.add_argument('--stats-cidr', action='store_true', help='Show statistics by CIDR')
    list_ips_parser.add_argument('--stats-asn', action='store_true', help='Show statistics by ASN')
    list_ips_parser.add_argument('--stats-port', action='store_true', help='Show statistics by port')

    delete_ip_parser = ip_action_parser.add_parser('delete', help='Delete IPs')
    delete_ip_parser.add_argument('ip', help='IP or CIDR (use * for all IPs)')  # Specify IP or CIDR
    delete_ip_parser.add_argument('program', help='program (use * for all programs)')  # Specify program
    delete_ip_parser.add_argument('--port', type=int, help='Filter by port')  # Optional port filter
    delete_ip_parser.add_argument('--service', help='Filter by service')  # Optional service filter
    delete_ip_parser.add_argument('--asn', help='Filter by ASN')  # Optional ASN filter
    delete_ip_parser.add_argument('--cidr', help='Filter by CIDR')  # Optional CIDR filter
    delete_ip_parser.add_argument('--cves', help='Filter by CVEs')  # Optional CVEs filter

    # setup
    program_parser = sub_parser.add_parser('setup', help='installing mongodb')
    
    args = parser.parse_args()

    # Handle commands
    if args.command == 'program':
        if args.action == 'add':
            add_program(program=args.program)
        elif args.action == 'list':
            list_programs(program=args.program, brief=args.brief, count=args.count)
        elif args.action == 'delete':
            delete_program(program=args.program, delete_all=args.all)

    elif args.command == 'domain':
        if args.action == 'add':
            add_domain(args.domain, args.program, scope=args.scope)
        elif args.action == 'list':
            list_domains(args.domain, args.program, brief=args.brief, count=args.count, scope=args.scope)
        elif args.action == 'delete':
            delete_domain(args.domain if args.domain != '*' else '*', args.program, scope=args.scope)

    elif args.command == 'subdomain':
        if args.action == 'add':
            add_subdomain(args.subdomain, args.domain, args.program, sources=args.source, unsources=args.unsource, 
                          scope=args.scope, resolved=args.resolved, ip_address=args.ip, unip=args.unip, cdn_status=args.cdn_status, 
                          cdn_name=args.cdn_name, uncdn_name=args.uncdn_name)
            
        elif args.action == 'list':
            list_subdomains(subdomain=args.subdomain, domain=args.domain, program=args.program, sources=args.source,
                            scope=args.scope, resolved=args.resolved, brief=args.brief, source_only=args.source_only,
                            cdn_status=args.cdn_status, ip=args.ip, cdn_name=args.cdn_name, count=args.count,
                            create_time=args.create_time, update_time=args.update_time, stats_source=args.stats_source,
                            stats_scope=args.stats_scope, stats_cdn_status=args.stats_cdn_status, stats_cdn_name=args.stats_cdn_name,
                            stats_resolved=args.stats_resolved, stats_ip_address=args.stats_ip_address, stats_domain=args.stats_domain, 
                            stats_program=args.stats_program, stats_created_at=args.stats_created_at, stats_updated_at=args.stats_updated_at)
            
        elif args.action == 'delete':
            if os.path.isfile(args.subdomain):
                with open(args.subdomain, 'r') as file:
                    subdomains = [line.strip() for line in file.readlines() if line.strip()]
                for subdomain in subdomains:
                    delete_subdomain(subdomain, args.domain, args.program, args.scope, args.source, args.resolved)
            else:
                delete_subdomain(args.subdomain, args.domain, args.program, args.scope, args.source, args.resolved,args.ip, args.cdn_status,
                                 args.cdn_name) if args.subdomain != '*' else delete_subdomain('*', args.domain, args.program, args.scope, args.source, args.resolved)

    elif args.command == 'url':
        if args.action == 'add':
            add_url(args.url, args.subdomain, args.domain, args.program, scheme=args.scheme, method=args.method, port=args.port, status_code=args.status_code,
                    ip_address=args.ip, cdn_status=args.cdn_status, cdn_name=args.cdn_name, title=args.title, webserver=args.webserver, webtech=args.webtech,
                    cname=args.cname, scope=args.scope, location=args.location, flag=args.flag, content_length=args.content_length, path=args.path)
            
        elif args.action == 'list':
            list_urls(args.url, args.subdomain, args.domain, args.program, scheme=args.scheme, method=args.method, port=args.port,
                      status_code=args.status_code, ip=args.ip, cdn_status=args.cdn_status, cdn_name=args.cdn_name, title=args.title,
                      webserver=args.webserver, webtech=args.webtech, cname=args.cname, create_time=args.create_time, update_time=args.update_time,
                      brief=args.brief, scope=args.scope, location=args.location, count=args.count, stats_domain=args.stats_domain,
                      stats_program=args.stats_program, stats_subdomain=args.stats_subdomain, stats_cdn_name=args.stats_cdn_name,
                      stats_cdn_status=args.stats_cdn_status, stats_cname=args.stats_cname, stats_created_at=args.stats_created_at,
                      stats_ip_address=args.stats_ip_address, stats_location=args.stats_location, stats_method=args.stats_method,
                      stats_port=args.stats_port, stats_scheme=args.stats_scheme, stats_scope=args.stats_scope, stats_status_code=args.stats_status_code,
                      stats_title=args.stats_title, stats_updated_at=args.stats_updated_at, stats_webserver=args.stats_webserver, 
                      stats_webtech=args.stats_webtech, flag=args.flag, path=args.path, content_length=args.content_length, stats_content_length=args.stats_content_length,
                      stats_flag=args.stats_flag, stats_path=args.stats_path)
            
        elif args.action == 'delete':
            delete_url(args.url, args.subdomain, args.domain, args.program, scheme=args.scheme, method=args.method, port=args.port,
                       status_code=args.status_code, ip_address=args.ip, cdn_status=args.cdn_status, cdn_name=args.cdn_name,
                       title=args.title, webserver=args.webserver, webtech=args.webtech, cname=args.cname, scope=args.scope, 
                       location=args.location, path=args.path, flag=args.flag, content_length=args.content_length)
            
    elif args.command == 'ip':
        if args.action == 'add':
            add_ip(args.ip, args.program, args.cidr, args.asn, args.port, args.service, args.cves)
            
        elif args.action == 'list':
            list_ip(args.ip, args.program, cidr=args.cidr, asn=args.asn, port=args.port, service=args.service,
                    brief=args.brief, cves=args.cves, create_time=args.create_time, update_time=args.update_time, count=args.count,
                    stats_asn=args.stats_asn, stats_cidr=args.stats_cidr, stats_domain=args.stats_domain, stats_port=args.stats_port)
            
        elif args.action == 'delete':
            delete_ip(ip=args.ip, program=args.program, asn=args.asn, cidr=args.cidr, port=args.port, service=args.service, cves=args.cves)
            
    elif args.command == 'setup':
        setup()
        
if __name__ == "__main__":
    main()
