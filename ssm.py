import os
import sys

from main.parsers import create_parser
from imp_exp.importdb import importdb
from imp_exp.exportdb import exportdb
from convert.bson2csv import bson2csv
from convert.bson2xml import bson2xml
from convert.json2csv import json2csv
from convert.json2xml import json2xml

from main.commands import add_program, list_programs, delete_program, add_domain, list_domains, delete_domain, add_subdomain, list_subdomains, delete_subdomain, add_url, list_urls, delete_url, add_ip, list_ip, delete_ip

def main():
    parser = create_parser()
    args = parser.parse_args()
    
    auth_line = os.getenv('ssm_cred')
    if not auth_line:
        print("Error: The 'ssm_cred' environment variable is not set.")
        sys.exit(1)
    try:
        user, password = auth_line.split(':')
    except ValueError:
        print("Error: The 'ssm_cred' environment variable must be in the format 'user:pass'.")
        sys.exit(1)

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
            list_domains(args.domain, args.program, brief=args.brief, count=args.count, scope=args.scope, passive=args.passive, dnsbrute=args.dnsbrute)
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
                            stats_program=args.stats_program, stats_created_at=args.stats_created_at, stats_updated_at=args.stats_updated_at,
                            resolve=args.resolve, permutation=args.permutation)

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
                      stats_flag=args.stats_flag, stats_path=args.stats_path, scan=args.scan)

        elif args.action == 'delete':
            delete_url(args.url, args.subdomain, args.domain, args.program, scheme=args.scheme, method=args.method, port=args.port,
                       status_code=args.status_code, ip_address=args.ip, cdn_status=args.cdn_status, cdn_name=args.cdn_name,
                       title=args.title, webserver=args.webserver, webtech=args.webtech, cname=args.cname, scope=args.scope,
                       location=args.location, path=args.path, flag=args.flag, content_length=args.content_length)

    elif args.command == 'ip':
        if args.action == 'add':
            add_ip(args.ip, args.program, args.cidr, args.asn, args.port, args.hostname, args.domain, args.organization,
                   args.data, args.ssl, args.isp, args.os, args.product, args.version, args.cves)

        elif args.action == 'list':
            list_ip(args.ip, args.program, cidr=args.cidr, asn=args.asn, port=args.port, hostname=args.hostname, domain=args.domain, organization=args.organization, data=args.data, ssl=args.ssl,
                    isp=args.isp, os=args.os, product=args.product, version=args.version, cves=args.cves, brief=args.brief, create_time=args.create_time,
                    update_time=args.update_time, count=args.count, stats_asn=args.stats_asn, stats_cidr=args.stats_cidr, stats_domain=args.stats_domain, stats_port=args.stats_port,
                    stats_isp=args.stats_isp, stats_os=args.stats_os, stats_product=args.stats_product, stats_version=args.stats_version, stats_cves=args.stats_cves, scan=args.scan)

        elif args.action == 'delete':
            delete_ip(ip=args.ip, program=args.program, asn=args.asn, cidr=args.cidr, port=args.port, cves=args.cves, hostname=args.hostname,
                    domain=args.domain, organization=args.organization, data=args.data, ssl=args.ssl, isp=args.isp, os=args.os, version=args.version)
        
    elif args.command == 'import':
        importdb(user, password, args.directory)
        
    elif args.command == 'export':
        exportdb(user, password)
        
    elif args.command == 'convert':
        if args.format == 'csv':
            _, file_extension = os.path.splitext(args.input)
            if file_extension == '.json':
                json2csv(json_file=args.input, csv_file=args.output)
            elif file_extension == '.bson':
                bson2csv(bson_file=args.input, csv_file=args.output)
            
        elif args.format == 'xml':
            _, file_extension = os.path.splitext(args.input)
            if file_extension == '.json':
                json2xml(json_file=args.input, xml_file=args.output)
            elif file_extension == '.bson':
                bson2xml(bson_file=args.input, xml_file=args.output)
            

    else:
        print("OK!")

if __name__ == "__main__":
    main()
