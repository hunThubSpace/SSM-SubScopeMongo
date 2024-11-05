import argparse

def create_parser():
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
    add_ip_parser.add_argument('program', help='program name')
    add_ip_parser.add_argument('--cidr', help='CIDR notation')
    add_ip_parser.add_argument('--asn', help='Autonomous System Number')
    add_ip_parser.add_argument('--port', help='One port number')
    add_ip_parser.add_argument('--hostname', help='Hostname associated with the IP')
    add_ip_parser.add_argument('--domain', help='Domain associated with the IP')
    add_ip_parser.add_argument('--organization', help='Organization name associated with the IP')
    add_ip_parser.add_argument('--data', help='Large data field associated with the IP')
    add_ip_parser.add_argument('--ssl', help='SSL information associated with the IP')
    add_ip_parser.add_argument('--isp', help='Internet Service Provider associated with the IP')
    add_ip_parser.add_argument('--os', help='Operating System associated with the IP')
    add_ip_parser.add_argument('--product', help='Product associated with the IP')
    add_ip_parser.add_argument('--version', help='Version of the product associated with the IP')
    add_ip_parser.add_argument('--cves', nargs='+', help='Comma-separated CVEs associated with the IP')

    list_ips_parser = ip_action_parser.add_parser('list', help='List IPs in a program')
    list_ips_parser.add_argument('ip', help='IP or CIDR (use * for all IPs)')
    list_ips_parser.add_argument('program', help='Program (use * for all programs)')
    list_ips_parser.add_argument('--cidr', help='Filter by CIDR')
    list_ips_parser.add_argument('--asn', help='Filter by ASN')
    list_ips_parser.add_argument('--port', type=int, help='Filter by port')  # Port filter
    list_ips_parser.add_argument('--hostname', help='Filter by hostname')  # Added hostname filter
    list_ips_parser.add_argument('--domain', help='Filter by domain')  # Added domain filter
    list_ips_parser.add_argument('--organization', help='Filter by organization')  # Added organization filter
    list_ips_parser.add_argument('--data', help='Filter by data')  # Added data filter
    list_ips_parser.add_argument('--ssl', help='Filter by SSL')  # Added ssl filter
    list_ips_parser.add_argument('--isp', help='Filter by ISP')  # Added ISP filter
    list_ips_parser.add_argument('--os', help='Filter by OS')  # Added OS filter
    list_ips_parser.add_argument('--product', help='Filter by product')  # Added product filter
    list_ips_parser.add_argument('--version', help='Filter by version')  # Added version filter
    list_ips_parser.add_argument('--cves', help='Filter by CVEs')  # Added CVEs filter
    list_ips_parser.add_argument('--brief', action='store_true', help='Show only IP addresses')
    list_ips_parser.add_argument('--create_time', help='Filter by creation time')
    list_ips_parser.add_argument('--update_time', help='Filter by update time')
    list_ips_parser.add_argument('--count', action='store_true', help='Show count of matching IPs')
    list_ips_parser.add_argument('--stats-domain', action='store_true', help='Show statistics by domain')
    list_ips_parser.add_argument('--stats-cidr', action='store_true', help='Show statistics by CIDR')
    list_ips_parser.add_argument('--stats-asn', action='store_true', help='Show statistics by ASN')
    list_ips_parser.add_argument('--stats-port', action='store_true', help='Show statistics by port')
    list_ips_parser.add_argument('--stats-isp', action='store_true', help='Show statistics by ISP')  # Added ISP stats
    list_ips_parser.add_argument('--stats-os', action='store_true', help='Show statistics by OS')  # Added OS stats
    list_ips_parser.add_argument('--stats-product', action='store_true', help='Show statistics by product')  # Added Product stats
    list_ips_parser.add_argument('--stats-version', action='store_true', help='Show statistics by version')  # Added Version stats
    list_ips_parser.add_argument('--stats-cves', action='store_true', help='Show statistics by CVEs')  # Added CVEs stats

    delete_ip_parser = ip_action_parser.add_parser('delete', help='Delete IPs')
    delete_ip_parser.add_argument('ip', help='IP or CIDR (use * for all IPs)')  # Specify IP or CIDR
    delete_ip_parser.add_argument('program', help='Program (use * for all programs)')  # Specify program
    delete_ip_parser.add_argument('--port', type=int, help='Filter by port')  # Optional port filter
    delete_ip_parser.add_argument('--asn', help='Filter by ASN')  # Optional ASN filter
    delete_ip_parser.add_argument('--cidr', help='Filter by CIDR')  # Optional CIDR filter
    delete_ip_parser.add_argument('--cves', help='Filter by CVEs')  # Optional CVEs filter
    delete_ip_parser.add_argument('--hostname', help='Filter by hostname')  # Optional hostname filter
    delete_ip_parser.add_argument('--domain', help='Filter by domain')  # Optional domain filter
    delete_ip_parser.add_argument('--organization', help='Filter by organization')  # Optional organization filter
    delete_ip_parser.add_argument('--data', help='Filter by data')  # Optional data filter
    delete_ip_parser.add_argument('--ssl', help='Filter by SSL')  # Optional SSL filter
    delete_ip_parser.add_argument('--isp', help='Filter by ISP')  # Optional ISP filter
    delete_ip_parser.add_argument('--os', help='Filter by OS')  # Optional OS filter
    delete_ip_parser.add_argument('--product', help='Filter by product')  # Optional product filter
    delete_ip_parser.add_argument('--version', help='Filter by version')  # Optional version filter

    setup_parser = sub_parser.add_parser('setup', help='Installing mondodb and enable authentication')
    import_parser = sub_parser.add_parser('importdb', help='Import database')
    export_parser = sub_parser.add_parser('exportdb', help='Export database')
    
    convert_parser = sub_parser.add_parser('convert', help='convert json to csv')
    convert_parser.add_argument('input', help='json file')
    convert_parser.add_argument('output', help='csv file')
    
    return parser
