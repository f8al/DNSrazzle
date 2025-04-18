#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
 ______  __    _ _______ ______   _______ _______ _______ ___     _______
|      ||  |  | |       |    _ | |   _   |       |       |   |   |       |
|  _    |   |_| |  _____|   | || |  |_|  |____   |____   |   |   |    ___|
| | |   |       | |_____|   |_||_|       |____|  |____|  |   |   |   |___
| |_|   |  _    |_____  |    __  |       | ______| ______|   |___|    ___|
|       | | |   |_____| |   |  | |   _   | |_____| |_____|       |   |___
|______||_|  |__|_______|___|  |_|__| |__|_______|_______|_______|_______|


Generate, resolve, and compare domain variations to detect typosquatting,
phishing, and brand impersonation

Copyright 2025 SecurityShrimp LTD, LLC

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
'''


__version__ = '1.6.0'
__author__ = 'SecurityShrimp'
__twitter__ = '@securityshrimp'
__email__ = 'securityshrimp@proton.me'


def run_whois(domains, nameserver, progress_callback=None):
    from .RDAPUtil import RDAPClient, extract_rdap_fields
    from .IOUtil import print_error, reset_tty

    rdap = RDAPClient()

    for domain in domains:
        if len(domain) > 2:
            try:
                rdap_data = rdap.lookup(domain['domain-name'].encode('idna').decode())
                parsed = extract_rdap_fields(rdap_data)
            except Exception as e:
                print_error(f"Failed to run RDAP lookup for {domain['domain-name']}")
                print_error(e)
                reset_tty()
                continue

            if parsed:
                if parsed.get('registration_date'):
                    domain['whois-created'] = str(parsed['registration_date']).split(' ')[0]
                if parsed.get('registrar'):
                    domain['whois-registrar'] = str(parsed['registrar'])

        if progress_callback is not None:
            progress_callback()


#def run_whois(domains, nameserver, progress_callback=None):
#    for domain in domains:
#        if len(domain) > 2:
#            try:
#                from whoisdomain import query
#                whoisq = query(domain=domain['domain-name'].encode('idna').decode())
#            except Exception as e:
#                from .IOUtil import print_error, reset_tty
#                print_error(f"Failed to run WHOIS query for {domain['domain-name']}")
#                print_error(e)
#                reset_tty()
#            else:
#                if whoisq is not None:
#                    if whoisq.creation_date:
#                        domain['whois-created'] = str(whoisq.creation_date).split(' ')[0]
#                    if whoisq.registrar:
#                        domain['whois-registrar'] = str(whoisq.registrar)
#        if progress_callback is not None:
#            progress_callback()


def run_portscan(domains, out_dir):
    from .IOUtil import print_status
    print_status(f"Running nmap on {domains}")
    import nmap
    nm = nmap.PortScanner()
    nm.scan(hosts=domains, arguments='-A -T4 -sV')
    f = open(out_dir + '/nmap/' + domains + '.csv', "w")
    f.write(nm.csv())
    f.close()


def run_recondns(domains, nameserver, out_dir, threads):
    '''
    :param domain: domain to run dnsrecon on
    :param out_dir: output directory to save records to
    general_enum arguments : res, domain, do_axfr, do_bing, do_yandex, do_spf, do_whois, do_crt, zw, thread_num=None
    :return:
    '''
    from .IOUtil import print_status,  write_to_file
    print_status(f'Running reconDNS report on {domains}!')

    from recondns import general_enum, DnsHelper, make_csv
    ns_server = [nameserver]
    request_timeout = 10
    proto = 'udp'
    res = DnsHelper(domains, ns_server, request_timeout, proto)
    std_records = general_enum(res, domains, False, False, False, True, False, True, True, threads)
    write_to_file(make_csv(std_records), out_dir , '/reconDNS/' + domains + '.txt')
