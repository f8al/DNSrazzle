'''
DNSrazzle input/output library

Generate, resolve, and compare domain variations to detect typosquatting,
phishing, and brand impersonation

Copyright 2020 SecurityShrimp

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


import os
import sys
import time


'''Global Variables'''
__version__ = '0.1.3'
__author__ = 'SecurityShrimp'
__twitter__ = '@securityshrimp'


if sys.platform != 'win32' and sys.stdout.isatty():
	FG_RND = '\x1b[3{}m'.format(int(time.time())%8+1)
	FG_YEL = '\x1b[33m'
	FG_CYA = '\x1b[36m'
	FG_BLU = '\x1b[34m'
	FG_RST = '\x1b[39m'
	ST_BRI = '\x1b[1m'
	ST_RST = '\x1b[0m'
else:
	FG_RND = FG_YEL = FG_CYA = FG_BLU = FG_RST = ST_BRI = ST_RST = ''


def create_folders(out_dir, nmap, recon):
    '''
    function to create output folders at location specified with -o
    '''
    os.makedirs(out_dir + '/screenshots/', exist_ok=True)
    os.makedirs(out_dir + '/screenshots/originals/', exist_ok=True)
    if recon:
        os.makedirs(out_dir + '/reconDNS/', exist_ok=True)
    if nmap:
        os.makedirs(out_dir + '/nmap/', exist_ok=True)


def write_to_file(data, out_dir, target_file):
    """
    Function for writing returned data to a file
    """
    f = open(out_dir + '/' + target_file, "w")
    f.write(data)
    f.close()


#def banner(version: str, author: str):
def banner():
    print(
        " ______  __    _ _______ ______   _______ _______ _______ ___     _______\n",
        "|      ||  |  | |       |    _ | |   _   |       |       |   |   |       |\n",
        "|  _    |   |_| |  _____|   | || |  |_|  |____   |____   |   |   |    ___|\n",
        "| | |   |       | |_____|   |_||_|       |____|  |____|  |   |   |   |___ \n",
        "| |_|   |  _    |_____  |    __  |       | ______| ______|   |___|    ___|\n",
        "|       | | |   |_____| |   |  | |   _   | |_____| |_____|       |   |___ \n",
        "|______||_|  |__|_______|___|  |_|__| |__|_______|_______|_______|_______|\n")
    print(f"Version {__version__} by {__author__}")

def print_status(message=""):
    print(f"\033[1;34m[*]\033[1;m {message}", flush=True)


def print_good(message=""):
    print(f"\033[1;32m[*]\033[1;m {message}", flush=True)


def print_error(message=""):
    print(f"\033[1;31m[-]\033[1;m {message}", flush=True)


def print_debug(message=""):
    print(f"\033[1;31m[!]\033[1;m {message}", flush=True)


def print_line(message=""):
    print(f"{message}", flush=True)

def format_domains(domains=[]):
    cli = []
    width_fuzzer = max([len(x['fuzzer']) for x in domains]) + 1
    width_domain = max([len(x['domain-name']) for x in domains]) + 1
    for domain in domains:
        info = []
        domains[:] = [x for x in domains if len(x) > 2]

        if 'dns-a' in domain:
            if 'geoip-country' in domain:
                info.append(';'.join(domain['dns-a']) + FG_CYA + '/' + domain['geoip-country'].replace(' ',
                                                                                                       '') + FG_RST)
            else:
                info.append(';'.join(domain['dns-a']))
        if 'dns-aaaa' in domain:
            info.append(';'.join(domain['dns-aaaa']))
        if 'dns-ns' in domain:
            info.append(FG_YEL + 'NS:' + FG_CYA + ';'.join(domain['dns-ns']) + FG_RST)
        if 'dns-mx' in domain:
            if 'mx-spy' in domain:
                info.append(FG_YEL + 'SPYING-MX:' + FG_CYA + ';'.join(domain['dns-mx']) + FG_RST)
            else:
                info.append(FG_YEL + 'MX:' + FG_CYA + ';'.join(domain['dns-mx']) + FG_RST)
        if 'banner-http' in domain:
            info.append(FG_YEL + 'HTTP:' + FG_CYA + domain['banner-http'] + FG_RST)
        if 'banner-smtp' in domain:
            info.append(FG_YEL + 'SMTP:' + FG_CYA + domain['banner-smtp'] + FG_RST)
        if 'whois-registrar' in domain:
            info.append(FG_YEL + 'REGISTRAR:' + FG_CYA + domain['whois-registrar'] + FG_RST)
        if 'whois-created' in domain:
            info.append(FG_YEL + 'CREATED:' + FG_CYA + domain['whois-created'] + FG_RST)
        if domain.get('ssdeep-score', 0) > 0:
            info.append(FG_YEL + 'SSDEEP:' + str(domain['ssdeep-score']) + FG_RST)
        if not info:
            info = ['-']
        cli.append(' '.join([FG_BLU + domain['fuzzer'].ljust(width_fuzzer) + FG_RST,
                             domain['domain-name'].ljust(width_domain), ' '.join(info)]))
    return '\n'.join(cli)

def make_csv(data):
    csv_data = "Type,Name,Address,Target,Port,String\n"
    for n in data:
        # make sure that we are working with a dictionary.
        if isinstance(n, dict):
            #print(n)
            if n['type'] in ['PTR', 'A', 'AAAA']:
                csv_data += n["type"] + "," + n["name"] + "," + n["address"] + "\n"

            elif re.search(r"NS$", n["type"]):
                csv_data += n["type"] + "," + n["target"] + "," + n["address"] + "\n"

            elif re.search(r"SOA", n["type"]):
                csv_data += n["type"] + "," + n["mname"] + "," + n["address"] + "\n"

            elif re.search(r"MX", n["type"]):
                csv_data += n["type"] + "," + n["exchange"] + "," + n["address"] + "\n"

            elif re.search(r"SPF", n["type"]):
                if "zone_server" in n:
                    csv_data += n["type"] + ",,,,,\'" + n["strings"] + "\'\n"
                else:
                    csv_data += n["type"] + ",,,,,\'" + n["strings"] + "\'\n"

            elif re.search(r"TXT", n["type"]):
                if "zone_server" in n:
                    csv_data += n["type"] + ",,,,,\'" + n["strings"] + "\'\n"
                else:
                    csv_data += n["type"] + "," + n["name"] + ",,,,\'" + n["strings"] + "\'\n"

            elif re.search(r"SRV", n["type"]):
                csv_data += n["type"] + "," + n["name"] + "," + n["address"] + "," + n["target"] + "," + n["port"] + "\n"

            elif re.search(r"CNAME", n["type"]):
                if "target" not in n.keys():
                    n["target"] = ""
                csv_data += n["type"] + "," + n["name"] + ",," + n["target"] + ",\n"

            else:
                # Handle not common records
                t = n["type"]
                del n["type"]
                record_data = "".join(["%s =%s," % (key, value) for key, value in n.items()])
                records = [t, record_data]
                csv_data + records[0] + ",,,,," + records[1] + "\n"

    return csv_data