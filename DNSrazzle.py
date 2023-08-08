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


__version__ = '1.5.1'
__author__ = 'SecurityShrimp'
__twitter__ = '@securityshrimp'
__email__ = 'securityshrimp@proton.me'


import argparse
import csv
import os
import signal
import sys
import time
from progress.bar import Bar
from dnsrazzle import BrowserUtil, IOUtil
from dnsrazzle.DnsRazzle import DnsRazzle
from dnsrazzle.IOUtil import print_error, print_good, print_status

def main():
    os.environ['WDM_LOG_LEVEL'] = '0'
    IOUtil.banner()
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--blocklist', action="store_true", dest='blocklist', default=False,
                            help="Generate a blocklist of domains/IP addresses of suspected impersonation domains.")
    parser.add_argument('-B', '--blocklist_pct', type=float, dest='blocklist_pct', metavar='PCT', default=0.9,
                        help="Threshold for what gets put on the blocklist. Default is 0.9.")
    parser.add_argument('--browser', type=str, dest='browser', default='chrome',
                        help='Specify browser to use with WebDriver. Default is "chrome", "firefox" is also supported.')
    parser.add_argument('-d', '--domain', type=str, dest='domain', help='Target domain or domain list.')
    parser.add_argument('-D', '--dictionary', type=str, dest='dictionary', metavar='FILE', default=[],
                        help='Path to dictionary file to pass to DNSTwist to aid in domain permutation generation.')
    parser.add_argument('-f', '--file', type=str, dest='file', metavar='FILE', default=None,
                        help='Provide a file containing a list of domains to run DNSrazzle on.')
    parser.add_argument('-g', '--generate', dest='generate', action='store_true', default=False,
                        help='Do a dry run of DNSRazzle and just output permutated domain names.')
    parser.add_argument('-n', '--nmap', dest='nmap', action='store_true', default=False,
                        help='Perform nmap scan on discovered domains.')
    parser.add_argument('-N', '--ns', dest='nameserver', metavar='STRING', type=str, default='1.1.1.1',
                        help='Specify DNS nameserver to use for DNS queries')
    parser.add_argument('-o', '--out-directory', type=str, dest='out_dir', default=None,
                        help='Absolute path of directory to output reports to.  Will be created if doesn\'t exist.'),
    parser.add_argument('-r', '--recon', dest = 'recon', action = 'store_true', default = False,
                        help = 'Create dnsrecon report on discovered domains.')
    parser.add_argument('-t', '--threads', dest='threads', type=int, default=10,
                        help='Number of threads to use in permutation checks, reverse lookups, forward lookups, brute force and SRV record enumeration.')
    parser.add_argument('--tld', type=str, dest='tld', metavar='FILE', default=[],
                        help='Path to TLD dictionary file.')
    parser.add_argument('-u', '--useragent', type=str, metavar='STRING', default='Mozilla/5.0 dnsrazzle/%s' % __version__,
                        help='User-Agent STRING to send with HTTP requests. Default is Mozilla/5.0 dnsrazzle/%s)' % __version__)
    parser.add_argument('--debug', dest='debug', action='store_true', default=False, help='Print debug messages')
    arguments = parser.parse_args()

    out_dir = arguments.out_dir
    useragent = arguments.useragent
    threads = arguments.threads
    debug = arguments.debug
    justPrintDomains = arguments.generate
    nameserver = arguments.nameserver
    nmap = arguments.nmap
    recon = arguments.recon
    driver = None

    def _exit(code):
        IOUtil.reset_tty()
        BrowserUtil.quit_webdriver(driver)
        sys.exit(code)

    def signal_handler(signal, frame):
        print(f'\nStopping threads... ', file=sys.stderr, end='', flush=True)
        for worker in razzle.workers:
            worker.stop()
            worker.join()
        print(f'Done', file=sys.stderr)
        _exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    if debug:
        os.environ['WDM_LOG_LEVEL'] = '4'
    # First, you need to put the domains to be scanned into the "domains_to_scan" variable
    # Use case 1 -- the user supplied the -d (domain) flag
    # Use case 2 -- the user supplied the -f (file) flag
    if arguments.domain is not None:
         domain_raw_list = list(set(arguments.domain.split(",")))
    elif arguments.file is not None:
         domain_raw_list = []
         with open(arguments.file) as f:
             for line in f:
                 for item in line.split("\n"):
                     domain_raw_list.append(item)
    else:
         print_error(f"You must specify either the -d or the -f option")
         sys.exit(1)

    # Everything you do depends on "out_dir" being defined, so let's just set it to cwd if we have to.
    if not arguments.generate:
        if out_dir is None:
            out_dir =  os.getcwd()
        print_status(f"Saving records to output folder {out_dir}")
        IOUtil.create_folders(out_dir, nmap, recon)

    dictionary = []
    if arguments.dictionary:
        if not os.path.exists(arguments.dictionary):
            parser.error('dictionary file not found: %s' % arguments.dictionary)
        with open(arguments.dictionary) as f:
            dictionary = set(f.read().splitlines())
            dictionary = [x for x in dictionary if x.isalnum()]

    tld = []
    if arguments.tld:
        if not os.path.exists(arguments.tld):
            parser.error('dictionary file not found: %s' % arguments.tld)
        with open(arguments.tld) as f:
            tld = set(f.read().splitlines())
            tld = [x for x in tld if x.isalpha()]

    print_status("Generating possible domain name impersonations")
    razzles: list[DnsRazzle] = []
    for entry in domain_raw_list:
        razzle = DnsRazzle(domain=str(entry), out_dir=out_dir, tld=tld, dictionary=dictionary, file=arguments.file,
                useragent=useragent, debug=debug, threads=threads, nmap=nmap, recon=recon, driver=driver,
                nameserver=nameserver)
        razzles.append(razzle)
        # fuzzing is fast so just do it while building the list of razzlers
        razzle.generate_fuzzed_domains()

    if justPrintDomains:
        for razzle in razzles:
            for entry in razzle.domains[1:]:
                print(entry['domain-name'])
        return

    for razzle in razzles:
        bar = Bar(f'Running DNS lookup of possible domain permutations for {razzle.domain}…', max=len(razzle.domains)-1)
        razzle.gendom_start()
        while not razzle.jobs.empty():
            bar.goto(razzle.jobs_max - razzle.jobs.qsize())
            time.sleep(0.5)
        bar.goto(bar.max)
        bar.finish()
        bar = Bar(f"Waiting for straggling DNS responses…", max=len(razzle.workers))
        razzle.gendom_stop(bar.next)
        bar.finish()
        if debug:
            print_good(f"Generated domains dictionary: \n{razzle.domains}")

    for razzle in razzles:
        pBar = Bar(f'Running WHOIS queries on discovered domains for {razzle.domain}…', max=len(razzle.domains))
        razzle.whois(pBar.next)
        pBar.finish()

    print_status("Processing domain information")
    with open(out_dir + '/discovered-domains.csv', 'w') as f:
        header_written = False
        writer = csv.DictWriter(f, IOUtil.domain_entry_keys)
        for razzle in razzles:
            if debug:
                formatted_domains = IOUtil.format_domains(razzle.domains)
                print(formatted_domains)

            if not header_written:
                writer.writeheader()
                header_written = True
            for d in razzle.domains:
                writer.writerow(d)
    print_good(f"Domain data written to {out_dir}/discovered-domains.csv")

    print_status("Collecting and analyzing web screenshots")

    if driver is None:
        driver = BrowserUtil.get_webdriver(arguments.browser)

    with open(file=out_dir + "/domain_similarity.csv", mode="w") as f:
        f.write("original_domain,discovered_domain,similarity_score\n")

    for razzle in razzles:
        razzle.driver = driver
        razzle.check_domains(check_domain_callback)
    BrowserUtil.quit_webdriver(driver)
    print_good(f"Visual analysis saved to {out_dir}/domain_similarity.csv")

    if arguments.blocklist:
        print_status("Compiling blocklist")
        for razzle in razzles:
            for domain in razzle.domains:
                if domain['ssim-score'] is not None and domain['ssim-score'] >= arguments.blocklist_pct:
                    with open(out_dir + "/blocklist.csv", "a") as f:
                        for field in ['dns-a', 'dns-aaaa', 'dns-ns', 'dns-mx']:
                            if field in domain:
                                for ip in domain[field]:
                                    f.write("%s,%s" % (ip, domain['domain-name']))
        print_good(f"Blocklist saved to {out_dir}/blocklist.csv")

def check_domain_callback(razzle: DnsRazzle, domain_entry):
    siteA = razzle.domain
    siteB = domain_entry['domain-name']
    score = domain_entry['ssim-score']
    rounded_score = round(score, 2)
    adj = "different from"
    if rounded_score == 1.00:
        adj = "identical to"
    elif rounded_score >= .90:
        adj = "similar to"
    print_status(f"{siteB} is {adj} {siteA} with a score of {rounded_score}!")
    with open(file=razzle.out_dir + "/domain_similarity.csv", mode="a") as f:
        f.write(f"{siteA},{siteB},{rounded_score}\n")

if __name__ == "__main__":
    main()
