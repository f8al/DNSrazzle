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


__version__ = '0.1.0'
__author__ = 'SecurityShrimp'
__twitter__ = '@securityshrimp'


import argparse
from os import path
import dns.resolver
from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import WebDriverException
from skimage.metrics import structural_similarity
import nmap
import cv2
import dnstwist
import queue
from progress.bar import Bar
from src.lib.IOUtil import *
import signal
import whois
from dnsrecon import *



def main():
    #
    # Option Variables
    #
    os.environ['WDM_LOG_LEVEL'] = '0'
    domain = None

    banner()
    #
    # Define options
    #
    parser = argparse.ArgumentParser()
    try:
        parser.add_argument('-d', '--domain', type=str, dest='domain', help='Target domain or domain list.')
        parser.add_argument('-D', '--dictionary', type=str, dest='dictionary', metavar='FILE', default=[],
                            help='Path to dictionary file to pass to DNSTwist to aid in domain permutation generation.')
        parser.add_argument('-f', '--file', type=str, dest='file', metavar='FILE', default=None,
                            help='Provide a file containing a list of domains to run DNSrazzle on.')
        parser.add_argument('-g', '--generate', dest='generate', action='store_true', default=False,
                            help='Do a dry run of DNSRazzle and just output permutated domain names')
        parser.add_argument('-n', '--nmap', dest='nmap', action='store_true',
                            help='Perform nmap scan on discovered domains', default=False)
        parser.add_argument('-o', '--out-directory', type=str, dest='out_dir', default=None,
                            help='Absolute path of directory to output reports to.  Will be created if doesn\'t exist'),
        parser.add_argument('-r', '--recon', dest = 'recon', action = 'store_true', default = False,
                            help = 'Create dnsrecon report on discovered domains.')
        parser.add_argument('-t', '--threads', dest='threads', type=int, default=10,
                            help='Number of threads to use in permutation checks, reverse lookups, forward lookups, brute force and SRV record enumeration.')
        parser.add_argument('--tld', type=str, dest='tld', metavar='FILE', default=[],
                            help='Path to TLD dictionary file.')
        parser.add_argument('-u', '--useragent', type=str, metavar='STRING', default='Mozilla/5.0 dnsrazzle/%s' % __version__,
                            help='User-Agent STRING to send with HTTP requests (default: Mozilla/5.0 dnsrazzle/%s)' % __version__)
        parser.add_argument('--debug', dest='debug', action='store_true', help='Print debug messages', default=False)
        arguments = parser.parse_args()

    except KeyboardInterrupt:
        # Handle exit() from passing --help
        raise
    def _exit(code):
        print(FG_RST + ST_RST, end='')
        sys.exit(code)

    def signal_handler(signal, frame):
        print(f'\nStopping threads... ', file=sys.stderr, end='', flush=True)
        for worker in razzle.threads:
            worker.stop()
            worker.join()
        print(f'Done', file=sys.stderr)
        _exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    out_dir = arguments.out_dir
    useragent = arguments.useragent
    threads = arguments.threads
    debug = arguments.debug
    nmap = arguments.nmap
    recon = arguments.recon

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
                 for item in line.split(","):
                     domain_raw_list.append(item)
    else:
         print_error(f"You must specify either the -d or the -f option")
         sys.exit(1)


    # Everything you do depends on "out_dir" being defined, so let's just set it to cwd if we have to.
    if not arguments.generate:
        if out_dir is None:
            out_dir =  os.getcwd()
        print_status(f"Saving records to output folder {out_dir}")
        create_folders(out_dir, nmap, recon)

    dictionary = []
    if arguments.dictionary:
        if not path.exists(arguments.dictionary):
            parser.error('dictionary file not found: %s' % arguments.dictionary)
        with open(arguments.dictionary) as f:
            dictionary = set(f.read().splitlines())
            dictionary = [x for x in dictionary if x.isalnum()]

    tld = []
    if arguments.tld:
        if not path.exists(arguments.tld):
            parser.error('dictionary file not found: %s' % arguments.tld)
        with open(arguments.tld) as f:
            tld = set(f.read().splitlines())
            tld = [x for x in tld if x.isalpha()]


    try:
        for entry in domain_raw_list:
            r_domain = str(entry)
            razzle = DnsRazzle(r_domain, out_dir, tld, dictionary, arguments.file,
                               useragent, debug, threads, nmap, recon)

            if arguments.generate:
                razzle.gen(True)
            else:
                razzle.gen()
                print_status(f"Performing General Enumeration of Domain: {r_domain}")
                razzle.screenshot_domain(r_domain, out_dir + '/screenshots/originals/')
                razzle.gendom_start(useragent)
                while not razzle.jobs.empty():
                    razzle.gendom_progress()
                    time.sleep(0.5)
                razzle.gendom_stop()
                print_status(f'Running whois queries on detected domains.')
                razzle._whois(razzle.domains, debug)


                print(format_domains(razzle.domains))
                write_to_file(format_domains(razzle.domains),out_dir + '/discovered-domains.txt')

                del razzle.domains[0]
                for domain in razzle.domains:
                    #razzle.check_domain(self, domains, r_domain, out_dir, nmap, recon, threads):
                    razzle.check_domain(domain['domain-name'],entry, out_dir, nmap, recon, threads)


    except dns.resolver.NXDOMAIN:
        print_error(f"Could not resolve domain: {domain}")
        sys.exit(1)

    except dns.exception.Timeout:
        print_error(f"A timeout error occurred please make sure you can reach the target DNS Servers")

    else:
        sys.exit(1)



def compare_screenshots(imageA, imageB):
    print_status(f"Comparing screenshot {imageA} with {imageB}.")
    try:
        # load the two input images
        image_A = cv2.imread(imageA)
        image_B = cv2.imread(imageB)
        # convert the images to grayscale
        grayA = cv2.cvtColor(image_A, cv2.COLOR_BGR2GRAY)
        grayB = cv2.cvtColor(image_B, cv2.COLOR_BGR2GRAY)
        # compute the Structural Similarity Index (SSIM) between the two
        # images, ensuring that the difference image is returned
        (score, diff) = structural_similarity(grayA, grayB, full=True)
        #print("SSIM: {}".format(score))
        rounded_score = round(score, 2)

        if rounded_score == 1.00 :
            print_status(f"{imageA} Is identical to {imageB} with a score of {str(rounded_score)}!")
        elif rounded_score > .90 :
            print_status(f"{imageA} Is similar to {imageB} with a score of {str(rounded_score)}!")
        elif rounded_score < .90 :
            print_status(f"{imageA} Is different from {imageB} with a score of {str(rounded_score)}!")
    except cv2.error as exception:
            print_error(f"Unable to compare screenshots.  One or more of the screenshots are missing!")


class DnsRazzle():
    def __init__(self, domain, out_dir, tld, dictionary, file, useragent, debug, threads, nmap, recon):
        self.domains = []
        self.domain = domain
        self.out_dir = out_dir
        self.tld = tld
        self.dictionary = dictionary
        self.file = file
        self.useragent = useragent
        self.threads = []
        self.jobs = queue.Queue()
        self.jobs_max = 0
        self.debug = False
        self.nmap = nmap
        self.recon = recon



    def gen(self, shouldPrint=False):
        fuzz = dnstwist.DomainFuzz(self.domain, self.dictionary, self.tld)
        fuzz.generate()
        if shouldPrint:
            for entry in fuzz.domains[1:]:
                print(entry['domain-name'])
        self.domains = fuzz.domains



    def gendom_start(self, useragent, threadcount=10):
        url = dnstwist.UrlParser(self.domain)

        for i in range(len(self.domains)):
            self.jobs.put(self.domains[i])
        self.jobs_max = len(self.domains)

        for _ in range(threadcount):
            worker = dnstwist.DomainThread(self.jobs)
            worker.setDaemon(True)

            self.kill_received = False
            self.debug = False

            worker.option_extdns = True
            worker.option_geoip = False
            worker.option_ssdeep = False
            worker.option_banners = True
            worker.option_mxcheck = True

            worker.nameservers = []
            self.useragent = useragent

            worker.uri_scheme = url.scheme
            worker.uri_path = url.path
            worker.uri_query = url.query

            worker.domain_init = url.domain
            worker.start()
            self.threads.append(worker)

        self.bar =  Bar('Processing domain permutations', max=self.jobs_max - 1)


    def gendom_stop(self):
        for worker in self.threads:
            worker.stop()
            worker.join()
        self.bar.finish()

    def gendom_progress(self):
        self.bar.goto(self.jobs_max - self.jobs.qsize())


    def _whois(self, domains, debug):
        for domain in domains:
            if len(domain) > 2:
                try:
                    whoisq = whois.query(domain['domain-name'].encode('idna').decode())
                except Exception as e:
                    if debug:
                        print_error(e)
                else:
                    if whoisq.creation_date:
                        domain['whois-created'] = str(whoisq.creation_date).split(' ')[0]
                    if whoisq.registrar:
                        domain['whois-registrar'] = str(whoisq.registrar)

    def portscan(self, domains, out_dir):
        print_status(f"Running nmap on {domains}")
        nm = nmap.PortScanner()
        nm.scan(hosts=domains, arguments='-A -T4 -sV')
        f = open(out_dir + '/nmap/' + domains + '.csv', "w")
        f.write(nm.csv())
        f.close()

    def dnsrecon(self, domains, out_dir, threads):
        '''
        :param domain: domain to run dnsrecon on
        :param out_dir: output directory to save records to
        general_enum arguments : res, domain, do_axfr, do_bing, do_yandex, do_spf, do_whois, do_crt, zw, thread_num=None
        :return:
        '''
        ns_server = []
        request_timeout = 10
        proto = 'udp'
        res = DnsHelper(domains, ns_server, request_timeout, proto)
        std_records = general_enum(res, domains, False, False, False, True, False, True, True, threads)
        write_to_file(make_csv(std_records), out_dir + '/dnsrecon/' + domains + '.txt')

    def check_domain(self, domains, r_domain, out_dir, nmap, recon, threads):
        '''
        primary method for performing domain checks
        '''

        self.screenshot_domain(domains, out_dir + '/screenshots/')
        compare_screenshots(out_dir + '/screenshots/originals/' + r_domain + '.png',
                            out_dir + '/screenshots/' + domains + '.png')
        if nmap:
            self.portscan(domains, out_dir)
        if recon:
            self.dnsrecon(domains, out_dir, threads)



    def screenshot_domain(self, domain, out_dir):
        """
        function to take screenshot of supplied domain
        """

        try:
            print_status(f"collecting screenshot of {domain}!")
            options = webdriver.ChromeOptions()
            options.headless = True
            try:
                driver = webdriver.Chrome(ChromeDriverManager().install(), options=options)
            except exception as E:
                print_error(f"Unable to install/update Chrome webdriver because {E}")
            url = "http://" + str(domain).strip('[]')
            driver.get(url)

            ss_path = str(out_dir + domain + '.png')

            driver.set_window_size(1920, 1080)  # May need manual adjustment
            driver.get_screenshot_as_file(ss_path)
            driver.quit()
            print_good(f"Screenshot for {domain} saved to {ss_path}")
        except WebDriverException as exception:
            print_error(f"Unable to screenshot {domain}!")


if __name__ == "__main__":
    main()