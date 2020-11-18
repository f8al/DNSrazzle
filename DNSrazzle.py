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


__version__ = '0.0.6'
__author__ = 'SecurityShrimp'
__twitter__ = '@securityshrimp'


import sys
import argparse
import os
import dns.resolver
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import WebDriverException
from contrib.dnsrecon.tools.parser import print_error, print_status, print_good
from skimage.measure import compare_ssim
from contrib.dnsrecon import *
import nmap
import imutils
import cv2
import math
from subprocess import PIPE, Popen
import json
import dnstwist
import threading
import queue
from progress.bar import Bar
import time






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
        (score, diff) = compare_ssim(grayA, grayB, full=True)
        diff = (diff * 255).astype("uint8")
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

    """
    # threshold the difference image, followed by finding contours to
    # obtain the regions of the two input images that differ
    thresh = cv2.threshold(diff, 0, 255,
                           cv2.THRESH_BINARY_INV | cv2.THRESH_OTSU)[1]
    cnts = cv2.findContours(thresh.copy(), cv2.RETR_EXTERNAL,
                            cv2.CHAIN_APPROX_SIMPLE)
    cnts = imutils.grab_contours(cnts)
    # loop over the contours
    for c in cnts:
        # compute the bounding box of the contour and then draw the
        # bounding box on both input images to represent where the two
        # images differ
        (x, y, w, h) = cv2.boundingRect(c)
        cv2.rectangle(image_A, (x, y), (x + w, y + h), (0, 0, 255), 2)
        cv2.rectangle(image_B, (x, y), (x + w, y + h), (0, 0, 255), 2)
    # show the output images
    cv2.imshow("Original", image_A)
    cv2.imshow("Modified", image_B)
    cv2.imshow("Diff", diff)
    cv2.imshow("Thresh", thresh)
    #cv2.waitKey(0)
    """

def portscan(domain, out_dir):
    print_status(f"Running nmap on {domain}")
    nm = nmap.PortScanner()
    if not os.path.isfile(out_dir+'/nmap/'):
        create_folders(out_dir)
    nm.scan(hosts=domain, arguments='-A -T4 -sV')
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    #print(nm.csv())
    f = open(out_dir + '/nmap/' + domain + '.csv' , "w")
    f.write(nm.csv())
    f.close()


def check_domain(t_domain,r_domain,out_dir):
    '''
    primary method for performing domain checks
    '''

    screenshot_domain(t_domain, out_dir + '/screenshots/')
    compare_screenshots(out_dir + '/screenshots/originals/' + r_domain + '.png',
                        out_dir + '/screenshots/'+ t_domain + '.png')
    portscan(t_domain, out_dir)
    dnsrecon(t_domain, out_dir + '/dnsrecon/')




def write_to_file(data, out_dir, target_file):
    """
    Function for writing returned data to a file
    """
    f = open(out_dir + '/' +target_file, "w")
    f.write(data)
    f.close()



def screenshot_domain(domain,out_dir):
    """
    function to take screenshot of supplied domain
    """

    try:
        print_status(f"collecting screenshot of {domain}!")
        options = webdriver.ChromeOptions()
        options.headless = True
        driver = webdriver.Chrome(ChromeDriverManager().install(),options=options)
        url = "http://" + str(domain).strip('[]')
        driver.get(url)


        ss_path = str(out_dir + domain + '.png')

        S = lambda X: driver.execute_script('return document.body.parentNode.scroll' + X)
        driver.set_window_size(1920,1080)  # May need manual adjustment
        driver.get_screenshot_as_file(ss_path)
        driver.quit()
        print_good(f"Screenshot for {domain} saved to {ss_path}")
    except WebDriverException as exception:
        print_error(f"Unable to screenshot {domain}!")


def create_folders(out_dir):
    '''
    function to create output folders at location specified with -o
    '''
    os.makedirs(out_dir + '/screenshots/', exist_ok=True)
    os.makedirs(out_dir + '/screenshots/originals/', exist_ok=True)
    os.makedirs(out_dir + '/dnsrecon/', exist_ok=True)
    os.makedirs(out_dir + '/dnstwist/', exist_ok=True)
    os.makedirs(out_dir + '/nmap/', exist_ok=True)

def show_todo(r_domain):
    # Create a generator
    for key, value in cal.items():
        yield value[0], key

def twistdomain(r_domain:str,dictionary:str):
    '''
    takes the value of r_domain and passes it to dnstwist as the target domain
    :param r_domain: reference domain to be permutated with dnstwist
    :param dictionary: dictionary file to extend dnstwist permutations
    :return: returns a json object with permutated domains, registrars, creation date, banners, and MX records
    '''
    _result = dict()
    print_status(f"Running DNSTwist permutation engine on {r_domain}!")
    _base_cmd = ['dnstwist', '-b', '-w', '-r', '-m', '-f', 'json']
    _dict_cmd = ['--dictionary', dictionary, r_domain]
    if dictionary:
        _base_cmd = _base_cmd + _dict_cmd
    else:
        _base_cmd.append(r_domain)
    proc = Popen(_base_cmd, shell=False, stdin=PIPE, stdout=PIPE,stderr=PIPE)
    stdout_value, stderr_value = proc.communicate()
    _result = json.loads(stdout_value)
    return _result


def dnsrecon(t_domain, out_dir):
    print_status(f"Running DNSRecon on {t_domain}!")
    _cmd = ['python3','dnsrecon.py','-a','-s', '-y','-k','-z','-d']
    _cmd.append(t_domain)
    print(_cmd)
    print(t_domain,out_dir)

class dnsrazzle():
    def __init__(self, domain, out_dir, tld, dictionary, file, useragent):
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


    def gen(self, shouldPrint=False):
        fuzz = dnstwist.DomainFuzz(self.domain, self.dictionary, self.tld)
        fuzz.generate()
        if shouldPrint:
            for entry in fuzz.domains:
                print(entry['domain-name'])

        self.domains = fuzz.domains



    def gendom_start(self, threadcount=10):
        url = dnstwist.UrlParser(self.domain)

        for i in range(len(self.domains)):
            self.jobs.put(self.domains[i])
        self.jobs_max = len(self.domains)

        for _ in range(threadcount):
            worker = dnstwist.DomainThread(self.jobs)
            worker.setDaemon(True)

            self.jobs = queue
            self.kill_received = False
            self.debug = False

            worker.option_extdns = True
            worker.option_geoip = False
            worker.option_ssdeep = False
            worker.option_banners = True
            worker.option_mxcheck = True

            worker.nameservers = []
            self.useragent = ''

            worker.uri_scheme = url.scheme
            worker.uri_path = url.path
            worker.uri_query = url.query

            worker.domain_init = url.domain
            worker.start()
            self.threads.append(worker)

        self.bar =  Bar('Processing', max=self.jobs_max)


    def gendom_stop(self):
        for worker in self.threads:
            worker.stop()
            worker.join()
        self.bar.finish()

    def gendom_progress(self):
        self.bar.goto(self.jobs_max - self.jobs.qsize())



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
        parser.add_argument("-d", "--domain", type=str, dest="domain", help="Target domain or domain list.",
                            required=True)
        parser.add_argument("-f", "--file", type=str, dest="file", metavar='FILE', default=None,
                            help="Provide a file containing a list of domains to run DNSrazzle on.")
        parser.add_argument("-o", "--out-directory", type=str, dest="out_dir", default=None,
                            help="Absolute path of directory to output reports to.  Will be created if doesn't exist")
        parser.add_argument("-D", "--dictionary", type=str, dest="dictionary", metavar='FILE', default=[],
                            help="Path to dictionary file to pass to DNSTwist to aid in domain permutation generation.")
        parser.add_argument('-g', "--generate", dest="generate", action="store_true", default=False,
                            help="Do a dry run of DNSRazzle and just output permutated domain names")
        parser.add_argument('--tld', type=str, dest='tld', metavar="FILE", default=[],
                            help='Path to TLD dictionary file.') #todo add tld dictionary processing
        parser.add_argument('--useragent', type=str, metavar='STRING', default='Mozilla/5.0 dnsrazzle/%s' % __version__,
                            help='User-Agent STRING to send with HTTP requests (default: Mozilla/5.0 dnsrazzle/%s)' % __version__)
        arguments = parser.parse_args()

    except KeyboardInterrupt:
        # Handle exit() from passing --help
        raise

    out_dir = arguments.out_dir

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


    razzle = dnsrazzle(arguments.domain, arguments.out_dir, arguments.tld, arguments.dictionary, arguments.file, arguments.useragent)


    if arguments.generate:
        razzle.gen(True)
        sys.exit(1)
    else:
        razzle.gen()


    # Everything you do depends on "out_dir" being defined, so let's just set it to cwd if we have to.
    if out_dir is None:
        out_dir =  os.getcwd()
    print_status(f"Saving records to output folder {out_dir}")
    create_folders(out_dir)



    try:
        for entry in domain_raw_list:
            r_domain = str(entry)
            print_status(f"Performing General Enumeration of Domain: {r_domain}")
            screenshot_domain(r_domain, out_dir + '/screenshots/originals/')
            razzle.gendom_start()
            while not razzle.jobs.empty():
                razzle.gendom_progress()
                time.sleep(0.5)
            razzle.gendom_stop()

            for domain in razzle.domains:
                check_domain(domain['domain-name'],r_domain, out_dir)


    except dns.resolver.NXDOMAIN:
        print_error(f"Could not resolve domain: {domain}")
        sys.exit(1)

    except dns.exception.Timeout:
        print_error(f"A timeout error occurred please make sure you can reach the target DNS Servers")

    else:
        sys.exit(1)


if __name__ == "__main__":
    main()




def resolvdoms(r_domain):
    _r = resolver()

    try:
        for i in range(len(fuzz.domains)):
            _tmp = _r.resolve(fuzz.domains[i]['domain-name'])
    except:
        pass
    else:
        dir(_r)