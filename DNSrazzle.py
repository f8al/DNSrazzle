#!/usr/bin/env python3
import sys
import argparse
import os
import dns.resolver
import pathlib
import string
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from contrib.dnsrecon.tools.parser import print_error, print_status
from contrib.dnstwist import *
import nmap




# -*- coding: utf-8 -*-

#    DNSRecon
#
#    Copyright (C) 2020  Carlos Perez
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; Applies version 2 of the License.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA


__version__ = '0.0.1'
__author__ = 'securityshrimp @securityshrimp'





'''
 ______  __    _ _______ ______   _______ _______ _______ ___     _______ 
|      ||  |  | |       |    _ | |   _   |       |       |   |   |       |
|  _    |   |_| |  _____|   | || |  |_|  |____   |____   |   |   |    ___|
| | |   |       | |_____|   |_||_|       |____|  |____|  |   |   |   |___ 
| |_|   |  _    |_____  |    __  |       | ______| ______|   |___|    ___|
|       | | |   |_____| |   |  | |   _   | |_____| |_____|       |   |___ 
|______||_|  |__|_______|___|  |_|__| |__|_______|_______|_______|_______|
'''

def portscan(domain, out_dir):
    print_status("Running nmap on "+ domain )
    nm = nmap.PortScanner()
    if not os.path.isfile(out_dir+'/nmap/'):
        create_folders(out_dir)
    nm.scan(hosts=domain, arguments='-A -T4 -sV -oG ' + out_dir + '/nmap/' + domain + '.txt')
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    print(nm.csv())



def check_domain(domain):
    '''
    primary method for performing domain checks
    '''
    print_status("Checking domain " + domain + "!")



def write_to_file(data, target_file):
    """
    Function for writing returned data to a file
    """
    f = open(target_file, "w")
    f.write(data)
    f.close()

def screenshot_domain(domain,out_dir):
    """
    function to take screenshot of supplied domain
    """
    cwd = os.getcwd()
    options = webdriver.ChromeOptions()
    options.headless = True
    driver = webdriver.Chrome(ChromeDriverManager().install(),options=options)
    url = "http://" + str(domain).strip('[]')
    driver.get(url)

    if out_dir is not None:
        ss_path = str(out_dir + '/screenshots/' + domain + '.png')
    else:
        ss_path = str(cwd) + '/screenshots/'+ domain + '.png'

    S = lambda X: driver.execute_script('return document.body.parentNode.scroll' + X)
    driver.set_window_size(S('Width'), S(
        'Height'))  # May need manual adjustment
    driver.find_element_by_tag_name('body').screenshot(ss_path)
    driver.quit()
    print_status('Screenshot for ' + domain + ' saved to ' + ss_path)

def create_folders(out_dir):
    '''
    function to create output folders at location specified with -o
    '''
    cwd = os.getcwd()
    if out_dir is not None:
        os.makedirs(out_dir + '/screenshots/', exist_ok=True)
        os.makedirs(out_dir + '/screenshots/original/', exist_ok=True)
        os.makedirs(out_dir + '/dnsrecon/', exist_ok=True)
        os.makedirs(out_dir + '/dnstwist/', exist_ok=True)
        os.makedirs(out_dir + '/nmap/', exist_ok=True)
    else:
        os.makedirs(cwd + '/screenshots/', exist_ok=True)
        os.makedirs(cwd + '/screenshots/original/', exist_ok=True)
        os.makedirs(cwd + '/dnsrecon/', exist_ok=True)
        os.makedirs(cwd + '/dnstwist/', exist_ok=True)
        os.makedirs(cwd + '/nmap/', exist_ok=True)


def main():
    #
    # Option Variables
    #
    os.environ['WDM_LOG_LEVEL'] = '0'
    domain = None
    file = None
    out_dir = None

    print(
        " ______  __    _ _______ ______   _______ _______ _______ ___     _______\n",
        "|      ||  |  | |       |    _ | |   _   |       |       |   |   |       |\n",
        "|  _    |   |_| |  _____|   | || |  |_|  |____   |____   |   |   |    ___|\n",
        "| | |   |       | |_____|   |_||_|       |____|  |____|  |   |   |   |___ \n",
        "| |_|   |  _    |_____  |    __  |       | ______| ______|   |___|    ___|\n",
        "|       | | |   |_____| |   |  | |   _   | |_____| |_____|       |   |___ \n",
        "|______||_|  |__|_______|___|  |_|__| |__|_______|_______|_______|_______|\n")
    #
    # Define options
    #
    parser = argparse.ArgumentParser()
    try:
        parser.add_argument("-d", "--domain", type=str, dest="domain", help="Target domain or domain list.",
                            required=True)
        parser.add_argument("-f", "--file", type=str, dest="file",
                            help="Provide a file containing a list of domains to run DNSrazzle on.")
        parser.add_argument("-o", "--out-directory", type=str, dest="out_dir",
                            help="Absolute path of directory to output reports to.  Will be created if doesn't exist")

        arguments = parser.parse_args()

    except SystemExit:
        # Handle exit() from passing --help
        raise

    domain = arguments.domain
    out_dir = arguments.out_dir
    file = arguments.file


    if domain is None:
        print_status('No Domain to target specified!')
        sys.exit(1)

    elif domain is not None:
        try:
            domain = []
            domain_raw_list = list(set(arguments.domain.split(",")))
            for entry in domain_raw_list:
                print_status(f"Performing General Enumeration of Domain: {entry}")
                if check_domain(entry):
                    continue
                else:
                    check_domain(arguments.domain)
                    screenshot_domain(entry,out_dir)
                    portscan(arguments.domain, arguments.out_dir)

             # if an output xml file is specified it will write returned results.
            if out_dir is not None:
                print_status(f"Saving records to output folder {out_dir}")



            if arguments.file is not None:
                file = []
                # print(arguments.file)
                if os.path.isfile(arguments.file.strip()):
                    infile = arguments.file.strip()
                else:
                    print_error(f"File {arguments.file.strip()} does not exist!")
                    exit(1)

        except dns.resolver.NXDOMAIN:
            print_error(f"Could not resolve domain: {domain}")
            sys.exit(1)

        except dns.exception.Timeout:
            print_error("A timeout error occurred please make sure you can reach the target DNS Servers")
            print_error("directly and requests are not being filtered. Increase the timeout")
            print_error("to a higher number with --lifetime <time> option.")
    else:
        sys.exit(1)




if __name__ == "__main__":
    main()