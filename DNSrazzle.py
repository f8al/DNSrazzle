#!/usr/bin/env python3
import sys
import argparse
import os
import dns.resolver
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from contrib.dnsrecon.tools.parser import print_error, print_status
from skimage.measure import compare_ssim
import dnstwist
from contrib.dnsrecon import *
import nmap
import imutils
import cv2
import math
import ipwhois



# -*- coding: utf-8 -*-

#    DNSRazzle
#
#    Copyright (C) 2020   SecurityShrimp
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
__version__ = '0.0.3'
__author__ = '@securityshrimp'

'''
 ______  __    _ _______ ______   _______ _______ _______ ___     _______ 
|      ||  |  | |       |    _ | |   _   |       |       |   |   |       |
|  _    |   |_| |  _____|   | || |  |_|  |____   |____   |   |   |    ___|
| | |   |       | |_____|   |_||_|       |____|  |____|  |   |   |   |___ 
| |_|   |  _    |_____  |    __  |       | ______| ______|   |___|    ___|
|       | | |   |_____| |   |  | |   _   | |_____| |_____|       |   |___ 
|______||_|  |__|_______|___|  |_|__| |__|_______|_______|_______|_______|
'''

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
    nm.scan(hosts=domain, arguments='-A -T4 -sV -oG ' + out_dir + '/nmap/' + domain + '.txt')
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    print(nm.csv())



def check_domain(tdomain,rdomain,out_dir):
    '''
    primary method for performing domain checks
    '''
    screenshot_domain(domain, out_dir)
    portscan(domain, out_dir)
    compare_screenshots(out_dir + '/screenshots/originals/' + rdomain + '.png',
                        out_dir + '/screenshots/'+ tdomain + '.png')



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


    ss_path = str(out_dir + domain + '.png')
    print ( ss_path )

    S = lambda X: driver.execute_script('return document.body.parentNode.scroll' + X)
    driver.set_window_size(1920,1080)  # May need manual adjustment
    driver.get_screenshot_as_file(ss_path)
    driver.quit()
    print_status(f"Screenshot for {domain} saved to {ss_path}")

def create_folders(out_dir):
    '''
    function to create output folders at location specified with -o
    '''
    cwd = os.getcwd()
    if out_dir is not None:
        os.makedirs(out_dir + '/screenshots/', exist_ok=True)
        os.makedirs(out_dir + '/screenshots/originals/', exist_ok=True)
        os.makedirs(out_dir + '/dnsrecon/', exist_ok=True)
        os.makedirs(out_dir + '/dnstwist/', exist_ok=True)
        os.makedirs(out_dir + '/nmap/', exist_ok=True)
    else:
        os.makedirs(cwd + '/screenshots/', exist_ok=True)
        os.makedirs(cwd + '/screenshots/originals/', exist_ok=True)
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

    banner()
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

    out_dir = arguments.out_dir
    cwd = os.getcwd()

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
         print_status("You must specify either the -d or the -f option")
         sys.exit(1)
    
    # Everything you do depends on "out_dir" being defined, so let's just set it to cwd if we have to.
    if out_dir is None:
        out_dir =  os.getcwd()
    print_status(f"Saving records to output folder {out_dir}")
    create_folders(out_dir)

    try:
        for entry in domain_raw_list:
            print_status(f"Performing General Enumeration of Domain: {entry}")
            screenshot_domain(entry,out_dir+"/screenshots/originals/")


           
            # if check_domain returns TRUE, then we SKIP this domain.
            # If check_domain returns FALSE, then we SAVE this domain.
            # XXX TODO -- are you sure about this? 
            if check_domain(tdomain, entry, out_dir): #tdomain is returned by dnstwist entry is rdomain, out_dir is out_dir
                continue




    except dns.resolver.NXDOMAIN:
        print_error(f"Could not resolve domain: {domain}")
        sys.exit(1)

    except dns.exception.Timeout:
        print_error("A timeout error occurred please make sure you can reach the target DNS Servers")

    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
