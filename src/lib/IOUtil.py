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

__version__ = '0.0.8'
__author__ = 'SecurityShrimp'
__twitter__ = '@securityshrimp'

def create_folders(out_dir):
    '''
    function to create output folders at location specified with -o
    '''
    os.makedirs(out_dir + '/screenshots/', exist_ok=True)
    os.makedirs(out_dir + '/screenshots/originals/', exist_ok=True)
    os.makedirs(out_dir + '/dnsrecon/', exist_ok=True)
    os.makedirs(out_dir + '/dnstwist/', exist_ok=True)
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
    #print(f"Version {version} by {author}")

def print_status(message=""):
    print(f"\033[1;34m[*]\033[1;m {message}")


def print_good(message=""):
    print(f"\033[1;32m[*]\033[1;m {message}")


def print_error(message=""):
    print(f"\033[1;31m[-]\033[1;m {message}")


def print_debug(message=""):
    print(f"\033[1;31m[!]\033[1;m {message}")


def print_line(message=""):
    print(f"{message}")