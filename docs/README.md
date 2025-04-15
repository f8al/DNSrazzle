    ______  __    _ _______ ______   _______ _______ _______ ___     _______ 
    |      ||  |  | |       |    _ | |   _   |       |       |   |   |       | 
    |  _    |   |_| |  _____|   | || |  |_|  |____   |____   |   |   |    ___|
    | | |   |       | |_____|   |_||_|       |____|  |____|  |   |   |   |___ 
    | |_|   |  _    |_____  |    __  |       | ______| ______|   |___|    ___|
    |       | | |   |_____| |   |  | |   _   | |_____| |_____|       |   |___ 
    |______||_|  |__|_______|___|  |_|__| |__|_______|_______|_______|_______|

---
A pure python tool for finding and comparing typo-squatting, bitsqatting, and homoglyph domains for detecting brand impersonation

![DNSRazzle](/docs/dnsrazzle.gif)

DNSrazzle's DNS fuzzing is an automated workflow for discovering potentially malicious domains targeting your organisation. This tool works by using dnstwists permutation engine to generate a large list of permutations based on a domain name you provide, and then checking if any of those permutations are in use. Additionally, it generates screenshots of the original domain, and the discovered web pages, and compares them using computer vision to see if they are part of an ongoing phishing attack or brand impersonation, and much more!

## Version 1.6.x note
- The selenium webdriver manager package has been deprecated and this project now uses Seleniums own manager, "Selenium Manager"
- DNSRazzle is now using RDAP instead of WHOIS for returning the registration information after changes made by Verisign regarding rate limiting of their WHOIS servers.  This will be functionally transparent in the output

## Version 1.5.x+ note
DNSRazzle no longer outputs all the discovered domains and their info and scores to console, it is now placed in a CSV file so you can start a DNSRazzle run and go do something else instead of having to babysit it to get the scores and DNS info.


# Installation steps
```
git clone https://github.com/f8al/DNSRazzle
cd DNSRazzle
python3 -m venv .
source bin/activate
pip3 install --upgrade pip
pip3 install -r requirements.txt
```


# Usage

![DNSRazzle_usage](/docs/usage.png)

DNSRazzle supports single domain names, a comma seperated list of domain names, with the -d option, or a file containing a list of domain names, 1 per line with the -f option.

## Basic command
```$ python3 DNSRazzle.py -d acme.com -o outdir```

## Required arguments

    -d DOMAIN, --domain DOMAIN   | Target domain or domain list.
  
                                            OR
  
    -f FILE, --file FILE         | Provide a file containing a list of domains to run DNSrazzle on.

## Optional arguments

    -h, --help                                        | Show help message and exit
    --browser                                         | specify what browser for seleium to use. Options: '(chrome|firefox)'
  
    -D FILE, --dictionary FILE                        | Path to dictionary file to pass to DNSTwist to aid in domain permutation generation.

    -g, --generate                                    | Do a dry run of DNSRazzle and just output permutated domain names
  
    -n, --nmap                                        | Perform nmap scan on discovered domains
  
    -o OUT_DIR, --out-directory OUT_DIR               | Absolute path of directory to output reports to. Will be created if doesn't exist
  
    -r, --recon                                       | Create dnsrecon report on discovered domains.
  
    -t THREADS, --threads THREADS                     | Number of threads to use in permutation checks, reverse lookups, forward lookups, brute force and SRV record enumeration.
    
    --tld FILE                                        | Path to TLD dictionary file.
  
    -u STRING, --useragent STRING                     | User-Agent STRING to send with HTTP requests (default: Mozilla/5.0 dnsrazzle/0.1.0)
    
    --debug                                           | Print debug messages



## Output
Upon successful execution of a base run without dnsrecon reports or nmap runs, there will be a folder and 2 files output,
- screenshots - contains the screenshots of the discovered domains
  - screenshots/originals - contains the screenshots of the original reference domain
- discovered-domains.csv - CSV file containing all of the discovered domains as well as all of the discovered information about them
- domain_similarity.csv - CSV file containing the domain name and the similarity score

## Known Compatibility Issues
As of version 1.5.3, thereare no known incompatibilities with Apple silicon. All utilized libraries now have pip installable ARM64 wheels or have compatible setup.py instruction sets
