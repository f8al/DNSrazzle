[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/f8al/DNSrazzle.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/f8al/DNSrazzle/context:python)

    ______  __    _ _______ ______   _______ _______ _______ ___     _______ 
    |      ||  |  | |       |    _ | |   _   |       |       |   |   |       | 
    |  _    |   |_| |  _____|   | || |  |_|  |____   |____   |   |   |    ___|
    | | |   |       | |_____|   |_||_|       |____|  |____|  |   |   |   |___ 
    | |_|   |  _    |_____  |    __  |       | ______| ______|   |___|    ___|
    |       | | |   |_____| |   |  | |   _   | |_____| |_____|       |   |___ 
    |______||_|  |__|_______|___|  |_|__| |__|_______|_______|_______|_______|


A pure python tool for finding and comparing typo-squatting, bytesqatting, phishing attacks and brand impersonation

This tool depends on DNSTwist and nmap

![DNSRazzle](/docs/dnsrazzle.gif)

DNSrazzle's DNS fuzzing is an automated workflow for discovering potentially malicious domains targeting your organisation. This tool works by using dnstwists permutation engine to generating a large list of permutations based on a domain name you provide, and then checking if any of those permutations are in use. Additionally, it generates screenshots of the original domain, and the discovered web pages, and compares them using computer vision to see if they are part of an ongoing phishing attack or brand impersonation, and much more!

# To-Do:
- [x] Add compatibility instructions for Apple Silicon
- [ ] Add support for YOLO image processing for specific site artifact discovery (IE company logos, webforms, etc)
- [ ] Add [darknet](https://github.com/pjreddie/darknet) neural network support for increasing speed of comparisons and detections and allow custom training

# Usage

![DNSRazzle_usage](/docs/usage.png)

DNSRazzle supports single domain names, a comma seperated list of domain names, with the -d option, or a file containing a list of domain names, 1 per line with the -f option.

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
    
    
    
    
    
    
## Known Compatibility Issues
As of version 1.5.0, thereare no known incompatibilities with Apple silicon. All utilized libraries now have pip installable ARM64 wheels or have compatible setup.py instruction sets
