[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/f8al/DNSrazzle.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/f8al/DNSrazzle/context:python)

    ______  __    _ _______ ______   _______ _______ _______ ___     _______ 
    |      ||  |  | |       |    _ | |   _   |       |       |   |   |       | 
    |  _    |   |_| |  _____|   | || |  |_|  |____   |____   |   |   |    ___|
    | | |   |       | |_____|   |_||_|       |____|  |____|  |   |   |   |___ 
    | |_|   |  _    |_____  |    __  |       | ______| ______|   |___|    ___|
    |       | | |   |_____| |   |  | |   _   | |_____| |_____|       |   |___ 
    |______||_|  |__|_______|___|  |_|__| |__|_______|_______|_______|_______|


A pure python tool for finding and comparing typo-squatting, bytesqatting, phishing attacks and brand impersonation

This tool depends on DNSTwist, DNSRecon, and nmap

![DNSRazzle](/docs/dnsrazzle.png)

DNS fuzzing is an automated workflow for discovering potentially malicious domains targeting your organisation. This tool works by using dnstwists permutation engine to generating a large list of permutations based on a domain name you provide, and then checking if any of those permutations are in use. Additionally, it generates screenshots of the original domain, and the discovered web pages, and compares them using computer vision to see if they are part of an ongoing phishing attack or brand impersonation, and much more!