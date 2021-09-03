# Project Scope
The scope of this project is to find and detect phishing websites and brand impersonation before it can be used maliciously by a threat actor

# Process
* Use fuzzing engine to generate a list of possible imitation domains
* Check if discovered domains are valid
* Check valid discovered domains for MX records
* Check if discovered domains content is similar to original domain
* Create reports


# Needed Features/abilities
* Use a fuzzing/permutation engine to generate list of domains
    * Expandable by adding either a domain dictionary file, or a TLD dictionary file to get more permutations
* Grab zone information on generated permutations
* A, AAAA, NS, MX records are recorded and displayed to STDOUT as well as written to a file
* Grab WHOIS information on generated domains
    * authoritative NS, creation date, updated date, registrar
* Banner grab and display what webserver is being used to serve site content
* Screenshot initially provided (reference) domain
    * `-o` option specifies where to create the screenshot folder and write screenshot/$domain.png file
* `-o` parameter allows user to specify output directory for all files created during a dnsrazzle run
    * By default this will be the CWD the script is run out of
* When `-o` is specified, this will give the tool the output directory where it will create the 3 output folders
    * dns reports
    * fingerprinting reports
    * screenshots
* Screenshot valid permutated domains using selenium webdriver (chromedriver)
* Compare detected permutated domain screenshot with reference domain screenshot using MSE equation
    * Return MSE score and display to STDOUT whether domain content is similar, identical, or different.
* If the parameter is selected, use NMAP to offensively fingerprint detected domains and write scan results to a file
    * `-o` option specifies where to create the nmap folder and write ./nmap/$domain.txt file with output
* If the parameter is selected, use recondns to generate a dnsrecon style report for all discovered domains and write them to files
    * `-o` option specifies where to create the recondns folder and write ./recondns/$domain.txt file with output


# Acceptance Criteria
Acceptance criteria for this project being complete is that a user can use this tool to do the following actions:
* User provides a domain name
* Tool returns a list of discovered impersonation domains
* Tool removes invalid discovered domains
* Tool then compares the original domain to the discovered valid domains
* Tool can return a score that is representative of how similar or different discovered domains are to the original reference domain
* Tool can generate reports on discovered domains
   * nmap report
   * dnsrecon style DNS report
