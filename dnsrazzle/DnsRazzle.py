from .BrowserUtil import screenshot_domain
from .NetUtil import run_portscan, run_recondns
from .VisionUtil import compare_screenshots
import queue

class DnsRazzle():
    def __init__(self, domain, out_dir, tld, dictionary, file, useragent, debug, threads, nmap, recon, driver, nameserver = '1.1.1.1'):
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
        self.nameserver = nameserver
        self.driver = driver

    def gen(self, shouldPrint=False):
        from dnstwist import DomainFuzz
        fuzz = DomainFuzz(self.domain, self.dictionary, self.tld)
        fuzz.generate()
        if self.tld is not None:
            for entry in fuzz.domains.copy():
                for tld in self.tld:
                    new_domain = ".".join(entry["domain-name"].split(".")[:-1]) + "." + tld;
                    fuzz.domains.append({"fuzzer": 'tld-swap', "domain-name": new_domain})
            m = getattr(fuzz, "_DomainFuzz__postprocess")
            m()
        if shouldPrint:
            for entry in fuzz.domains[1:]:
                print(entry['domain-name'])
        self.domains = fuzz.domains

    def gendom_start(self, useragent, threadcount=10):
        from dnstwist import DomainThread, UrlParser
        url = UrlParser(self.domain)

        for i in range(len(self.domains)):
            self.jobs.put(self.domains[i])
        self.jobs_max = len(self.domains)

        for _ in range(threadcount):
            worker = DomainThread(self.jobs)
            worker.setDaemon(True)

            self.kill_received = False
            self.debug = False

            worker.option_extdns = True
            worker.option_geoip = False
            worker.option_ssdeep = False
            worker.option_banners = True
            worker.option_mxcheck = True

            worker.nameservers = [self.nameserver]
            self.useragent = useragent

            worker.uri_scheme = url.scheme
            worker.uri_path = url.path
            worker.uri_query = url.query

            worker.domain_init = url.domain
            worker.start()
            self.threads.append(worker)

    def gendom_stop(self):
        for worker in self.threads:
            worker.stop()
            worker.join()

    def check_domain(self, domains, r_domain, out_dir, nmap, recon, threads):
        '''
        primary method for performing domain checks
        '''
        screenshot_domain(self.driver, domains['domain-name'], out_dir + '/screenshots/')
        ssim_score = compare_screenshots(out_dir + '/screenshots/originals/' + r_domain + '.png',
                            out_dir + '/screenshots/' + domains['domain-name'] + '.png')
        domains['ssim-score'] = ssim_score
        if nmap:
            run_portscan(domains['domain-name'], out_dir)
        if recon:
            run_recondns(domains['domain-name'], self.nameserver, out_dir, threads)
