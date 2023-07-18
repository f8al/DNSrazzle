from src.lib.IOUtil import *

def run_whois(domains, debug):
    from progress.bar import Bar
    num_doms = len(domains)
    pBar = Bar('Running whois queries on discovered domains', max=num_doms - 1)
    for domain in domains:
        if len(domain) > 2:
            try:
                from whois import query
                whoisq = query(domain['domain-name'].encode('idna').decode())
            except Exception as e:
                if debug:
                    print_error(e)
            else:
                if whoisq is not None:
                    if whoisq.creation_date:
                        domain['whois-created'] = str(whoisq.creation_date).split(' ')[0]
                    if whoisq.registrar:
                        domain['whois-registrar'] = str(whoisq.registrar)
        pBar.next()
    pBar.finish()


def run_portscan(domains, out_dir):
    print_status(f"Running nmap on {domains}")
    import nmap
    nm = nmap.PortScanner()
    nm.scan(hosts=domains, arguments='-A -T4 -sV')
    f = open(out_dir + '/nmap/' + domains + '.csv', "w")
    f.write(nm.csv())
    f.close()


def run_recondns(domains, nameserver, out_dir, threads):
    '''
    :param domain: domain to run dnsrecon on
    :param out_dir: output directory to save records to
    general_enum arguments : res, domain, do_axfr, do_bing, do_yandex, do_spf, do_whois, do_crt, zw, thread_num=None
    :return:
    '''
    print_status(f'Running reconDNS report on {domains}!')
    from recondns import general_enum, DnsHelper, make_csv
    ns_server = [nameserver]
    request_timeout = 10
    proto = 'udp'
    res = DnsHelper(domains, ns_server, request_timeout, proto)
    std_records = general_enum(res, domains, False, False, False, True, False, True, True, threads)
    write_to_file(make_csv(std_records), out_dir , '/reconDNS/' + domains + '.txt')
