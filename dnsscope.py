#!/usr/bin/python3

import sys, tty, socket, ssl, OpenSSL, ipaddress, logging, argparse, termios
from ipwhois import IPWhois
from dns import resolver, reversename
import sublister as sl
from tld import get_tld, get_fld

# Setup Argument Parameters 
progname = 'DNSscope'
parser = argparse.ArgumentParser(description='Takes a list of IPs and look for domains/subdomains that are associated with them or vice versa')
parser.add_argument('-i', '--infile', help='File with explicitly in-scope IPs to check DNS records', required=True)
parser.add_argument('-o', '--outfile', help='Output file. Default is DNSscope_results.txt', default='DNSscope_results.txt')
parser.add_argument('-d', '--domain', help='run subdomain enumeration on a single domain')
parser.add_argument('-D', '--domains', help='File with FLDs to run subdomain enumeration')
parser.add_argument('-s', '--subdomains', help='File with FQDN of subdomains to include in scope')
parser.add_argument('--tls', action="store_true", help='NON-PASSIVE! - For each identified subdomain and IP, check port 443 for TLS certificate CN and SAN')
parser.add_argument('-p', '--ports', nargs='+', help='NON-PASSIVE! - To be run with the --tls command. Provide additional ports to check for TLS certificate CNs i.e. --tls --ports 8443,9443')
args = parser.parse_args()

logging.basicConfig(level=logging.INFO, filename="output.log", filemode="w", format="%(asctime)-15s %(levelname)-8s %(message)s")

# Keep track of in scope IP addresses from initial infile 
inscope = {}
# Keep track of all out of scope IP addresses and the domains that resolve to them
outscope = {}
# Keep track of all identified domains that don't resolve to IPs
dead_domains = set()
# Keep track of flds that have been asked/tested already
flds_processed = set()
# Keep track of domains that did not have their FLD in scope - if it is determined to be in scope, then we revisit these and process them
revisit_queue = set()
# Keep track of all FLDs we have seen so we don't double process
flds_seen = set()
# Keep track of new FLDs so they can be determined to be in or out of scope
flds_new = set()
# Keep track of FLDs that have been deemed in-scope
flds_inscope = set()
# Keep track of domains and IPs that have been processed
processed = set()
flds_ignore= ["googleusercontent.com","amazonaws.com","akamaitechnologies.com","office.com","office.net","windows.net","microsoftonline.com","azure.net","live.com","cloudfront.net","awsglobalaccelerator.com","outlook.com","microsoft.com","office365.com","office.com","office.net","windows.net","microsoftonline.com","azure.net","live.com","outlook.com","microsoft.com","office365.com","msidentity.com","windowsazure.us","live-int.com","microsoftonline-p-int.com","microsoftonline-int.com","microsoftonline-p.net","microsoftonline-p.com","windows-ppe.net","microsoft-ppe.com","passport-int.com","microsoftazuread-sso.com","azure-ppe.net","ccsctp.com","b2clogin.com","authapp.net","azure-int.net","secureserver.net","windows-int.net","microsoftonline-pst.com","microsoftonline-p-int.net","sl-reverse.com","incapdns.net","comcastbusiness.net","akamaized.net","cloudflaressl.com", "wpengine.com"]

# Queues for keeping track of remaining items to test
IPq = set()
Dq = set()

r = resolver.Resolver()
r.timeout = .7
r.lifetime = .7

# Read IPs from file and add to inscope
# inscope is dictionary with IP as key
def readips():
    f=open(args.infile, "r")
    for x in f: 
        x = x.strip()
        if isIP(x):
            IPq.add(str(x))
        else:
            try:
                cidr = ipaddress.IPv4Network(x)
                for ip in cidr:
                    IPq.add(str(ip))
            except:
                # skip because not a CIDR or IP
                continue

def printout():
    print("\n\nExplicitly In scope (resolves to IP provided in infile):\n")
    for x in inscope: 
        if inscope[x]:
            print(x + ":" + ','.join(str(s) for s in inscope[x]))
    print("\n\nTentatively in scope (IP not in provided infile but FLD determined to be in scope):\n")
    outscope1 = {}
    for y in outscope:
        inscopeFLD = False
        for s in outscope[y]:
            fld = get_fld(s, fix_protocol=True)
            # check if any of domains that resolve to IP are in scope flds:
            if fld in flds_inscope:
                inscopeFLD = True
                break
        if inscopeFLD:
            print(y + ":" + ','.join(outscope[y]))
        else: outscope1[y] = outscope[y]
    print("\n\nOut of scope:\n")
    for y in outscope1: print(y + ":" + ','.join(outscope[y]))
    print("\n\nDead domains (identified subdomains that did not resolve):\n")
    for z in dead_domains: print(z)

def getch():
    def _getch():
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch
    return _getch()


def printfile(filename):
    f=open(filename, "w+")
    f.write("Explicitly In scope (resolves to IP provided in infile):\n")
    for x in inscope: 
        if inscope[x]:
            f.write(x + ":" + ','.join(str(s) for s in inscope[x]) + "\n")
    f.write("\n\nTentatively in scope (IP not in provided infile but FLD determined to be in scope:\n")
    outscope1 = {}
    for y in outscope:
        inscopeFLD = False
        for s in outscope[y]:
            fld = get_fld(s, fix_protocol=True)
            # check if any of domains that resolve to IP are in scope flds:
            if fld in flds_inscope:
                inscopeFLD = True
                break
        if inscopeFLD:
            f.write(y + ":" + ','.join(outscope[y]) + "\n")
        else: outscope1[y] = outscope[y]
    f.write("\n\nOut of scope:\n")
    for y in outscope1: f.write(y + ":" + ','.join(outscope[y]) + "\n")
    f.write("\n\nDead domains (identified subdomains that did not resolve):\n")
    for z in dead_domains: f.write(z + "\n")

def alreadyProcessed(nameorip):
    if nameorip in processed:
        return True
    else:
        return False

# Do a reverse DNS lookup for single IP, add to keep track
def rDNS(ip):
    try:
        # get reversename i.e. 10.10.10.10.in-addr.arpa
        rev = reversename.from_address(ip)
        # get reverse DNS entry
        for name in r.resolve(rev,"PTR"):
            name = str(name).rstrip('.')
            if "in-addr.arpa" in name: continue
            if not alreadyProcessed(name):
                log("(+) rDNS DISCOVERY! ADDING TO QUEUE: %s" %name)
                Dq.add(name)
    except Exception as e: 
        log("rDNS lookup failed on: " + ip)
        log("\tException: %s" % e)

def get_certificate(host, port=443):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode=ssl.CERT_NONE
        conn = socket.create_connection((host, port),0.5)
        sock = context.wrap_socket(conn, server_hostname=host)
        der_cert = sock.getpeercert(True)
        sock.close()
        return ssl.DER_cert_to_PEM_cert(der_cert)
    except:
        "Could not get TLS Certificate from %s on port %i" % (host,port)

def TLSenum(hostname,port=443):
    # This should actually grab CN and SAN. Returns List in format of hostname/ip,CN,SAN,SAN,SAN,SAN,etc.
    try:
        log("Attempting to get certificate for %s" % hostname)
        certificate = get_certificate(hostname,port)
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
    
        result = {
            'subject': dict(x509.get_subject().get_components()),
            'issuer': dict(x509.get_issuer().get_components()),
        }

        extensions = (x509.get_extension(i) for i in range(x509.get_extension_count()))
        extension_data = {e.get_short_name(): str(e) for e in extensions}
        result.update(extension_data)
        CN = result['subject'][b'CN'].decode("utf-8").lower()
        certdata = set()
        certdata.add(CN)
        SANs = result[b'subjectAltName'].split(",")
        for s in SANs:
            SAN = s.split(":")[1].lower()
            certdata.add(SAN)
        log("(+) Success")
        for x in certdata:
            if not alreadyProcessed(x):
                # Add this check to add to correct queue, since TLSenum can be called on IP addresses or domains
                if isIP(x) and x not in IPq and x != hostname: 
                    log("(+) TLSENUM DISCOVERY! ADDING TO IP QUEUE: %s" %x)
                    IPq.add(x)
                elif x not in Dq and x != hostname:
                    log("(+) TLSENUM DISCOVERY! ADDING TO DOMAIN QUEUE: %s" %x)
                    Dq.add(x)
        return certdata
    except: 
        log("(-) Failed")
        return False

def getwhois(domain):
    # forward DNS
    # for first IP, grab whois data
    try:
        ips = r.resolve(domain, "A")
        for ip in ips:
            ip = str(ip)
            ipwhoisraw = IPWhois(ip)
            whoisdata = ipwhoisraw.lookup_rdap(depth=1)
            return whoisdata
    except Exception as e: 
        return False

def printwhois(domain, whoisarray):
    ### TODO ### 
    ### add option to add asn_cidr to scope and process IPs ###
    ############
    whoisdata = whoisarray[domain]
    log("\n---------------------------------------------------------------------------")
    log("%s WHOIS DATA:" % domain)
    if not whoisdata: 
        log("\t\tFailed to get whoisdata for %s" % domain)
        return False
    
    try:
        log("\t\tresolves to %s:" %  ip)
        log("\t\tasn_cidr: %s" % whoisdata["asn_cidr"])
        log("\t\tnetwork name: %s" % whoisdata["network"]["name"])
        log("\t\tasn_description: %s" % whoisdata["asn_description"])
        # Grab first 2 items of Whois Org names, emails, and addresses
        i = 2
        for obj in whoisdata["objects"]:
            if i==0: break
            log("\t\tOrg Name: %s" % whoisdata["objects"][obj]["contact"]["name"])
            email = whoisdata["objects"][obj]["contact"]["email"]
            if email:
                log("\t\tContact Email: %s" % email[0]["value"])
            address = whoisdata["objects"][obj]["contact"]["address"]
            if address:
                address_split=address[0]["value"].split("\n")
                log("\t\tOrg Contact Address: %s" % ", ".join(address_split))
            i=i-1
        return True
    except Exception as e: 
        log("(-) Error printing whois data for %s" % domain)
        log("\tException: %s" % e)
        return False

def newFLD(fld, whoisdata):
    # I don't think this check needs to be here, should be accounted for already but leaving just in case to prevent endless recursion:
    if fld in flds_processed:
        return False
    flds_processed.add(fld)
    log("\nNewly discovered top-level domain: %s" % fld)
    for x in flds_ignore:
        if x in fld:
            log("(-) FLD is in list of FLDs to ignore. %s not added to scope.\n" % fld)
            return False
    printwhois(fld, whoisdata)
    prompt = "\nAdd %s domain to scope? This will run additional subdomain enumeration (y/n) " %fld
    log(prompt)
    while True:
        print()
        choice = getch().lower()
        if choice == 'y':
            log("(+) %s ADDED TO SCOPE!\n" % fld)
            log("---------------------------------------------------------------------------")
            return fld
        elif choice == 'n': 
            log("(-) %s not added to scope.\n" % fld)
            log("---------------------------------------------------------------------------")
            return False
        else:
            print("Please choose y/n")

def log(string):
    #if not args.quiet: print(string)
    print(string)
    logging.info(string)

# Do a forward DNS lookup for a domain names and add to inscope/outscope/dead_domains
def fDNS(name):
    log("Forward DNS lookup for %s" % name)
    name=name.strip("\n")
    try:
        ips = r.resolve(name, "A")
        for ip in ips:
            ip = str(ip)
            if not alreadyProcessed(ip) and isIP(ip):
                log("(+) DNS IP DISCOVERY! ADDING TO QUEUE: %s" %ip)
                IPq.add(ip)
            if ip in inscope.keys(): inscope[ip].add(name)
            elif ip in outscope.keys(): outscope[ip].add(name)
            else: outscope[ip] = {name}
        return True
    except Exception as e: 
        log("(-) fDNS lookup failed on: " + name)
        log("\tException: %s" % e)
        dead_domains.add(name)
        return False


# run sublist3r on domain and do forward DNS lookup for each
def sublister(domain):
    log("Searching for subdomains of %s. This may take a few seconds..." % domain)
    bf = False
    subdomains = sl.sublister_main(domain, 30, None, None, silent=True, verbose=False, enable_bruteforce=bf, engines=None)
    return subdomains

def isIP(ip):
    try:
        ipaddress.ip_address(ip)
        if ipaddress.ip_address(ip).is_private:
            log("(+) Private/Internal IP Address Identified: %s" % str(ip))
        return True
    except:
        return False


# Take a FLD and return subdomains identified with sublister
def SDenum(domain):
    subdomains = set()
    SLresults = sublister(domain)
    for sd in SLresults:
        # Deal with sublist3r multiple entries separated by <BR>:
        if "<BR>" in sd:
            for x in sd.split("<BR>"): subdomains.add(x)
        else: subdomains.add(sd)
    for subdomain in subdomains:
        subdomain = subdomain.lower()
        if not alreadyProcessed(subdomain) and subdomain != domain:
            log("(+) SUBDOMAIN ENUM DISCOVERY: ADDING TO QUEUE: %s" %subdomain)
            Dq.add(subdomain)
    return subdomains


if __name__ == '__main__':
    log("Starting %s" % progname)
    log("Processing IPs from %s" %args.infile) 
    readips()
    for ip in IPq:
        inscope[ip.rstrip('\n')]=set()
    ### TODO ###
    ### Add option for list of subdomains to include. Read from this list and add them to the domain queue
    ### Alternatively have subdomain prefix that checks against all in-scope FLDs
    ###########

    # Injest FLDs and run subdomain enumeration on all of them
    initdomains = set()
    if args.domain:
        domain = args.domain.lower()
        Dq.add(domain)
        initdomains.add(domain)
        flds_processed.add(domain)
        flds_inscope.add(domain)
    if args.domains:
        f=open(args.domains, "r")
        for domain in f: 
            domain = domain.strip().lower()
            Dq.add(domain)
            initdomains.add(domain)
            flds_processed.add(domain)
            flds_inscope.add(domain)
    for domain in initdomains:
        subdomains = SDenum(domain)
    ports = {}
    if args.tls:
       ports={443}
       if args.ports: 
           for x in args.ports: ports.add(int(x))
    if args.subdomains:
        f=open(args.subdomains, "r")
        for sd in f:
            subdomain = sd.strip().lower()
            Dq.add(subdomain)
    # Main loop - go through remaining IPs and domains and run flow for each
    # and add additional discovered IPs or domains to queue
    # Currently pops and processes one IP and one domain per iteration in this while loop
    while (Dq or IPq or flds_new):
        if Dq: 
            domain = Dq.pop()
            if not alreadyProcessed(domain):
                log("")
                log("Processing domain: %s" %domain)
                try:
                    fld = get_fld(domain, fix_protocol=True)
                except:
                    log("(+) Getting FLD for %s Failed! This may suggest an internal domain name!" % domain)
                    dead_domains.add("{INTERNAL DOMAIN???}  " + domain)
                    continue
                ignore = False
                for x in flds_ignore:
                    if x in fld:
                        log("(-) FLD is in list of FLDs to ignore. Ignoring %s" % fld)
                        ignore = True
                if not ignore:
                    if not alreadyProcessed(fld) and fld not in flds_processed and fld not in flds_seen:
                        flds_new.add(fld)
                        flds_seen.add(fld)
                    if fld in flds_inscope:
                        fDNS(domain)
                        if domain not in dead_domains:
                            for port in ports:
                                TLSenum(domain,port)
                        processed.add(domain)
                    else:
                        log("FLD not in scope. Will return to %s if FLD is added to scope" % domain)
                        if domain not in revisit_queue:
                            revisit_queue.add(domain)
                log("Finished processing domain: %s" %domain)
        if IPq: 
            ip = IPq.pop()
            if not alreadyProcessed(ip):
                log("")
                log("Processing IP: %s" %ip)
                rDNS(ip)
                if ip in inscope:
                    for port in ports:
                        TLSenum(ip,port)
                log("Finished Processing IP: %s" %ip)
                processed.add(ip)

        if not Dq and not IPq and flds_new:
            log("(+++) Finished processing IP and Domain queues\n\n\n") 
            log("---------------------------------------------------------------------------\n")
            if flds_new:
                log("%d New FLDs discovered for additional processing!\n\n" % len(flds_new)) 
                log(flds_new)
            flds_to_process = set()
            whoisdata = {}
            log("\n(+) Grabbing whois data for new FLDs. Be patient, this can take a while for large environments!\n")
            for fld in flds_new:
                whoisdata[fld] = getwhois(fld)
            for fld in flds_new:
                # if newfld is populated, the fld has been added to scope
                newfld = newFLD(fld, whoisdata)
                if newfld:
                    flds_to_process.add(newfld)
            # Reset flds_new queue for next round of enum
            flds_new = set()
            # Process new FLDs selected as in-scope
            log("(+++) Resuming processing IP and Domain queues\n\n\n")
            for fld in flds_to_process:
                flds_inscope.add(fld)
                # If we added the FLD to scope, then we need to revisit
                for domain in revisit_queue:
                    if fld in domain and domain != fld: 
                        log("(+) Adding Domain %s back to queue to be processed - FLD was marked in-scope" % domain)
                        Dq.add(domain)
                SDenum(fld)
                Dq.add(fld)
            
    print("-------------------------------------")
    printout()
    if args.outfile: printfile(args.outfile)


