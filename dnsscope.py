#!/usr/bin/python3

import server
import sqlite3, json, sys, tty, socket, ssl, ipaddress, logging, argparse, termios, OpenSSL, re, requests
from bs4 import BeautifulSoup
from ipwhois import IPWhois
from dns import resolver, reversename
import sublister as sl
from tld import get_tld, get_fld

# Setup Argument Parameters 
progname = 'DNSscope'
parser = argparse.ArgumentParser(description='Takes a list of IPs and look for domains/subdomains that are associated with them or vice versa')
parser.add_argument('-i', '--infile', help='File with explicitly in-scope IPs to check DNS records')
parser.add_argument('-d', '--domain', help='run subdomain enumeration on a single domain')
parser.add_argument('-D', '--domains', help='File with FLDs to run subdomain enumeration')
parser.add_argument('-s', '--subdomains', help='File with FQDN of subdomains to include in scope')
parser.add_argument('--notls', action="store_true", help='Skip TLS checks and only run pure DNS enumeration')
parser.add_argument('-p', '--ports', nargs='+', default=['443'], help='Provide additional ports besides 443 to check for TLS certificate CNs. i.e. to run TLSenum on ports 443,8443,9443,and 8080, run: --ports 8443 9443 8080')
parser.add_argument('--server', action = "store_true",  help='Just runs the webserver on port http://localhost:5432')
parser.add_argument('--reprocess', action = "store_true",  help='This will delete all entries in the "processed" table. This means all data will remain present but all identified domains and IP addressed will be treated as new and will be reprocessed.')
args = parser.parse_args()

logging.basicConfig(level=logging.INFO, filename="output.log", filemode="a", format="%(asctime)-15s %(levelname)-8s %(message)s")

# Create database and tables:
# don't check same thread - this is only called single-threaded in this script unless being called from server.py which is read-only
con = sqlite3.connect("DNSscope.db", check_same_thread=False)
db = con.cursor()
createtable = "CREATE TABLE IF NOT EXISTS "
db.execute(createtable + "dead_domains(domain,fld_inscope,UNIQUE(domain))")
db.execute(createtable + "flds(fld,fld_inscope,whoisdata,UNIQUE(fld))")
db.execute(createtable + "data(ip,domains,ip_inscope,UNIQUE(ip))")
db.execute(createtable + "processed(domainorip,type,fld_inscope,fld,certdata,UNIQUE(domainorip))")

flds_ignore = ["googleusercontent.com","amazonaws.com","akamaitechnologies.com","office.com","office.net","windows.net","microsoftonline.com","azure.net","live.com","cloudfront.net","awsglobalaccelerator.com","outlook.com","microsoft.com","office365.com","office.com","office.net","windows.net","microsoftonline.com","azure.net","live.com","outlook.com","microsoft.com","office365.com","msidentity.com","windowsazure.us","live-int.com","microsoftonline-p-int.com","microsoftonline-int.com","microsoftonline-p.net","microsoftonline-p.com","windows-ppe.net","microsoft-ppe.com","passport-int.com","microsoftazuread-sso.com","azure-ppe.net","ccsctp.com","b2clogin.com","authapp.net","azure-int.net","secureserver.net","windows-int.net","microsoftonline-pst.com","microsoftonline-p-int.net","sl-reverse.com","incapdns.net","comcastbusiness.net","akamaized.net","cloudflaressl.com", "wpengine.com"]

# Queues for keeping track of remaining items to test
IPq = set()
Dq = set()

r = resolver.Resolver()
r.timeout = .8
r.lifetime = .8
r.nameservers = ['1.1.1.1','8.8.8.8']

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
                continue


def alreadyProcessed(nameorip):
    db.execute("SELECT domainorip FROM processed WHERE domainorip=?",(nameorip,))
    result = db.fetchone()
    if result:
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
    # This should actually grab CN and SAN. Returns List in format of CN,SAN,SAN,SAN,SAN,etc.
    try:
        log("Attempting to get certificate for %s:%s" % (hostname,str(port)))
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
    except Exception as e: 
        log("(-) Failed: %s" % e)
        return False

def getwhois(domain):
    # forward DNS - for first IP, grab whois data
    try:
        ips = r.resolve(domain, "A", lifetime=1.5)
        for ip in ips:
            ip = str(ip)
            object = IPWhois(ip)
            whoisdata = object.lookup_rdap(depth=3, asn_methods=['whois'])
            return whoisdata
    except Exception as e: 
        return "Error getting whoisdata. \nDetailed Error:\n%s" % e

def log(string):
    print(string)
    logging.info(string)

# Do a forward DNS lookup for a domain names and add to database
def fDNS(name,fldinscope,fld):
    log("Forward DNS lookup for %s" % name)
    name=name.strip("\n")
    try:
        ips = r.resolve(name, "A")
        for ip in ips:
            ip = str(ip)
            if not alreadyProcessed(ip) and isIP(ip):
                log("(+) DNS IP DISCOVERY! ADDING TO QUEUE: %s" %ip)
                IPq.add(ip)
            db.execute("SELECT domains FROM data WHERE ip = ?", (ip,))
            result = db.fetchone()
            # If row already exists
            if result:
                # check if any domains already associated. If not, add the current domain to the list
                if result[0] == "":
                    updateddomains = {name}
                else:
                    # Convert domains string to set
                    updateddomains = set(result[0].split(','))
                    updateddomains.add(name)
                # Convert domains set back to comma separated string
                updatedcommastring = ','.join(updateddomains)
                db.execute("UPDATE data SET domains = ? WHERE ip = ?", (updatedcommastring,ip))
            else:
                db.execute("INSERT INTO data VALUES(?,?,?)", (ip,name,False))
        return True
    except Exception as e: 
        log("(-) fDNS lookup failed on: " + name)
        log("\tException: %s" % e)
        # Add domain to dead_domains
        db.execute("INSERT OR REPLACE INTO dead_domains VALUES(?,?)", (name,fldinscope))
        return False


# run sublist3r on domain and do forward DNS lookup for each
def sublister(domain):
    log("Searching for subdomains of %s via sublist3r. This may take a while..." % domain)
    bf = False
    subdomains = sl.sublister_main(domain, 30, None, None, silent=False, verbose=False, enable_bruteforce=bf, engines=None)
    return subdomains

def get_crt_sh(domain):
    try:
        log("Searching for certificates associated with %s via https://crt.sh. This may take a while..." % domain)
        url = f"https://crt.sh/?q={domain}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:141.0) Gecko/20100101 Firefox/141.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.8',
            'Accept-Encoding': 'gzip',
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        unique_domains = set()

        # Find all tables on the page
        tables = soup.find_all("table")
        for table in tables:
            headers = [th.get_text(strip=True) for th in table.find_all("th")]
            if "Common Name" not in headers:
                continue  # skip tables without the "Common Name" column

            cn_index = headers.index("Common Name")  # find column index dynamically

            # Iterate rows after the header
            for row in table.find_all("tr")[1:]:
                cells = row.find_all("td")
                if len(cells) <= cn_index:
                    continue

                # Use separator="\n" to split <br> into separate lines
                cn_text = cells[cn_index].get_text(separator="\n").strip()

                # Split by newlines, then strip each domain
                for domain_entry in cn_text.split("\n"):
                    domain_entry = domain_entry.strip()
                    if domain_entry:
                        unique_domains.add(domain_entry)

        return sorted(unique_domains)
    except Exception as e:
        log("Error getting subdomains from https://crt.sh. \nException is: %s" % e)


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
    crt_sh_results = get_crt_sh(domain)
    crt_count = len(crt_sh_results)
    log("(+) Found %d new subdomains via crt.sh" % crt_count)
    for sd in crt_sh_results:
        subdomains.add(sd)
    SL_results = sublister(domain)
    for sd in SL_results:
        # Deal with sublist3r multiple entries separated by <BR>:
        if "<BR>" in sd:
            for x in sd.split("<BR>"): subdomains.add(x)
        else: subdomains.add(sd)
    sl_count = len(subdomains) - crt_count
    log("(+) Found %d new/unique subdomains via sublist3r" % sl_count)
    for subdomain in subdomains:
        subdomain = subdomain.lower()
        if not alreadyProcessed(subdomain) and subdomain != domain:
            log("(+) SUBDOMAIN ENUM DISCOVERY: ADDING TO QUEUE: %s" %subdomain)
            Dq.add(subdomain)
    return subdomains

def isNewFLD(fld):
    db.execute("SELECT fld FROM flds WHERE fld=?",(fld,))
    result = db.fetchone()
    if result:
        return False
    else: 
        return True

def fldinscope(fld):
    db.execute("SELECT fld_inscope FROM flds WHERE fld=?",(fld,))
    result = db.fetchone()
    if result:
        return result[0] == "true"
    else:
        return False
        
def processDomain(domain, ports):
    log("")
    log("Processing domain: %s" %domain)
    try:
        fld = get_fld(domain, fix_protocol=True)
        fld_inscope = fldinscope(fld)
    except:
        log("(+) Getting FLD for %s Failed! This may suggest an internal domain name!" % domain)
        db.execute("INSERT OR REPLACE INTO dead_domains VALUES(?,?)", (domain,"unknown"))
        return 0
    ignore = False
    certdata = []
    for ignorefld in flds_ignore:
        if ignorefld in fld:
            log("(-) FLD is in list of FLDs to ignore. Ignoring %s" % fld)
            ignore = True
    if not ignore:
        if isNewFLD(fld):
            log("(+) New FLD Discovered! %s" % fld)
            db.execute("INSERT OR REPLACE INTO flds VALUES(?,?,?)", (fld,"pending",""))
        elif fld_inscope:
            resolves = fDNS(domain,True,fld)
            if resolves: 
                for port in ports:
                    cert = TLSenum(domain,port)
                    certdata.append(cert)
        else:
            log("FLD not in scope. Will return to %s if FLD is added to scope" % domain)
    certdata = str(certdata)
    db.execute("INSERT OR REPLACE INTO processed VALUES(?,?,?,?,?)",(domain,"domain",fld_inscope,fld,certdata))
    log("Finished processing domain: %s" %domain)

def processIP(ip,ports):
    log("")
    log("Processing IP: %s" %ip)
    rDNS(ip)
    db.execute("SELECT ip_inscope FROM data WHERE ip=?",(ip,))
    result = db.fetchone()
    certdata = []
    if result:
        for port in ports:
            cert = TLSenum(ip,port)
            certdata.append(cert)
    log("Finished Processing IP: %s" %ip)
    certdata = str(certdata)
    db.execute("INSERT OR REPLACE INTO processed VALUES(?,?,?,?,?)",(ip,"IP_ADDRESS","NA","NA",certdata))

def populateWhois(flds):
    log("(+) Grabbing whois data for new FLDs (printed below). Be patient, this can take a while for large environments!\n")
    log(flds)
    # Grabs and populates whoisdata for the provided list
    for fld in flds:
        db.execute("SELECT whoisdata from flds WHERE fld = ?", (fld,))
        result = db.fetchone()
        if result[0] == '':
            log("Grabbing whoisdata for %s" % fld)
            whoisdata = json.dumps(getwhois(fld))
            db.execute("UPDATE flds SET whoisdata = ? WHERE fld = ?", (whoisdata,fld))
            con.commit()
            log("(+) Success!")


def processNewFlds(flds_new):
    conn = sqlite3.connect("DNSscope.db", check_same_thread=False)
    c = conn.cursor()
    log("(+) /process-new-flds called. Adding the following FLDs to scope and processing further")
    log(flds_new)
    log("\n\n(+++) Resuming processing IP and Domain queues\n")
    try:
        for fld in flds_new:
            log("(+) Reprocessing FLD %s" % fld)
            c.execute("SELECT * FROM flds WHERE fld = ?", (fld,))
            result = c.fetchone()
            if not result:
                log("(-) %s FLD not found in FLDs. Skipping" % fld)
                continue
            elif result[1] == "true":
                log("(-) %s FLD is already marked as in-scope. Skipping" % fld)
                continue
            # mark fld as in-scope
            c.execute("UPDATE flds SET fld_inscope = ? WHERE fld = ?", ('true',fld))
            # grab all domains for reprocessing that match the fld marked as newly in-scope
            c.execute("SELECT domainorip FROM processed WHERE fld = ?", (fld,)) 
            revisit_queue = c.fetchall()
            for domain in revisit_queue:
                domain = domain[0]
                log("(+) Adding Domain %s back to queue to be processed - FLD was marked in-scope" % domain)
                Dq.add(domain)
                c.execute("DELETE FROM processed WHERE domainorip = ?", (domain,))
            SDenum(fld)
        conn.commit()
        conn.close()
        ports = {443}
        process(ports)
    except Exception as r:
        log("(-) Error processing additional FLDs\n%s" % r)

# Main loop - go through remaining IPs and domains and run flow for each
# add additional discovered IPs and domains to queue
# Pops and processes one IP and one domain per iteration in this while loop
def process(ports):
   i = 0
   while (Dq or IPq):
        while (Dq):
            if i % 50 == 0:
                con.commit()
            i=i+1
            domain = Dq.pop()
            if not alreadyProcessed(domain):
                processDomain(domain,ports)
        while (IPq):
            if i % 50 == 0:
                con.commit()
            i=i+1
            ip = IPq.pop()
            if not alreadyProcessed(ip):
                processIP(ip,ports)
        if not Dq and not IPq:
            log("(+++) Finished processing IP and Domain queues\n\n\n") 
            log("---------------------------------------------------------------------------\n")
            db.execute("SELECT fld FROM flds WHERE fld_inscope=?", ("pending",))
            flds_new = [t[0] for t in db.fetchall()]
            if flds_new:
                log("%d New FLDs discovered for additional processing!\n\n" % len(flds_new)) 
                populateWhois(flds_new)
        con.commit()
  

if __name__ == '__main__':
    clargs = " ".join(sys.argv)
    log("Starting %s" % clargs)
    
    if 'PASTE YOUR VIRUSTOTAL KEY HERE' in sl.vt_apikey:
        log("\n(-) VirusTotal API Key Not Found!\nYou should add your VirusTotal API key to the top of sublister.py for more robust subdomain enumeration\n\n")
    
    if args.server:
        server.app.run(host="127.0.0.1", port=5432, debug=False)
        exit(0)
    
    ports = set()
    if not args.notls:
       if args.ports: 
           for x in args.ports: ports.add(int(x))
    
    if args.subdomains:
        f=open(args.subdomains, "r")
        for sd in f:
            subdomain = sd.strip().lower()
            Dq.add(subdomain)

    if args.reprocess:
        log("You have selected reprocess. This will irreversibly delete all data within the \"processed\" table")
        answer = input("Do you want to continue? (y/n): ").strip().lower()
        if answer == "y":
            log("(+) Deleting all rows from the \"processed\" table")
            db.execute("DELETE FROM processed")
            con.commit()
        else:
            print("Aborted. Exiting")
            exit(-1)

    try:
        log("Processing IPs from %s" % args.infile) 
        readips()
        for ip in IPq:
            db.execute("INSERT OR IGNORE INTO data VALUES(?,?,?)", (ip,"",True))
    except Exception as e:
        print("(-) Error processing IP file.\n\tError: %s\n" % e)
        parser.print_help()
        
        exit(-1)
    

    # Ingest FLDs and run subdomain enumeration on all of them
    initdomains = set()
    if args.domain:
        domain = args.domain.lower()
        initdomains.add(domain)
    if args.domains:
        f=open(args.domains, "r")
        for domain in f: 
            domain = domain.strip().lower()
            initdomains.add(domain)
    for domain in initdomains:
        Dq.add(domain)
        db.execute("INSERT OR REPLACE INTO flds VALUES(?,?,?)", (domain,"true",""))
        subdomains = SDenum(domain)
    populateWhois(initdomains)
    
    con.commit()
    process(ports)
    con.commit()            
    con.close()
