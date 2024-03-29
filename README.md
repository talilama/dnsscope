# dnsscope
Takes a list of IPs and TLDs in scope and automates DNS enumeration. This includes reverse DNS, subdomain enumeration, TLS certificate CN and SAN enumeration, and finally forward DNS to sort results into the following categories:

* In Scope - Domain resolves to an IP provided as In Scope
* Tentatively In Scope - Domain resolves to an IP not in provided infile but the TLD was determined to be in scope
* Out of Scope - domain resolves but neither the IP or TLD were determined to be in scope
* Dead Domains - Identified domain does not resolve

## Usage
Specify an input file with the target scope using the -i/--infile flag (supports IP addresses and CIDR ranges). Additionally, pass a list or single top-level domain using -D/-d to run subdomain enumeration. By default, only DNS recon is done, but specifying the --tls flag will additionally grab the TLS certificate and check for domains in the Common Name and Subject Alternate Name fields. 

### Basic Usage Examples:
Common usage with single domain:

    python3 dnsscope.py -i scope_ips -d targetdomain.com --tls

Multiple domains in a file

    python3 dnsscope.py -i scope_ips -D domainsfile.txt --tls -o dnsrecon.txt

Run TLSenum on additional ports

    python3 dnsscope.py -i scope_ips -d targetdomain.com --tls -p 8443
	


## Credits
All credit for sublist3r goes to Ahmed Aboul-Ela (@aboul3la).

https://github.com/aboul3la/Sublist3r

Minor modifications were made to sublist3r to work for this application - 
