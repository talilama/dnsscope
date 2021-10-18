# dnsscope
Takes a list of IPs and TLDs in scope and automates DNS enumeration. This includes reverse DNS, subdomain enumeration, TLS certificate CN and SAN enumeration, and finally forward DNS to sort results into the following categories:

* In Scope - Domain resolves to an IP provided as In Scope
* Tentatively In Scope - Domain resolves to an IP not in provided infile but the TLD was determined to be in scope
* Out of Scope - domain resolves but neither the IP or TLD were determined to be in scope
* Dead Domains - Identified domain does not resolve

## Credits
All credit for sublist3r goes to Ahmed Aboul-Ela (@aboul3la).

https://github.com/aboul3la/Sublist3r

Minor modifications were made to sublist3r to work for this application - 
