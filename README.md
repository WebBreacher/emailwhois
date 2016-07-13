# emailwhois
Look up an email domain (@example.com), using Python, across all known domains using the API at web site http://viewdns.info/reversewhois/?q=%40example.com.

*This script does require an API to ViewDNS.info. They will ban your IP if you scrape their web pages.*

# Sample Help
```
$  python emailwhois.py -h
usage: emailwhois.py [-h] -a API [-d DOMAIN] [-i INFILE] [-o OUTFILE] [-w]

To look up an email wildcard and find all domains reg'd with it

optional arguments:
  -h, --help            show this help message and exit
  -a API, --api API     REQUIRED API to ViewDNS.info
  -d DOMAIN, --domain DOMAIN
                        Single domain to search for (Ex: dhs.gov) or use the
                        -i [file]
  -i INFILE, --infile INFILE
                        [OPTIONAL] Input file for all content. Just a list of
                        domains (Ex. dhs.gov)
  -o OUTFILE, --outfile OUTFILE
                        [OPTIONAL] Output file for all content
  -w, --whois           [OPTIONAL] For each domain retrieved from
                        ViewDNS.info, do a whois [domain]. Default is not to
                        do this.

```

# Issues
1. Only the first 500 domains are retrieved. This is a limit of the viewdns.info site, not my script.
2. I think viewdns.info may be blocking/shunning IPs after a certain number of repeated lookups. Beware.
3. The OUTFILE format without the -w (extra whois) option is CSV-compliant and easy to copy/import into other tools (Excel, Maltego...).
4. The -w (whois) option may hang for long periods when looking up certain domains. Press CTRL-C to skip that "problem domain" and move to the next.
5. If you need to stop the script (especially during the long -w function), press CTRL-Z to send to the background. Then look at the ```[1]+ Stopped``` output and type ```kill %1```. I've used a "1" here but in your system, it may be a 2 or 3 or something else. Look for the number inside the "[ ]" and ```kill %``` that.
