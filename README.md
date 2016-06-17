# emailwhois
Look up an email domain (@example.com), using Python, across all known domains using the web site http://viewdns.info/reversewhois/?q=%40dhs.gov

# Sample Help
```
$  python ./emailwhois.py -h
usage: emailwhois.py [-h] [-d DOMAIN] [-i INFILE] [-o OUTFILE] [-w]

To look up an email wildcard and find all domains reg'd with it

optional arguments:
  -h, --help            show this help message and exit
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
1. Only thge first 500 domains are retrieved. This is a limit of the viewdns.info site.
2. I think viewdns.info may be blocking/shunning IPs after a bunch of lookups. FYSA.
3. The OUTFILE format without the -w (extra whois) option is CSV compliant and easy to copy/import into other tools.
4. The -w (whois) option may hang for long periods when looking up certain domains. Press CTRL-C to skip that "problem domain" and move to the next.
5. If you need to stop the script, press CTRL-Z to send to the background. Then look at the ```[1]+ Stopped``` output and type ```kill %1```. I've used a "1" here but in your system, it may be a 2 or 3 or something else. Look for the number inside the "[ ]" and ```kill %``` that.
