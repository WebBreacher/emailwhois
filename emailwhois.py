#!/usr/bin/python
'''
    Author: Micah Hoffman (@WebBreacher)
    Purpose: To look up an email wildcard and find all domains reg'd with it

    TODO -
        1 - Parse the number of responses from the site. If > 500 get other pages
'''

# Tell python we want to use a library
import argparse
from datetime import date
import pprint
import pythonwhois # http://cryto.net/pythonwhois/index.html
import random
import re
import sys
import time
import urllib2

####
# Variables
####
pp = pprint.PrettyPrinter(indent=4)

# Parse command line input
parser = argparse.ArgumentParser(description="To look up an email wildcard and find all domains reg'd with it")
parser.add_argument('-a', '--api', required=True, help='REQUIRED API to ViewDNS.info')
parser.add_argument('-d', '--domain', help='Single domain to search for (Ex: dhs.gov) or use the -i [file]')
parser.add_argument('-i', '--infile', help='[OPTIONAL] Input file for all content. Just a list of domains (Ex. dhs.gov)')
parser.add_argument('-o', '--outfile', help='[OPTIONAL] Output file for all content')
parser.add_argument('-w', '--whois', action="store_true", help='[OPTIONAL] For each domain retrieved from ViewDNS.info, do a whois [domain]. Default is not to do this.')
args = parser.parse_args()

def DomainVerification(passed_domain):
    # Use some kind of regex to verify a domain
    # Regex copied from https://www.safaribooksonline.com/library/view/regular-expressions-cookbook/9781449327453/ch08s15.html
    if re.match('((?=[a-z0-9-]{1,63}\.)[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}', passed_domain):
        return True
    else:
        return False


def GetDataFromViewDNS(passed_domain):
    ####
    # Setting up and Making the Web Call
    ####
    try:
        url = 'http://pro.viewdns.info/reversewhois/?q=%s&apikey=%s&output=json' % (passed_domain, args.api)
        req = urllib2.Request(url)
        response = urllib2.urlopen(req, timeout=15)
        resp_data = response.read()
        print '[+] Response from ViewDNS.info received'

        # Matching and Extracting Content
        number = re.findall('There are [0-9,]+ domains', resp_data)
        print '[*] ' + number[0] + '.'
        if re.findall('The first 500 of these', resp_data):
            print '[*]   WARNING: Only the first 500 results will be retrieved/processed.'
            if args.outfile:
                outfile.write('[*]   WARNING: Only the first 500 results will be retrieved/processed.')

        # Format of the viewdns.info data as of 2016-06-10
        '''<tr><td>aberdeenweb.net</td><td>2008-07-17</td><td>FASTDOMAIN, INC.</td></tr>'''
        print '[ ] Parsing the response'
        data = re.findall(r"<td>[a-z0-9].+?\..+?</td><td>[0-9\-]+?</td><td>[A-Z0-9].+?</td>", resp_data)
        return data

    except Exception:
        print '[!]   ERROR - Cannot reach or parse data from the viewdns.info site.'
        exit(1)

def IndividualWhoisLookups(domains):
    print '[ ] Starting individual domain lookups in 10 seconds'
    print '[*]    If the output "hangs" on a lookup, press CTRL-C to go to next entry'
    time.sleep(10)
    for line in domains:
        line = re.sub('</td>', '', line)
        domains = line.split('<td>')

        # Make a whois lookup of the domain and pull out the email@dhs.gov
        try:
            w = pythonwhois.get_whois(domains[1], normalized=True)

            print '------------------------------------------------------------'
            print '"%s","%s","%s"\n' % (domains[1],domains[2],domains[3])

            # Look for false positives in web output by doing search of whois results
            if re.match('NOT FOUND', w['raw'][0]):
                # Some 'found' content fails specific whois. This is a false positive.
                print '[!]   ERROR: No valid Whois data for %s' % domains[1]
                outfile.write('[!]   ERROR: No valid Whois data for %s' % domains[1])
                continue

            elif not re.findall(args.domain, w['raw'][0], flags=re.IGNORECASE) and not re.findall(args.domain, w['raw'][1], flags=re.IGNORECASE):
                # Is the search domain actually in any of the output?
                print '[!]   ERROR: %s not found in %s' % (args.domain, domains[1])
                outfile.write('[!]   ERROR: %s not found in %s' % (args.domain, domains[1]))
                continue

            elif re.search('No match for ', w['raw'][0], flags=re.IGNORECASE):
                # The Whois failed
                print '[!]   ERROR: %s no match in Whois' % args.domain
                outfile.write('[!]   ERROR: %s no match in Whois' % args.domain)
                continue

            else:
                # Print all the things except the "raw" element
                del w['raw']
                pp.pprint(w)

                # Output to outfile
                if args.outfile:
                    outfile.write('------------------------------------------------------------\n')
                    outfile.write('Domain: %s, Registered on: %s, Registrar: %s\n' % (domains[1], domains[2], domains[3]))
                    pprint.pprint(w, stream=outfile, indent=4)

        except KeyboardInterrupt:
            # Sense and continue if user presses ctrl-c (used for times the script gets...er...stuck)
            continue

        except Exception:
            pass

def OutputScrapedDomsFromViewDNS(domain, responses):
    print "[+] Domain Searched (first 500 responses): %s" % domain
    if args.outfile:
        outfile.write("[+] Domain Searched (first 500 responses): %s\n" % domain)
        outfile.write('"Domain","Date Creation","Registrar"\n')
    for domain in responses:
        domain = re.sub('</td>', '', domain)
        domains = domain.split('<td>')
        print '"%s","%s","%s"' % (domains[1], domains[2], domains[3])
        if args.outfile:
            outfile.write('"%s","%s","%s"\n' % (domains[1], domains[2], domains[3]))

####
# Main Script
####

# Open file for writing output
if args.outfile:
    try:
        outfile = open(args.outfile, 'a', 0)
    except Exception:
        print '[!]   ERROR: Problem with the outfile.'
        exit(1)

# Main part of the script
if args.domain:
    if args.infile:
        # If they passed both -d and -i, exit.
        print '[!]   ERROR: Please only pass -d OR -i...not both.'
        exit(1)

    # OK, we have a single domain. Let's make sure it IS a domain
    print '[+] Trying %s' % args.domain

    if DomainVerification(args.domain):
        print '[ ] Validated that %s looks like a domain. Well done.' % args.domain
        resp_data = GetDataFromViewDNS(args.domain)

        if args.whois:
            # Do the whois lookup and then output
            print '[ ] Doing the additional WHOIS look ups on the found domains per the -w switch'
            IndividualWhoisLookups(resp_data)
        else:
            # Just output the scraped domains
            OutputScrapedDomsFromViewDNS(args.domain, resp_data)
    else:
        print '[!]   ERROR: The value you passed (%s) did not validate as a domain.' % args.domain
        exit(1)

elif args.infile:
    # Open file for reading input
    try:
        infile = open(args.infile, 'r')
        infile_lines = infile.readlines()
    except Exception:
        print '[!]   ERROR: Problem with the infile.'
        exit(1)

    for line in infile_lines:
        line = line.strip()
        print '[ ] Trying %s' % line

        if DomainVerification(line):
            print '[ ] Validated that %s looks like a domain. Well done.' % line
            resp_data = GetDataFromViewDNS(line)

            if args.whois:
                # Do the whois lookup and then output
                print '[ ] Doing the additional WHOIS look ups on the found domains per the -w switch'
                IndividualWhoisLookups(resp_data)
            else:
                # Just output the scraped domains
                OutputScrapedDomsFromViewDNS(line, resp_data)

        else:
            print '[!]   ERROR: The value you passed (%s) did not validate as a domain.' % args.domain
            continue

    infile.close()

else:
    print '[!]   ERROR: You need to either use -d or -i to pass in domains.'
    exit(1)

if args.outfile:
    outfile.close()