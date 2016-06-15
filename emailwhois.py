#!/usr/bin/python
'''
    Author: Micah Hoffman (@WebBreacher)
    Purpose: To look up an email wildcard and find all domains reg'd with it

    TODO -
        - Rotate UserAgents
'''

# Tell python we want to use a library
import argparse
from datetime import date
import pprint
import pythonwhois # http://cryto.net/pythonwhois/index.html
import re
import sys
import urllib2

####
# Variables
####
# Pretend to be a normal web browser instead of "Python"
# Large list of User Agents are http://techpatterns.com/downloads/firefox/useragentswitcher.xml
user_agent = 'Mozilla/5.0 (compatible; Googlebot/2.1;  http://www.google.com/bot.html)'
csv_output = {}
pp = pprint.PrettyPrinter(indent=4)

# Parse command line input
parser = argparse.ArgumentParser(description="To look up an email wildcard and find all domains reg'd with it")
parser.add_argument('-d', '--domain', required=True, help='Single domain to search for (Ex: dhs.gov) or use the -i [file]')
parser.add_argument('-i', '--infile', help='[OPTIONAL] Input file for all content. Just a list of domains (Ex. dhs.gov)')
parser.add_argument('-o', '--outfile', default='domains_with_email.txt', help='[OPTIONAL] Output file for all content')
parser.add_argument('-w', '--whois', help='[OPTIONAL] For each domain retrieved from ViewDNS.info, do a whois [domain]')
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
    # Create and make the call
    try:
        url = 'http://viewdns.info/reversewhois/?q=%40' + args.domain
        req = urllib2.Request(url)
        req.add_header('User-Agent', user_agent)
        response = urllib2.urlopen(req, timeout=5)
        resp_data = response.read()
        return resp_data
    except:
        print '[!] ERROR - Cannot reach or parse data from the viewdns.info site.'
        exit(1)

def MatchAndExtractFromViewDNS(resp_data):
    ####
    # Matching and Extracting Content
    ####
    # Format of the viewdns.info data as of 2016-06-10
    '''<tr><td>aberdeenweb.net</td><td>2008-07-17</td><td>FASTDOMAIN, INC.</td></tr>'''
    data = re.findall(r"<td>[a-z0-9].+?\..+?</td><td>[0-9\-]+?</td><td>[A-Z0-9].+?</td>", resp_data)
    return data

def IndividualWhoisLookups(domains):
    for line in data:
    line = re.sub('</td>', '', line)
    domains = line.split('<td>')

    # Make a whois lookup of the domain and pull out the email@dhs.gov
    try:
        w = pythonwhois.get_whois(domains[1], normalized=True)

        print "------------------------------------------------------------\n"
        print " DOM: %s --- CREATED: %s --- REGISTRAR: %s\n" % (domains[1],domains[2],domains[3])

        # Look for false positives in web output by doing search of whois results
        if re.match('NOT FOUND', w['raw'][0]):
            # Some 'found' content fails specific whois. This is a false positive.
            print '[!]   ERROR: No valid Whois data for %s' % domains[1]
            #outfile.write('[!]   ERROR: No valid Whois data for %s' % domains[1])
            continue

        elif not re.findall(args.domain, w['raw'][0], flags=re.IGNORECASE) and not re.findall(args.domain, w['raw'][1], flags=re.IGNORECASE):
            # Is the search domain actually in any of the output?
            print '[!]   ERROR: %s not found in %s' % (args.domain, domains[1])
            #outfile.write('[!]   ERROR: %s not found in %s' % (args.domain, domains[1]))
            continue

        elif re.search('No match for ', w['raw'][0], flags=re.IGNORECASE):
            # The Whois failed
            print '[!]   ERROR: %s no match in Whois' % args.domain
            continue

        else:
            # Print all the things except the "raw" element
            del w['raw']
            pp.pprint(w)

            # Output to outfile
            outfile.write("------------------------------------------------------------\n")
            outfile.write("DOM: %s --- CREATED: %s --- REGISTRAR: %s\n" % (domains[1],domains[2],domains[3]))
            pprint.pprint(w, stream=outfile, indent=4)

    except KeyboardInterrupt:
        # Sense and continue if user presses ctrl-c (used for times the script gets...er...stuck)
        continue

    except Exception:
        pass

'''
if -d is passed
    verify that it is a domain
    do the viewdns lookup 
    do the match and extract
    if -w is passed
        do additional lookups
'''


# Open file for writing output
try:
    outfile = open(args.outfile, 'a', 0)
except Exception:
    print '[!]   ERROR: Problem with the outfile.'
    exit(1)

if args.domain:
    if args.infile:
        print '[!]   ERROR: Please only pass -d OR -i'
        exit(1)
        
    if DomainVerification(args.domain):
        resp_data = GetDataFromViewDNS(args.domain)
        domains = MatchAndExtractFromViewDNS(resp_data)

    else:
        print '[!]   ERROR: The value you passed (%s) did not validate as a domain.' % args.domain
        exit(1)

outfile.close()