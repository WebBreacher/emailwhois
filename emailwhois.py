#!/usr/bin/python
'''
    Author: Micah Hoffman (@WebBreacher)
    Purpose: To look up an email wildcard and find all domains reg'd with it

    TODO -

'''

# Tell python we want to use a library
import argparse
from datetime import date
import pprint
import pythonwhois # http://cryto.net/pythonwhois/index.html
import random
import re
import sys
import urllib2

####
# Variables
####
# Pretend to be a normal web browser instead of "Python"
# Large list of User Agents are http://techpatterns.com/downloads/firefox/useragentswitcher.xml
user_agents = [ 'Mozilla/5.0 (compatible; Googlebot/2.1;  http://www.google.com/bot.html)',
                'BlackBerry9700/5.0.0.351 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/123',
                'Googlebot/2.1 ( http://www.googlebot.com/bot.html)',
                'HTC_Dream Mozilla/5.0 (Linux; U; Android 1.5; en-ca; Build/CUPCAKE) AppleWebKit/528.5  (KHTML, like Gecko) Version/3.1.2 Mobile Safari/525.20.1',
                'Java/1.6.0_13',
                'LG-GC900/V10a Obigo/WAP2.0 Profile/MIDP-2.1 Configuration/CLDC-1.1',
                'LG-LX550 AU-MIC-LX550/2.0 MMP/2.0 Profile/MIDP-2.0 Configuration/CLDC-1.1',
                'Mozilla/5.0 (Linux U; en-US)  AppleWebKit/528.5  (KHTML, like Gecko, Safari/528.5 ) Version/4.0 Kindle/3.0 (screen 600x800; rotate)',
                'Mozilla/5.0 (Linux; Android 4.4.2; LG-V410 Build/KOT49I.V41010d) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.103 Safari/537.36',
                'Mozilla/5.0 (Linux; Android 5.0.1; SCH-R970 Build/LRX22C) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.84 Mobile Safari/537.36',
                'Mozilla/5.0 (Linux; Android 5.0.2; SAMSUNG SM-T530NU Build/LRX22G) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/3.2 Chrome/38.0.2125.102 Safari/537.36',
                'Mozilla/5.0 (Linux; Android 5.1.1; Nexus 7 Build/LMY47V) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.78 Safari/537.36 OPR/30.0.1856.93524',
                'Mozilla/5.0 (Linux; Android 5.1; C6740N Build/LMY47O) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.111 Mobile Safari/537.36',
                'Mozilla/5.0 (Linux; U; Android 4.4.2; en-us; GT-P5210 Build/KOT49H) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Safari/534.30',
                'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_2; en-us) AppleWebKit/531.21.8 (KHTML, like Gecko) Version/4.0.4 Safari/531.21.10',
                'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240',
                'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.93 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; MATBJS; rv:11.0) like Gecko',
                'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.71 Safari/537.36 Edge/12.0',
                'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.76 Safari/537.36 OPR/19.0.1326.56',
                'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.89 Vivaldi/1.0.94.2 Safari/537.36',
                'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Maxthon/4.4.6.1000 Chrome/30.0.1599.101 Safari/537.36',
                'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.76 Safari/537.36 OPR/28.0.1750.40',
                'Mozilla/5.0 (Windows NT 6.2; WOW64; rv:39.0) Gecko/20100101 Firefox/39.0',
                'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1667.0 Safari/537.36',
                'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko',
                'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.57 Safari/537.36 OPR/18.0.1284.49',
                'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36',
                'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0',
                'Mozilla/5.0 (X11; U; Linux x86_64; en-US) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.114 Safari/537.36 Puffin/4.5.0IT',
                'Mozilla/5.0 (X11; U; Linux x86_64; en-US) AppleWebKit/540.0 (KHTML, like Gecko) Ubuntu/10.10 Chrome/9.1.0.0 Safari/540.0',
                'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.0.3) Gecko/2008092814 (Debian-3.0.1-1)',
                'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
                'Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4"ri/531.22.7',
                'Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_2_1 like Mac OS X; da-dk) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8C148 Safari/6533.18.5',
                'Mozilla/5.0 (iPhone; U; CPU iPhone OS 4_3 like Mac OS X; de-de) AppleWebKit/533.17.9 (KHTML, like Gecko) Mobile/8F190',
                'Mozilla/5.0 (iPhone; U; CPU iPhone OS 5_1_1 like Mac OS X; da-dk) AppleWebKit/534.46.0 (KHTML, like Gecko) CriOS/19.0.1084.60 Mobile/9B206 Safari/7534.48.3']

csv_output = {}
pp = pprint.PrettyPrinter(indent=4)

# Parse command line input
parser = argparse.ArgumentParser(description="To look up an email wildcard and find all domains reg'd with it")
parser.add_argument('-d', '--domain', help='Single domain to search for (Ex: dhs.gov) or use the -i [file]')
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
    try:
        url = 'http://viewdns.info/reversewhois/?q=%40' + passed_domain
        req = urllib2.Request(url)
        chosen_agent = random.choice(user_agent)
        req.add_header('User-Agent', chosen_agent)
        print '[ ] Using User-Agent: %s' % chosen_agent
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

def OutputScrapedDomsFromViewDNS(domains):
    for domain in domains:
        outfile.write("------------------------------------------------------------\n")
        outfile.write("DOM: %s --- CREATED: %s --- REGISTRAR: %s\n" % (domains[1],domains[2],domains[3]))


# Open file for writing output
try:
    outfile = open(args.outfile, 'a', 0)
except Exception:
    print '[!]   ERROR: Problem with the outfile.'
    exit(1)

# Main part of the script
if args.domain:
    if args.infile:
        # If they passed both -d and -i, exit.
        print '[!]   ERROR: Please only pass -d OR -i'
        exit(1)
    
    # OK, we have a single domain. Let's make sure it IS a domain
    if DomainVerification(args.domain):
        resp_data = GetDataFromViewDNS(args.domain)
        domains = MatchAndExtractFromViewDNS(resp_data)

        if args.whois:
            # Do the whois lookup and then output
            IndividualWhoisLookups(domains)
        else:
            # Just output the scraped domains
            OutputScrapedDomsFromViewDNS(domains)
    else:
        print '[!]   ERROR: The value you passed (%s) did not validate as a domain.' % args.domain
        exit(1)

elif args.infile:
    for line in args.infile:
        print '[ ]  Trying %s' % line
        if DomainVerification(line):
            resp_data = GetDataFromViewDNS(line)
            domains = MatchAndExtractFromViewDNS(resp_data)

            if args.whois:
                # Do the whois lookup and then output
                IndividualWhoisLookups(domains)
            else:
                # Just output the scraped domains
                OutputScrapedDomsFromViewDNS(domains)

        else:
            print '[!]   ERROR: The value you passed (%s) did not validate as a domain.' % args.domain
            continue
else:
    print '[!]   ERROR: You need to either use -d or -i to pass in domains.'
    exit(1)

outfile.close()