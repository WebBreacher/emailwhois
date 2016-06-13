#!/usr/bin/python
'''
    Author: Micah Hoffman (@WebBreacher)
    Purpose: To look up an email wildcard and find all domains reg'd with it
    
    TODO -
        - Recursively look up domains found and print info
        - Output to CSV/Excel
        - Rotate UserAgents 
'''

# Tell python we want to use a library
import argparse
import csv
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
parser.add_argument('-d', '--domain', required=True, help='Single domain to search for (Ex: dhs.gov)')
args = parser.parse_args()


####
# Setting up and Making the Web Call
####
# Create and make the call
url = 'http://viewdns.info/reversewhois/?q=%40' + args.domain
req = urllib2.Request(url)
req.add_header('User-Agent', user_agent)
response = urllib2.urlopen(req, timeout=15)
resp_data = response.read()


####
# Matching and Extracting Content
####
# Format of the viewdns.info data as of 2016-06-10
'''<tr><td>aberdeenweb.net</td><td>2008-07-17</td><td>FASTDOMAIN, INC.</td></tr>'''

data = re.findall(r"<td>[a-z0-9].+?\..+?</td><td>[0-9\-]+?</td><td>[A-Z0-9].+?</td>", resp_data)
for line in data:
    line = re.sub('</td>', '', line)
    domains = line.split('<td>')

    # Make a whois lookup of the domain and pull out the email@dhs.gov
    try:
        w = pythonwhois.get_whois(domains[1], normalized=True)

        print '------------------------------------------------------------'
        print '%s, %s, %s' % (domains[1],domains[2],domains[3])
        for response in w['raw']:
            if re.match('NOT FOUND', response):
                print '[!] ERRROR with %s' % domains[1]
                continue
            else:
                print '\n'.join(['   %s: %s' % (key, value) for (key, value) in w['contacts']['admin'].items()]) 
                print '     ------'
                #print w['contacts']
                
                #pp.pprint(w)
                #csv_output[domains[1]] = w
                #print csv_output[domains[1]]
    except KeyboardInterrupt:
        exit(0)
    except:
        pass

'''# File Write for Output
with open('domains_with_bah_email.csv', 'w') as csvfile:
    fieldnames = ['Domain', 'last_name']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    for row in csv_output:
    	writer.writerow(row)'''
