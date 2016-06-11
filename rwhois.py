#!/usr/bin/python
'''
    Author: Micah Hoffman (@WebBreacher)
    Purpose: To look up an email wildcard and find all domains reg'd with it
'''

# Tell python we want to use a library
import csv # https://docs.python.org/2/library/csv.html
from datetime import date
import pprint
import re
import urllib2
import pythonwhois # http://cryto.net/pythonwhois/index.html

####
# Variables
####
# Pretend to be a normal web browser instead of "Python"
# Large list of User Agents are http://techpatterns.com/downloads/firefox/useragentswitcher.xml
user_agent = 'Mozilla/5.0 (compatible; Googlebot/2.1;  http://www.google.com/bot.html)'
targetDomain = 'dhs.gov'
csv_output = {}
pp = pprint.PrettyPrinter(indent=4)

####
# Setting up and Making the Web Call
####
# Create and make the call
url = 'http://viewdns.info/reversewhois/?q=%40' + targetDomain
req = urllib2.Request(url)
req.add_header('User-Agent', user_agent)
response = urllib2.urlopen(req, timeout=20)
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

    # Make a whois lookup of the domain and pull out the email@bah.com
    w = pythonwhois.get_whois(domains[1], normalized=True)
    
    print '------------------------------------------------------------'
    print "%s, %s, %s" % (domains[1],domains[2],domains[3])
    print ',\n'.join(['   %s: %s' % (key, value) for (key, value) in w['contacts']['admin'].items()]) 

    #print w['contacts']
    
    #pp.pprint(w)
    #csv_output[domains[1]] = w
    #print csv_output[domains[1]]

'''# File Write for Output
with open('domains_with_bah_email.csv', 'w') as csvfile:
    fieldnames = ['Domain', 'last_name']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    for row in csv_output:
    	writer.writerow(row)'''
