#!/usr/bin/env python3

'''
    Author: Micah Hoffman (@WebBreacher)
    Purpose: To look up an email wildcard and find all domains reg'd with it
    TODO -
        1 - Parse the number of responses from the site. If > 500 get other pages
'''

import argparse
from datetime import date
import json
import pprint
import re
import sys
import time
import urllib.request as urllib2
import pythonwhois

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
parser.add_argument('-w', '--whois', action='store_true', help='[OPTIONAL] For each domain retrieved from ViewDNS.info, do a whois [domain]. Default is not to do this.')
args = parser.parse_args()

def DomainVerification(passed_domain):
    if re.match('((?=[a-z0-9-]{1,63}\.)[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}', passed_domain):
        return True
    else:
        return False

def GetDataFromViewDNS(passed_domain):
    try:
        url = f'http://pro.viewdns.info/reversewhois/?q={passed_domain}&apikey={args.api}&output=json'
        req = urllib2.Request(url)
        with urllib2.urlopen(req, timeout=20) as response:
            resp_data = json.load(response)
        print('[+] Response from ViewDNS.info received')

        print(f'[+] {resp_data["response"]["result_count"]} Domains found.')
        if resp_data['response']['total_pages'] > 1:
            return resp_data['response']
        else:
            return resp_data['response']

    except Exception as e:
        print(f'[!]   ERROR - ViewDNS issue: {e}')
        exit(1)

def IndividualWhoisLookups(domains):
    print('[ ] Starting individual domain lookups in 10 seconds')
    print('[*]    If the output "hangs" on a lookup, press CTRL-C to go to next entry')
    time.sleep(10)

    for line in domains:
        try:
            w = pythonwhois.get_whois(line['domain'], normalized=True)

            print('------------------------------------------------------------')
            print(f'"{line["domain"]}","{line["created_date"]}","{line["registrar"]}"\n')

            if re.match('NOT FOUND', w['raw'][0]):
                print(f'[!]   ERROR: No valid Whois data for {line["domain"]}')
                outfile.write(f'[!]   ERROR: No valid Whois data for {line["domain"]}')
                continue

            elif not re.findall(args.domain, w['raw'][0], flags=re.IGNORECASE) and not re.findall(args.domain, w['raw'][1], flags=re.IGNORECASE):
                print(f'[!]   ERROR: {args.domain} not found in {line["domain"]}')
                outfile.write(f'[!]   ERROR: {args.domain} not found in {line["domain"]}')
                continue

            elif re.search('No match for ', w['raw'][0], flags=re.IGNORECASE):
                print(f'[!]   ERROR: {args.domain} no match in Whois')
                outfile.write(f'[!]   ERROR: {args.domain} no match in Whois')
                continue

            else:
                del w['raw']
                pp.pprint(w)

                if args.outfile:
                    outfile.write('------------------------------------------------------------\n')
                    outfile.write(f'Domain: {line["domain"]}, Registered on: {line["created_date"]}, Registrar: {line["registrar"]}\n')
                    pp.pprint(w, stream=outfile, indent=4)

        except KeyboardInterrupt:
            continue

        except Exception as e:
            print(f'[!]   ERROR: Exception caught: {e}')

def OutputScrapedDomsFromViewDNS(domain, responses):
    print(f"[+] Domain Searched: {domain}")
    if args.outfile:
        outfile.write(f"[+] Domain Searched: {domain}\n")
        outfile.write(f"[+] {responses['result_count']} Domains found.\n")
        outfile.write('"Domain","Date Creation","Registrar"\n')
    for line in responses['matches']:
        print(f'"{line["domain"]}","{line["created_date"]}","{line["registrar"]}"')
        if args.outfile:
            outfile.write(f'"{line["domain"]}","{line["created_date"]}","{line["registrar"]}"\n')

def RunIt(domain):
    print(f'\n[+] Trying {domain}')

    if DomainVerification(domain):
        print(f'[ ] Validated that {domain} looks like a domain. Well done.')
        resp_data = GetDataFromViewDNS(domain)

        if args.whois:
            print('[ ] Doing the additional WHOIS look ups on the found domains per the -w switch')
            IndividualWhoisLookups(resp_data)
        else:
            OutputScrapedDomsFromViewDNS(domain, resp_data)
    else:
        print(f'[!]   ERROR: The value you passed ({domain}) did not validate as a domain.')
        exit(1)

####
# Main Script
####
if args.outfile:
    try:
        outfile = open(args.outfile, 'a', buffering=1) # Use line buffering (buffering=1)
    except Exception as e:
        print(f'[!]   ERROR: Problem with the outfile: {e}')
        exit(1)

if args.domain:
    if args.infile:
        print('[!]   ERROR: Please only pass -d OR -i...not both.')
        exit(1)

    RunIt(args.domain)

elif args.infile:
    try:
        with open(args.infile, 'r') as infile:
            for domain in infile:
                domain = domain.strip()
                RunIt(domain)
    except Exception as e:
        print(f'[!]   ERROR: Problem with the infile: {e}')
        exit(1)

else:
    print('[!]   ERROR: You need to either use -d or -i to pass in domains.')
    exit(1)

if args.outfile:
    outfile.close()
