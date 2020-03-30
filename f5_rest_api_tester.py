#!/usr/bin/python3
# f5_rest_api_tester.py
# Author: Chad Jenison (c.jenison at f5.com)
# Version 1.0
#
# Script that uses F5 BIG-IP iControl REST API to Add Pools and Virtual Servers after listing all virtuals

import argparse
import sys
import requests
import json
import getpass
import time
from datetime import datetime

requests.packages.urllib3.disable_warnings()

# Taken from http://code.activestate.com/recipes/577058/
def query_yes_no(question, default="no"):
    valid = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
    if default == None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)
    while 1:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid.keys():
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")

#Setup command line arguments using Python argparse
parser = argparse.ArgumentParser(description='A tool to identify expiring and soon to expire certs and related config detritus and assist user with pruning it from configuration')
parser.add_argument('--bigip', help='IP or hostname of BIG-IP Management or Self IP', required=True)
parser.add_argument('--user', help='username to use for authentication', required=True)
parser.add_argument('--loops', help='Number of loops [adding config objects]')
parser.add_argument('--items', help='Items to retrieve when using topskip mode', default=50)
parser.add_argument('--itemoutput', help='Print item names', default=False)
parser.add_argument('--singlerequest', action='store_true', help='Retrieve Config Objects using a single HTTP request')
parser.add_argument('--topskip', action='store_true', help='Retrieve Config Objects iteratively using top and skip filters')

args = parser.parse_args()
contentJsonHeader = {'Content-Type': "application/json"}
filename = ''

def convert_bigip_path(path_to_replace):
    return path_to_replace.replace("/", "~")

def get_auth_token(bigip, username, password):
    authbip = requests.session()
    authbip.verify = False
    payload = {}
    payload['username'] = username
    payload['password'] = password
    payload['loginProviderName'] = 'tmos'
    authurl = 'https://%s/mgmt/shared/authn/login' % (bigip)
    authPost = authbip.post(authurl, headers=contentJsonHeader, data=json.dumps(payload))
    if authPost.status_code == 404:
        print ('attempt to obtain authentication token failed; will fall back to basic authentication; remote LDAP auth will require configuration of local user account')
        token = None
    elif authPost.status_code == 401:
        print ('attempt to obtain authentication token failed due to invalid credentials')
        token = 'Fail'
    elif authPost.json().get('token'):
        token = authPost.json()['token']['token']
        print ('Got Auth Token: %s' % (token))
    else:
        print ('Unexpected error attempting POST to get auth token')
        quit()
    return token

user = args.user
password = getpass.getpass("Password for " + user + ":")
bip = requests.session()
token = get_auth_token(args.bigip, args.user, password)
if token and token != 'Fail':
    bip.headers.update({'X-F5-Auth-Token': token})
else:
    bip.auth = (args.user, password)
bip.verify = False
requests.packages.urllib3.disable_warnings()
url_base = ('https://%s/mgmt/tm' % (args.bigip))

if args.singlerequest:
    start = time.time()
    virtuals = bip.get('%s/ltm/virtual' % (url_base) ).json()
    print ('Virtual Count: %s' % (len(virtuals['items'])))
    for virtual in virtuals['items']:
        if args.itemoutput:
            print('Virtual Name: %s' % (virtual['name']))
    pools = bip.get('%s/ltm/pool' % (url_base) ).json()
    print ('Pool Count: %s' % (len(pools['items'])))
    for pool in pools['items']:
        if args.itemoutput:
            print('Pool Name: %s' % (pool['name']))
    end = time.time()
    runtime = end - start
    print ('Single Request Run Time: %s' % (runtime))

if args.topskip:
    end = time.time()
    virtuals = bip.get('%s/ltm/virtual?$top=%s' % (url_base, args.items) ).json()
    if virtuals.get('nextLink'):
        done = False
        while (not done ):
            itemsretrieved = len(virtuals['items'])
            #print ('Items retrieved: %s' % (itemsretrieved))
            virtualpage = bip.get('%s/ltm/virtual?$top=%s&$skip=%s' % (url_base, args.items, itemsretrieved) ).json()
            #print ('virtualpage item count: %s' % (len(virtualpage['items'])))
            for item in virtualpage['items']:
                virtuals['items'].append(item)
            #virtuals['items'].append(virtualpage['items'])
            if not virtualpage.get('nextLink'):
                done = True
                #print ('Got all items')
    print ('Virtual Count: %s' % (len(virtuals['items'])))
    for item in virtuals['items']:
        if args.itemoutput:
            print ('Virtual Name: %s' % (item['name']))
    pools = bip.get('%s/ltm/pool?$top=%s' % (url_base, args.items) ).json()
    if pools.get('nextLink'):
        done = False
        while (not done ):
            itemsretrieved = len(pools['items'])
            #print ('Items retrieved: %s' % (itemsretrieved))
            poolpage = bip.get('%s/ltm/pool?$top=%s&$skip=%s' % (url_base, args.items, itemsretrieved) ).json()
            #print ('poolpage item count: %s' % (len(poolpage['items'])))
            for item in poolpage['items']:
                pools['items'].append(item)
            #virtuals['items'].append(virtualpage['items'])
            if not poolpage.get('nextLink'):
                done = True
    print ('Pool Count: %s' % (len(pools['items'])))
    for item in pools['items']:
        if args.itemoutput:
            print ('Pool Name: %s' % (item['name']))
    end = time.time()
    runtime = end - start
    print ('Top/Skip Run Time: %s' % (runtime))
