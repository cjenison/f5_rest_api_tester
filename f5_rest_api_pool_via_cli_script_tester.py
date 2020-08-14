#!/usr/bin/python3
# f5_rest_api_pool_via_cli_script_tester.py
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
parser.add_argument('--loops', help='Number of loops', type=int, default=1)
parser.add_argument('--poolmembers', help='Number of pool members to create', type=int, default=2)
parser.add_argument('--poolipprefix', help='IP Prefix for pool members', default="192.168.100.10")
parser.add_argument('--buildconfig', help='Add pool and virtual in each loop', action='store_true')
parser.add_argument('--items', help='Items to retrieve when using topskip mode', default=50)
parser.add_argument('--itemoutput', help='Print item names', default=False)
parser.add_argument('--getlist', help='Get list of objects before creating objects', action='store_true')
parser.add_argument('--singlerequest', action='store_true', help='Retrieve Config Objects using a single HTTP request')
parser.add_argument('--poolbulk', action='store_true', help='Create Pool and include members using one HTTP request')
parser.add_argument('--topskip', action='store_true', help='Retrieve Config Objects iteratively using top and skip filters')

args = parser.parse_args()
contentJsonHeader = {'Content-Type': "application/json"}
filename = ''
poolprefix = 'pool'
virtualprefix = 'virtual'
cliScriptName = 'pool-add-remove-members'
poolerrorcount = 0
virtualerrorcount = 0
membererrorcount = 0
restgetcount = 0
restgetexecutiontime = 0
## Below two variables are set at extremes to catch best case and worst case execution
restgetbest = 1000
restgetworst = 0
restpostcount = 0
restpostexecutiontime = 0
restdeletecount = 0
scriptbegin = time.time()

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

def deletePoolPlusVirtual(index):
    global restdeletecount
    bip.delete('%s/ltm/virtual/%s%s' % (url_base, virtualprefix, index))
    bip.delete('%s/ltm/pool/%s%s' % (url_base, poolprefix, index))
    restdeletecount += 2
    print('Deleted Pool: %s%s - Deleted Virtual: %s%s' % (poolprefix, index, virtualprefix, index))

def createPoolPlusVirtual(index):
    global poolerrorcount
    global membererrorcount
    global virtualerrorcount
    global restpostcount
    global restpostexecutiontime
    port = 10000 + index
    poolDict = {}
    poolDict['name'] = '%s%s' % (poolprefix, index)
    poolDict['monitor'] = '/Common/tcp_half_open'
    if args.poolbulk:
        poolMemberList = []
        for member in range(1,args.poolmembers + 1):
            memberDict = {}
            memberDict['name'] = '%s%s:%s' % (args.poolipprefix, member, port)
            poolMemberList.append(memberDict)
        memberReferenceDict = {}
        memberReferenceDict['isSubcollection'] = True
        memberReferenceDict['items'] = poolMemberList
        poolDict['membersReference'] = memberReferenceDict
        restpoststarttime = time.time()
        poolpost = bip.post('%s/ltm/pool' % (url_base), headers=contentJsonHeader, data=json.dumps(poolDict))
        restpostexecutiontime += time.time() - restpoststarttime
        restpostcount += 1
    else:
        restpoststarttime = time.time()
        poolpost = bip.post('%s/ltm/pool' % (url_base), headers=contentJsonHeader, data=json.dumps(poolDict))
        restpostexecutiontime += time.time() - restpoststarttime
        restpostcount += 1
        if poolpost.status_code == 200:
            print ('Successfully Created Pool: %s%s' % (poolprefix, index))
        else:
            print ('Problem creating Pool: %s%s - response: %s' % (poolprefix, index, poolpost.content))
            poolerrorcount
            poolerrorcount += 1
        for member in range(1,args.poolmembers + 1):
            memberDict = {}
            memberDict['name'] = '%s%s:%s' % (args.poolipprefix, member, port)
            restpoststarttime = time.time()
            memberpost = bip.post('%s/ltm/pool/%s%s/members' % (url_base, poolprefix, index), headers=contentJsonHeader, data=json.dumps(memberDict))
            restpostexecutiontime += time.time() - restpoststarttime
            restpostcount += 1
            if memberpost.status_code == 200:
                print ('Successfully Created Pool: %s%s Member: %s%s:%s' % (poolprefix, index, args.poolipprefix, member, port))
            else:
                print ('Problem creating Pool: %s%s Member: %s%s%s- response: %s' % (poolprefix, index, args.poolipprefix, member, port, memberpost.content))
                membererrorcount += 1
    virtualDict = {}
    virtualDict['name'] = '%s%s' % (virtualprefix, index)
    virtualDict['destination'] = '10.0.0.1:%s' % (port)
    virtualDict['pool'] = '%s%s' % (poolprefix, index)
    virtualDict['profiles'] = 'f5-tcp-lan'
    restpoststarttime = time.time()
    virtualpost = bip.post('%s/ltm/virtual' % (url_base), headers=contentJsonHeader, data=json.dumps(virtualDict))
    restpostexecutiontime += time.time() - restpoststarttime
    restpostcount += 1
    if virtualpost.status_code == 200:
        print ('Successfully Created Virtual: %s%s' % (virtualprefix, index))
    else:
        print ('Problem creating Virtual: %s%s - response: %s' % (virtualprefix, index, virtualpost.content))
        virtualerrorcount += 1

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

virtualerrorcount = 0
poolerrorcount = 0
membererrorcount = 0
singlerequesttotal = 0
singlerequestdeletetime = 0
topskipdeletetime = 0

if args.singlerequest:
    singlerequestbuildstart = time.time()
    for loop in range(1,args.loops + 1):
        createpool = True
        createvirtual = True
        print ('Creating objects: %s' % (loop))
        start = time.time()
        if args.getlist:
            restgetliststart = time.time()
            virtuals = bip.get('%s/ltm/virtual' % (url_base) ).json()
            restgetlistend = time.time()
            restgetlisttime = time.time() - restgetlistend
            restgetexecutiontime += restgetlisttime
            if restgetlisttime > restgetworst:
                restgetworst = restgetlisttime
            if restgetlisttime < restgetbest:
                restgetbest = restgetlisttime
            restgetcount += 1
            print ('Virtual Count: %s' % (len(virtuals['items'])))
            for virtual in virtuals['items']:
                if virtual['name'] == '%s%s' % (virtualprefix, loop):
                    createvirtual = False
                if args.itemoutput:
                    print('Virtual Name: %s' % (virtual['name']))
            restgetliststart = time.time()
            pools = bip.get('%s/ltm/pool' % (url_base) ).json()
            restgetlisttime = time.time() - restgetliststart
            restgetexecutiontime += restgetlisttime
            if restgetlisttime > restgetworst:
                restgetworst = restgetlisttime
            if restgetlisttime < restgetbest:
                restgetbest = restgetlisttime
            restgetcount += 1
            print ('Pool Count: %s' % (len(pools['items'])))
            for pool in pools['items']:
                if pool['name'] == '%s%s' % (poolprefix, loop):
                    createpool = False
                if args.itemoutput:
                    print('Pool Name: %s' % (pool['name']))
        if createpool and createvirtual:
            createPoolPlusVirtual(loop)
        end = time.time()
        runtime = end - start
        singlerequesttotal += runtime
        print ('Single Request Run Time: %s' % (runtime))
        print ('Single Request Total Runtime: %s' % (singlerequesttotal))
    singlerequestbuildend = time.time()
    for loop in range(args.loops, 0, -1):
        print ('Deleting objects: %s' % (loop))
        deletePoolPlusVirtual(loop)
    singlerequestdeleteend = time.time()
    singlerequestdeletetime = singlerequestdeleteend - singlerequestbuildend

topskiptotal = 0
if args.topskip:
    topskipbuildstart = time.time()
    for loop in range(1,args.loops + 1):
        createpool = True
        createvirtual = True
        print ('Creating objects: %s' % (loop))
        start = time.time()
        if args.getlist:
            restgetliststart = time.time()
            virtuals = bip.get('%s/ltm/virtual?$top=%s' % (url_base, args.items) ).json()
            restgetlisttime = time.time() - restgetliststart
            if restgetlisttime > restgetworst:
                restgetworst = restgetlisttime
            if restgetlisttime < restgetbest:
                restgetbest = restgetlisttime
            restgetexecutiontime += restgetlisttime
            restgetcount += 1
            if virtuals.get('nextLink'):
                done = False
                while (not done ):
                    itemsretrieved = len(virtuals['items'])
                    #print ('Items retrieved: %s' % (itemsretrieved))
                    restgetliststart = time.time()
                    virtualpage = bip.get('%s/ltm/virtual?$top=%s&$skip=%s' % (url_base, args.items, itemsretrieved) ).json()
                    restgetlisttime = time.time() - resgetliststart
                    restgetexecutiontime += restgetlisttime
                    if restgetlisttime > restgetworst:
                        restgetworst = restgetlisttime
                    if restgetlisttime < restgetbest:
                        restgetbest = restgetlisttime
                    restgetcount += 1
                    #print ('virtualpage item count: %s' % (len(virtualpage['items'])))
                    for item in virtualpage['items']:
                        virtuals['items'].append(item)
                    #virtuals['items'].append(virtualpage['items'])
                    if not virtualpage.get('nextLink'):
                        done = True
                        #print ('Got all items')
            print ('Virtual Count: %s' % (len(virtuals['items'])))
            for item in virtuals['items']:
                if virtual['name'] == '%s%s' % (virtualprefix, loop):
                    createvirtual = False
                if args.itemoutput:
                    print ('Virtual Name: %s' % (item['name']))
            restgetliststart = time.time()
            pools = bip.get('%s/ltm/pool?$top=%s' % (url_base, args.items) ).json()
            restgetlisttime = time.time() - resgetliststart
            restgetexecutiontime += restgetlisttime
            if restgetlisttime > restgetworst:
                restgetworst = restgetlisttime
            if restgetlisttime < restgetbest:
                restgetbest = restgetlisttime
            restgetcount += 1
            if pools.get('nextLink'):
                done = False
                while (not done ):
                    itemsretrieved = len(pools['items'])
                    #print ('Items retrieved: %s' % (itemsretrieved))
                    restgetliststart = time.time()
                    poolpage = bip.get('%s/ltm/pool?$top=%s&$skip=%s' % (url_base, args.items, itemsretrieved) ).json()
                    restgetlisttime = time.time() - resgetliststart
                    restgetexecutiontime += restgetlisttime
                    if restgetlisttime > restgetworst:
                        restgetworst = restgetlisttime
                    if restgetlisttime < restgetbest:
                        restgetbest = restgetlisttime
                    restgetcount += 1
                    #print ('poolpage item count: %s' % (len(poolpage['items'])))
                    for item in poolpage['items']:
                        pools['items'].append(item)
                    #virtuals['items'].append(virtualpage['items'])
                    if not poolpage.get('nextLink'):
                        done = True
            print ('Pool Count: %s' % (len(pools['items'])))
            for item in pools['items']:
                if pool['name'] == '%s%s' % (poolprefix, loop):
                    createpool = False
                if args.itemoutput:
                    print ('Pool Name: %s' % (item['name']))
        if createpool and createvirtual:
            createPoolPlusVirtual(loop)
        end = time.time()
        runtime = end - start
        print ('Top/Skip Run Time: %s' % (runtime))
        topskiptotal += runtime
        print ('Top Skip Total Runtime: %s' % (topskiptotal))
    topskipbuildend = time.time()
    for loop in range(args.loops, 0, -1):
        print ('Deleting objects: %s' % (loop))
        deletePoolPlusVirtual(loop)
    topskipdeleteend = time.time()
    topskipdeletetime = topskipdeleteend - topskipbuildend

scriptend = time.time()
scriptruntime = scriptend - scriptbegin
if args.singlerequest:
    singlerequestbuildtime = singlerequestbuildend - singlerequestbuildstart
else:
    singlerequestbuildtime = 0
if args.topskip:
    topskipbuildtime = topskipbuildend - topskipbuildstart
else:
    topskipbuildtime = 0
buildtime = singlerequestbuildtime + topskipbuildtime
restpostrps = restpostcount / buildtime
deletetime = singlerequestdeletetime + topskipdeletetime
deleterps = restdeletecount / deletetime

print ('Total REST GET requests: %s' % (restgetcount))
if args.getlist:
    restgetresponsetime = restgetexecutiontime / restgetcount
    print ('Average REST GET response time: %s' % (restgetresponsetime))
    print ('Best REST GET response time: %s' % (restgetbest))
    print ('Worst REST GET response time: %s' % (restgetworst))
print ('Total REST POST requests: %s' % (restpostcount))
restpostresponsetime = restpostexecutiontime / restpostcount
print ('Average POST request response time: %s' % (restpostresponsetime))
print ('Total REST DELETE requests: %s' % (restdeletecount))
restrequests = restgetcount + restpostcount + restdeletecount
print ('POST requests per second: %s' % (restpostrps))
print ('DELETE requests per second: %s' % (deleterps))
print ('Total REST requests: %s' % (restrequests))
print ('Script execution time: %s' % (scriptruntime))
requestspersec = restrequests / scriptruntime
print ('Script REST requests per second: %s' % (requestspersec))
print ('Single Request Total Runtime: %s' % (singlerequesttotal))
print ('Top Skip Total Runtime: %s' % (topskiptotal))
print ('Virtual Error Count: %s' % (virtualerrorcount))
print ('Pool Error Count: %s' % (poolerrorcount))
print ('Member Error Count: %s' % (membererrorcount))
