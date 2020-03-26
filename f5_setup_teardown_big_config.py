#!/usr/bin/python

## Big Config Tool
## Author: Chad Jenison (c.jenison@f5.com)
## Script that connects to BIG-IP over network (via SSH) and then uses TMSH commands to create large configuration


import argparse
import sys
import socket
import getpass
import paramiko
import time


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
        choice = raw_input().lower()
        if default is not None and choice == '':
           return valid[default]
        elif choice in valid.keys():
           return valid[choice]
        else:
           sys.stdout.write("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")

def determineShell():
    stdin, stdout, stderr = sshSession.exec_command('tmsh show sys version')
    output = ""
    for line in stderr.read().splitlines():
        output = output + line
    if output.find('Syntax Error') == -1:
        return 'bash'
    else:
        print ('Login shell for user %s is not bash; this script requires login shell of bash (Advanced Shell)')
        return 'tmsh'



parser = argparse.ArgumentParser(description='A tool to test large configurations', epilog='Use this tool with caution')
mode = parser.add_mutually_exclusive_group(required=True)
mode.add_argument('--add', action='store_true', help='build up configuration')
mode.add_argument('--remove', action='store_true', help='clean up configuration')
mode.add_argument('--addandremove', action='store_true', help='build up configuration then remove')
parser.add_argument('--num', type=int, help='Number of Pools and Virtuals to create', required=True)
parser.add_argument('--bigip', help='IP or hostname of BIG-IP Management or Self IP', required=True)
parser.add_argument('--user', help='username to use for authentication', required=True)

args = parser.parse_args()

passwd = getpass.getpass("Password for " + args.user + ":")

sshSession=paramiko.SSHClient()
sshSession.set_missing_host_key_policy(paramiko.AutoAddPolicy())
sshSession.connect(args.bigip, username=args.user, password=passwd, look_for_keys=False, allow_agent=False)
configChanged = False
if determineShell() == 'bash':
    loginShell = 'bash'
    commandPrefix = 'tmsh -c \"'
    commandPostfix = '\"'
else:
    loginShell = 'tmsh'
    commandPrefix = ''
    commandPostfix = ''

if args.add or args.addandremove:
	configInstance = 1
	port = 1
	while configInstance <= args.num:
		print ('configInstance: %s ;args.num: %s' % (configInstance, args.num))
		stdin, stdout, stderr = sshSession.exec_command('%screate ltm pool pool%s monitor tcp_half_open members add { 192.168.1.1:%s 192.168.1.2:%s}%s' % (commandPrefix, configInstance, port, port, commandPostfix))
		exit_status = stdout.channel.recv_exit_status()
		for line in stderr.read().splitlines():
			if line:
				print ('configInstance: %s - stderr: %s' % (configInstance, line))
		for line in stdout.read().splitlines():
			if line:
				print ('configInstance: %s - stderr: %s' % (configInstance, line))
		stdin, stdout, stderr = sshSession.exec_command('%screate ltm virtual virtual%s destination 10.0.0.1:%s pool pool%s%s' % (commandPrefix, configInstance, port, configInstance, commandPostfix))
		exit_status = stdout.channel.recv_exit_status()
		for line in stderr.read().splitlines():
			if line:
				print ('configInstance: %s - stderr: %s' % (configInstance, line))
		for line in stdout.read().splitlines():
			if line:
				print ('configInstance: %s - stderr: %s' % (configInstance, line))
		configInstance += 1
        port += 1

if args.remove or args.addandremove:
	configInstance = 1
	while configInstance <= args.num:
		error = 0
		print ('configInstance: %s ;args.num: %s' % (configInstance, args.num))
		stdin, stdout, stderr = sshSession.exec_command('%sdelete ltm virtual virtual%s; delete ltm pool pool%s%s' % (commandPrefix, configInstance, configInstance, commandPostfix))
		exit_status = stdout.channel.recv_exit_status()
		for line in stderr.read().splitlines():
			if line:
				print ('configInstance: %s - stderr: %s' % (configInstance, line))
				error = 1
		for line in stdout.read().splitlines():
			if line:
				print ('configInstance: %s - stderr: %s' % (configInstance, line))
				error = 1
		if error:
			stdin, stdout, stderr = sshSession.exec_command('%sdelete ltm virtual virtual%s%s' % (commandPrefix, configInstance, commandPostfix))
			stdin, stdout, stderr = sshSession.exec_command('%sdelete ltm pool pool%s%s' % (commandPrefix, configInstance, commandPostfix))
		configInstance += 1
		error = 0

if args.add or args.remove:
    queryString = 'Do you want to save changes to configuration files?'
    if query_yes_no(queryString, default="yes"):
        if loginShell == 'bash':
            stdin, stdout, stderr = sshSession.exec_command("tmsh save sys config")
        elif loginShell == 'tmsh':
            stdin, stdout, stderr = sshSession.exec_command("save sys config")
