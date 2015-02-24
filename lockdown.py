#!/usr/bin/env python
# -*- coding: utf-8

from __future__ import print_function

NORMAL = '\033[m'; DARK_GREEN = '\033[32m'

tag = '''{green}

              ▄▄▌         ▄▄· ▄ •▄ ·▄▄▄▄        ▄▄▌ ▐ ▄▌ ▐ ▄ 
              ██•  ▪     ▐█ ▌▪█▌▄▌▪██▪ ██ ▪     ██· █▌▐█•█▌▐█
              ██▪   ▄█▀▄ ██ ▄▄▐▀▀▄·▐█· ▐█▌ ▄█▀▄ ██▪▐█▐▐▌▐█▐▐▌
              ▐█▌▐▌▐█▌.▐▌▐███▌▐█.█▌██. ██ ▐█▌.▐▌▐█▌██▐█▌██▐█▌
              .▀▀▀  ▀█▄▀▪·▀▀▀ ·▀  ▀▀▀▀▀▀•  ▀█▄▀▪ ▀▀▀▀ ▀▪▀▀ █▪
{normal}
'''.format( green=DARK_GREEN, normal=NORMAL )

import collections
import itertools
import argparse
import socket
import os

def parse_args():
	parser = argparse.ArgumentParser(description='l0ckd0wn ur shit')
	parser.add_argument('--inet', metavar='eth0', dest='inet',
						type=str, help='internet interface', default='eth0' )
	parser.add_argument('--ivpn', metavar='tun0', dest='ivpn',
						type=str, help='vpn interface', default='tun0' )
	parser.add_argument('--ssh', action='store_true', dest='ssh',
						help='allow ssh' )
	parser.add_argument('--dir', metavar='/etc/openvpn', dest='dir', type=str,
						help='vpn config folder', default='/etc/openvpn' )
	parser.add_argument('--ext', metavar='.conf', dest='ext', type=str,
						help='vpn config extension', default='.conf' )
	parser.add_argument('--out', metavar='fw.sh', dest='out', type=str,
						help='write to file', default=None )
	args = parser.parse_args()
	return args

base = '''
#!/bin/bash
iptables -F
iptables -P OUTPUT DROP
iptables -P INPUT DROP
iptables -P FORWARD DROP

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
'''

vpn = '''
iptables -A OUTPUT -o {ivpn} -j ACCEPT
iptables -A INPUT -i {ivpn} -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i {inet} -m state --state ESTABLISHED,RELATED -j ACCEPT
'''

ssh = '''
iptables -A INPUT -i {inet} -p tcp --dport 22 -j ACCEPT
iptables -A OUTPUT -o {inet} -p tcp --sport 22 -j ACCEPT
'''

conn = '''
iptables -A OUTPUT -o {inet} -p {proto} -d {host} --dport {dport} -j ACCEPT
'''

def list_files( dir, ext ):
	files = os.listdir( dir )
	for file in files:
		if file.endswith( ext ):
			yield os.path.abspath(os.path.join( dir, file ))

def parse_config( file ):
	with open( file, 'rb' ) as fh:
		lines = [ _.strip() for _ in fh.readlines() ]
	proto = [ _.split(' ')[1] for _ in lines if _.startswith('proto ') ][0]
	remotes = [ _.split(' ')[1:3] for _ in lines if _.startswith('remote ') ]
	servers = [ _.split(' ')[1] for _ in lines if _.startswith('server') ]
	ports = [ _.split(' ')[1] for _ in lines if _.startswith('port ') ]
	return ( proto, remotes, servers, ports )

class OrderedSet( object ):

	def __init__( self, iter=[] ):
		self._ordered = collections.OrderedDict(zip(iter,
													itertools.cycle([None,])))

	def add( self, value ):
		self._ordered[ value ] = None

	def ordered( self ):
		return self._ordered.keys()

def valid_ip( candidate ):
	try:
		socket.inet_pton(socket.AF_INET, candidate)
		return True
	except socket.error:
		return False

def generate_config_block( proto, remotes, servers, ports, inet, ivpn ):
	yield vpn.format( ivpn=ivpn, inet=inet )
	for host, port in remotes:
		if valid_ip( host ):
			ips = [host,]
		else: 
			ips = socket.gethostbyname_ex( host )[2]
		for ip in ips:
			yield conn.format( inet=inet, proto=proto, host=ip, dport=port )
	for server in servers:
		if valid_ip( server ):
			ips = [server,]
		else:
			ips = socket.gethostbyname_ex( server )[2]
		for ip in ips:
			for port in ports:
				yield conn.format( inet=inet, proto=proto, host=ip, dport=port )

def generate_config( configs, inet='eth0', ivpn='tun0', ssh=False ):
	fw = OrderedSet([ base, ])
	if ssh:
		fw.add( ssh.format( inet=inet ))
	for config in configs:
		for block in generate_config_block( *config, inet=inet, ivpn=ivpn ):
			fw.add( block )
	return '\n'.join([ _.strip() for _ in fw.ordered() ])

if __name__ == "__main__":
	print( tag )
	args = parse_args()
	configs = [parse_config( _ ) for _  in  list_files( args.dir, args.ext )]
	conf = generate_config( configs,
							inet=args.inet,
							ivpn=args.ivpn,
							ssh=args.ssh )
	if args.out:
		with open( args.out, 'wb+' ) as fh:
			fh.write( conf )
	print( conf )
