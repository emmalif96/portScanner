import os
import sys
import socket
import argparse
import random
import time
from scapy.all import *
from ipaddress import ip_address
from ipaddress import ip_network
from ipaddress import summarize_address_range
from datetime import datetime

class SimpleScanner():

	def __init__(self):
		pass

	def scan(self, hostname, lowport, highport, ports, lowAndSlow, showClosed):
		"""
		@param hostname: is either a url,a ip address or a list of ip addresses.
		@param lowport: is a port number and the ports between lowport and highport are the ports that are being checked 
		if both are 0 then the most common ports are used.
		@param highport: is a port number and the ports between lowport and highport are the ports that are being checked 
		if both are 0 then the most common ports are used.
		@param ports: Is the number between lowport and highport. is not used if both highport and lowport are 0.
		@param lowAndSlow: Is a boolean that decides if lowAndSlow is used or not.
		@param showClosed: Is a boolean that decides if we show closed ports or not.

		@type hostname: String
		@type lowport: int 
		@type highport: int
		@type ports: list 
		@type lowAndSlow: boolean
		@type showClosed: boolean

		@return: none
		"""
		serverIP  = socket.gethostbyname(hostname)


		print("-" * 60)
		print("Please wait, scanning host '%s', IP %s" % (hostname, serverIP))
		print("-" * 60)

		t1 = datetime.now()

		try:
			current = 0
			open = 0
			closed_or_filtered = 0
			if lowAndSlow:
				random.shuffle(ports) """makes the ports go in a random order instead of a decending order"""
			for port in ports:
				port = int(port)
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock.settimeout(1)
				result = sock.connect_ex((serverIP, port))
				sock.close()
				if result == 0:
					open += 1
					print("Port %s - Open" % (port))
				else:
					if showClosed:
						print("Port %s - Closed" % (port))
					closed_or_filtered += 1

				if lowAndSlow:
					time.sleep(60)

		except KeyboardInterrupt:
			print("You pressed Ctrl+C")
			sys.exit()
		except socket.gaierror:
			print('Hostname could not be resolved. Exiting')
			sys.exit()
		except socket.error:
			print("Couldn't connect to server")
			sys.exit()

		t2 = datetime.now()
		total =  t2 - t1
		print('%d ports scanned in %s' % (len(ports), total))
		print('    Open:                 %d' % open)
		print('    Closed or filtered:   %d' % closed_or_filtered)


	def checkhost(self, hostname):
		""" 
		@param hostname: is either a url,a ip address or a list of ip addresses.

		@type hostname: String

		@return: none 
		"""
		serverIP  = socket.gethostbyname(hostname)
		ping = IP(dst = serverIP)/ICMP()
		response = sr1(ping, timeout=6, verbose=0)
		if response == None: 
			print ("This host is down!")
		else:
			print("This host is up!")

	def checkport(self, hostname, ports, lowAndSlow, showClosed):
		""" 
		@param hostname: Is either a url,a ip address or a list of ip addresses.
		@param ports: Is a list of ports.
		@param lowAndSlow: Is a boolean that decides if lowAndSlow is used or not.
		@param showClosed: Is a boolean that decides if we show closed ports or not.
		
		@type hostname: String
		@type ports: list 
		@type lowAndSlow: boolean
		@type showClosed: boolean

		@return: none 
		"""
		serverIP  = socket.gethostbyname(hostname)
		totalPorts = highport - lowport
		for port in ports:
			tcpRequest = IP(dst=serverIP)/TCP(dport=port,flags="S")
			tcpResponse = sr1(tcpRequest, timeout=6, verbose=0)

			try: 
				if "SA" in str(tcpResponse.summary()):
					print("Port %s - Open" % (port))
				else:
					if showClosed:
						print("Port %s - Closed" % (port))	
			except AttributeError:
				print(port, "is not listening")		
			
			if lowAndSlow:
				time.sleep(60)


""" Parse some arguments """

parser = argparse.ArgumentParser('Scanner')
parser.add_argument('host', help="The host")
parser.add_argument('lowport', help="The low port")
parser.add_argument('highport', help="The high port")
parser.add_argument('-v', '--verbose', help="Verbose output", action="store_true")
args = parser.parse_args()

host = args.host
lowport = int(args.lowport)
highport = int(args.highport)
scanner = SimpleScanner()
lowAndSlow = False
ranPorts = False
showClosed = False
topPorts = False

ports = []
ipRange = []

""" Testing ports in range or well known ports """
if lowport == 0 and highport == 0:
	topPorts = True
	with open('ports.txt') as file_in:
		for line in file_in:
			ports.append(int(line.split(':')[0]))
else:
	for port in range(lowport, highport+1):
		ports.append(port)


""" Low and slow or normal scan? """
print("Press 1 for a low and slow scan and 2 for a normal scan")
q1 = input()
if q1 == "1":
	lowAndSlow = True
	ranPorts = True
elif q1 == "2":
	print("Press 1 to scan ports in ascending order and 2 for a randomized order")
	q2 = input()
	if q2 == "2":
		ranPorts = True
	elif q2 != "1":
		print("Error, choose 1 or 2")
		sys.exit(0)
else:	 
	print("Error, choose 1 or 2")
	sys.exit(0)


""" Normal scan or SYN scan? """
print("Press 1 for SYN scan and 2 for a normal scan")
q0 = input()
if q0 == "1":
	SYN = True
elif q0 == "2":
	SYN = False
else:
	print("Error, choose 1 or 2")
	sys.exit(0)

""" Show closed ports or hide """
print("Press 1 to display closed/filtered ports and 2 to hide them")
q0 = input()
if q0 == "1":
	showClosed = True
elif q0 == "2":
	showClosed = False
else:
	print("Error, choose 1 or 2")
	sys.exit(0)

print('')
print('-' * 80)

if lowAndSlow:
	print("Low and slow mode activated")
else:
	print("Low and slow mode not activated")
if SYN:
	print("SYN scan activated")
else:
	print("SYN scan not activated")
if ranPorts:
	print("Ports will be tested in randomized order")
else:
	print("Ports will be tested in ascending order")
if topPorts:
	print("50 well known ports will be tested")
else:
	print("Ports in the range", lowport, "-", highport, "will be tested")
print("Host/s to scan:", host)

print('-' * 80)
input("Correct? Press enter to start the scan")
print('-' * 80)



""" if we want to scan a CIDR range """
if "/" in host:
	print(host)
	network = ip_network(host)
	for ip in network:
		if SYN:
			scanner.checkhost(str(ip))
			scanner.checkport(str(ip), ports, lowAndSlow, showClosed)
		else:
			scanner.scan(str(ip), lowport, highport, ports, lowAndSlow, showClosed)

""" if we want to scan a range of IP addresses """
elif "-" in host:
	ipRange.append(host.split("-"))
	for r in summarize_address_range(ip_address(ipRange[0][0]), ip_address(ipRange[0][1])):
		network = ip_network(r)
		for ip in network:
			if SYN:
				scanner.checkhost(str(ip))
				scanner.checkport(str(ip), ports, lowAndSlow, showClosed)
			else:
				scanner.scan(str(ip), lowport, highport, ports, lowAndSlow, showClosed)

""" If hostname is 0 then we read ip addresses from a file """
elif (host == "0"):
	with open('ipaddresses.txt') as file_in:
		for line in file_in:
			if SYN:
				scanner.checkhost(str(ip))
				scanner.checkport(str(ip), ports, lowAndSlow, showClosed)
			else:
				scanner.scan(str(line.split("\n")[0]), lowport, highport, ports, lowAndSlow, showClosed)
			
else:
	if SYN:
		scanner.checkhost(host)
		scanner.checkport(host, ports, lowAndSlow, showClosed)
	else:
		scanner.scan(host, lowport, highport, ports, lowAndSlow, showClosed)