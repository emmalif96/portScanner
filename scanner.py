import os
import sys
import socket
import argparse
import random
import time
# from scapy.all import *
from ipaddress import ip_address
from ipaddress import ip_network
from ipaddress import summarize_address_range
from datetime import datetime

class SimpleScanner():

	def __init__(self):
		pass

	def scan(self, hostname, lowport, highport, ports):

		serverIP  = socket.gethostbyname(hostname)


		print("-" * 80)
		print("Please wait, scanning host '%s', IP %s" % (hostname, serverIP))
		print("-" * 80)

		t1 = datetime.now()

		try:
			current = 0
			open = 0
			closed_or_filtered = 0
			
			# if lowport == 0 and highport == 0:
			print("total searches: %s" % len(ports))
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
					closed_or_filtered += 1
			# else:
			# 	print("total searches: %s" % (highport-lowport+1))
			# 	for port in range(lowport, highport+1):
			# 		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			# 		sock.settimeout(1)
			# 		result = sock.connect_ex((serverIP, port))
			# 		sock.close()
			# 		if result == 0:
			# 			open += 1
			# 			print("Port %s - Open" % (port))
			# 		else:
			# 			closed_or_filtered += 1

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
		print('Scanning Completed in:  %s' % total)
		print('    Open:               %d' % open)
		print('    Closed or filtered: %d' % closed_or_filtered)


	def lowandslow(self, hostname, lowport, highport, ports):
		serverIP  = socket.gethostbyname(hostname)
		print("-" * 60)
		print("Please wait, low and slow scanning host '%s', IP %s" % (hostname, serverIP))
		print("-" * 60)

		lowtime1 = datetime.now()

		try:
			total = 1000
			current = 0
			open = 0
			closed_or_filtered = 0
			# randomlist = range(lowport,highport+1)
			random.shuffle(ports)
			for port in ports:
				# port = ports[i]
				sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				sock.settimeout(1)
				result = sock.connect_ex((serverIP, port))
				sock.close()
				
				if result == 0:
					open += 1
					print("Port %s - Open" % (port))
					time.sleep(60)                                            
				else:
					closed_or_filtered += 1
					print("Port %s - Closed" % (port))
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

		lowtime2 = datetime.now()
		total =  lowtime1 - lowtime2
		print('Scanning Completed in:  %s' % total)
		print('    Open:               %d' % open)
		print('    Closed or filtered: %d' % closed_or_filtered)


	def checkhost(self, hostname, lowport, highport):
		#totalPorts = highport - lowport
		#for port in range(lowport, highport+1):
		serverIP  = socket.gethostbyname(hostname)
		print(serverIP)
		ping = IP(dst = serverIP)/ICMP()
		response = sr1(ping, timeout=6, verbose=0)
		print(response)
		if response == None: 
			print ("This host is down!")
		else:
			print("This host is up!")

	def checkport(self, hostname, lowport, highport):
		serverIP  = socket.gethostbyname(hostname)
		totalPorts = highport - lowport
		for port in range(lowport, highport+1):
			tcpRequest = IP(dst = serverIP)/TCP(dport=port, flags="S")
			tcpResponse = sr1(tcpRequest, timeout = 6, verbose = 0)
			print(tcpRequest)
			print(tcpResponse.getLayer(TCP))

			try: 
				if tcpResponse.getLayer(TCP).flags == "A":
					print(port, "is listening")
			except AttributeError:
				print(port, "is not listening")		

# Parse some arguments
#
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


ports = []
ipRange = []

# Testing ports in range or well known ports
if lowport == 0 and highport == 0:
	print("Testing well known ports...")
	with open('ports.txt') as file_in:
		for line in file_in:
			ports.append(int(line.split(':')[0]))
else:
	for port in range(lowport, highport+1):
		ports.append(port)


print("Press 1 for a low and slow scan and 2 for a normal scan")
x = input()
if x == "1":
	scanner.lowandslow(host, lowport, highport, ports)
elif x == "2":
	scanner.scan(host, lowport, highport, ports)
else: 
	print("Error, choose 1 or 2")
	sys.exit(0)

# if we want to scan a CIDR range
if "/" in host:
	print(host)
	network = ip_network(host)
	for ip in network:
		scanner.scan(str(ip), lowport, highport, ports)

# if we want to scan a range of IP addresses 
elif "-" in host:
	ipRange.append(host.split("-"))
	print(ipRange[0][0], ipRange[0][1])
	for r in summarize_address_range(ip_address(ipRange[0][0]), ip_address(ipRange[0][1])):
		nw = ip_network(r)
		for ip in nw:
			scanner.scan(str(ip), lowport, highport, ports)

# If hostname is 0 then we read ip addresses from a file
elif (host == "0"):
	with open('ipaddresses.txt') as file_in:
		for line in file_in:
			scanner.scan(str(line.split("\n")[0]), lowport, highport, ports)
			
else:
	scanner.scan(host, lowport, highport, ports)
