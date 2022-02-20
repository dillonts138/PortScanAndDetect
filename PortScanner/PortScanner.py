#John Marinelli 
#CSCI 5742
#Homework 2
#Program purpose:	This program will take as input a target IP, start and end ports, scanning
#					from the start port to the end port, attempting to open a TCP connection 
#					at each one. 
#					
#					Between each connection, a supplied argument time_var will determine the 
#					amount of time in seconds to wait before connecting to the next port. 
#
#					Expected types: All should be supplied as strings from command line arguments.
#					Type conversion is performed for start_port, end_port and time_var into
#					integer, integer and float respectively.					
#

#----------------------------------------------------------------------------------------------
#Imports
#----------------------------------------------------------------------------------------------

from scapy.all import *
import random
from time import sleep

#----------------------------------------------------------------------------------------------
#Internal methods
#----------------------------------------------------------------------------------------------

#Implementation of port_scanner() taking in arguments for IP, sart port, end port and wait time
def port_scanner(host, start_port, end_port, time_var):
	start_port = int(start_port)
	end_port = int(end_port)
	time_var = float(time_var)
	#Loop will not run if start_port == end_port. This corrects.
	if start_port == end_port:
		end_port += 1	
	#Iterate through port range
	for i in range(start_port, end_port):
		src_port = random.randint(1025, 65534)
		#Attempt TCP connection
		response = sr1(IP(dst=host)/TCP(sport=src_port, 
			dport=i, flags="S"), timeout=1, verbose=0)
		#Determine output based on response
		if response is None:
			print("{0}:{1} has silently dropped the packet.".format(host, i))
		elif(response.haslayer(TCP)):
			if(response.getlayer(TCP).flags == 0x12):
				send_rst = sr(IP(dst=host)/TCP(sport=src_port, dport=i, 
					flags="R"), timeout=1)
				print("{0}:{1} is open.".format(host, i))
			elif(response.getlayer(TCP).flags == 0x14):
				print("{0}:{1} is closed.".format(host, i))
		elif(response.haslayer(ICMP)):
			if (int(response.getlayer(ICMP).type) == 3
				and int(response.getlayer(ICMP).code) in 
				[1, 2, 3, 9, 10, 13]):
				print("{0}:{1} has silently dropped the packet.".format(host, i))
		#Wait for specified time in seconds
		sleep(time_var)



