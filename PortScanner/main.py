#John Marinelli 
#CSCI 5742
#Homework 2
#Program purpose:	This program will take as input a target IP, start and end ports, scanning
#					from the start port to the end port, attempting to open a TCP connection 
#					at each one. A time argument is also supplied, determining how long the program
#					waits between each connection
#					
#					Between each connection, a supplied argument time_var will determine the 
#					amount of time in seconds to wait before connecting to the next port. 
#
#----------------------------------------------------------------------------------------------
#Imports
#----------------------------------------------------------------------------------------------

import sys
#If proper arguments are not supplied, provide help and exit. 
if len(sys.argv)!= 5:
	print("Enter IP, start and end ports ",
		"Ex: Python3 main.py 192.168.10.129 1 150")
	sys.exit(0)
from PortScanner import port_scanner

#----------------------------------------------------------------------------------------------
#Main function implementation
#----------------------------------------------------------------------------------------------

#Calls port_scanner() from PortScanner.py
def main():
	#arguments: IP, start port, end port, wait time
	port_scanner(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])

#Call to main() when this file is run
if __name__ == "__main__":
	main()


