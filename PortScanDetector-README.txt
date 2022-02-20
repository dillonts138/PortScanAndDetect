#Dillon Shaver John Marinelli
#CSCI 5742
#Homework 2
#PortScan Detector


#--------------------------------------------------
# Usage Instructions
#--------------------------------------------------

# This program requires Scapy:

# To Install Scapy on kali linux, use: sudo apt install python3-scapy
# Further information: https://www.kali.org/tools/scapy/

# Because Scapy Sniffs network traffic, the Start command requires admin or root privleges.

# To start the PortScan Detector, navigate to the folder containing PortScanDetector.py and run using:
# Sudo python3 PortScanDetector

#---------------------------------------------------
# Program Details
#---------------------------------------------------
# The program takes no arguments

# The program will scan network traffic every second

# The program is multi-threaded using 3 Threads:


# Thread One:
# The program stores all IP traffic using UDP or TCP protocols in a hashed table
# The Table is hashed by IP address, which contains a list of First Connection data [Source IP, Destination IP, Destination Port, TimeStamp (in Seconds)]
# A first connection is the first found connection from a Source IP address to a previously unvisited port on a destination IP.


# Thread Two:
# Checks the alive time for each First Connection, and if has been alive for more than five minutes, removes it


# Thread Three:
# Checks for port scanning by calculating a fan out rate per second, minute, and every five minutes.

# Because some scanning might be detected earlier, the minute and five minute fan out rate is calculated using all established First Conections 
# With an alive time less than the minute and five minute mark respectively.

# If the fan out rate exceeds the benchmark (Seconds: 5, Minute: 100, Five Minutes: 300),
# The program displays the IP address suspected of port sniffing and all three fan out rates, as well as the reason the IP address was flagged.

# The program will continue to update the fan out rate for an IP until the fanout rate drops below the benchmark.

#---------------------------------------------------
# Sources and refrences
#---------------------------------------------------

#Scapy Documentation and Licensing: https://scapy.readthedocs.io/en/latest/
