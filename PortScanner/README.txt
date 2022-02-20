###########################################
#PortScanner 							  # 	
#John Marinelli							  # 	 
#CSCI 5742 								  #		
#Homework 2						  		  #
###########################################

To operate, navigate to PortScanner directory and run: Python3 main.py [IP] [start port] [end port] [wait time]

Output should indicate whether port is open, closed or the connection was dropped. 

Arguments:

[IP] is the desired target IP.
[start port] is the port you would like to begin your scan with. 
[end port] is the port you would like to end your scan with. 
[wait time] is the desired time between each TCP connection.*

*This is a float value with 1 being one second. 

Dependencies: 

scapy -- To install scapy, run: pip3 install scapy or pip install scapy
