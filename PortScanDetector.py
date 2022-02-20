# Dillon Shaver
# CSCI 5742
# Homework 2
# Program Purpose: This program will open up two threads in order to detect port scanning on the host lan. 
#
#                  Thread 1 will constanly sniff traffic and look for the first connection (First time Source IP : Source Port -> Destination IP : Destination Port), 
#                  then save that connection data along with a time stamp into a table with a time to live of 5 minutes. On each pass, it will remove any connections that went over five minutes
#                   
#                   Thread 2 will                  
#
#                  Thread 3 will calculate fan out rate for 1 second, 1 minute, and 5 minutes for each IP address. 
#                  If the fan out exceeds (Sec: 5, 1min: 100, 5min: 300), then the Ip is flagged as a detected port scan and the information is displayed.
#-------------------------------------------------------------------------
# Imports
#-------------------------------------------------------------------------
import threading
import time
from scapy.all import *
from FirstConnect import FirstConnect


#-------------------------------------------------------------------------
# Internal Variables
#-------------------------------------------------------------------------
fcTable = {}
fiveMin = 300.0
oneMin = 60.0
oneSec = 1.0

#-------------------------------------------------------------------------
# Internal Methods
#-------------------------------------------------------------------------

# Function to sniff traffic, and check if that traffic is a first connect.
def scanForFirstConnect(fcTable,lock):
    #print("Starting Scans...\n")
    #Flag to check if a first connect already exists. False for doesn't exist, true if it does.
    isFC = False

    #Sniff Traffic
    packets = sniff(timeout = 1)

    srcIP = None
    dstIP = None
    dstPort = None
    timeStamp = None
    #If first connection, append first connection data to table
    for pkt in packets:
        #For all packets that have an IP layer
        if pkt.haslayer(IP):
            if pkt.haslayer(TCP) or pkt.haslayer(UDP):
                #Store IP information
                srcIP = pkt.getlayer(IP).src
                dstIP = pkt.getlayer(IP).dst
                dstPort = pkt.getlayer(IP).dport
                timeStamp = pkt.time
        else:
            continue

        if srcIP != None and dstIP != None and dstPort != None and timeStamp != None:
            lock.acquire()
            if len(fcTable) == 0 or srcIP not in fcTable:
                fcTable[srcIP] = [FirstConnect(srcIP,dstIP,dstPort,timeStamp)]
            else:
                for fc in fcTable[srcIP]:
                    isFC = True
                    if fc.srcIP == srcIP and fc.dstIP == dstIP and fc.dstPort == dstPort:
                        isFC = False
                        break

                if isFC == True:
                    newList = fcTable[srcIP].copy()
                    newList.append(FirstConnect(srcIP,dstIP,dstPort,timeStamp))
                    fcTable[srcIP] = newList
            lock.release() 
    #print("Scans complete.\n")

# TTL Check Function
def ttlCheck(fcTable,lock):
    #print("Starting ttl check...")
    lock.acquire()
    for key in fcTable:
        for fc in reversed(fcTable[key]):
            aliveTime = time.time() - fc.timeStamp
            if aliveTime > fiveMin:
                fcTable[key].remove(fc)
    lock.release()
    #print("Ending ttl check.")




# Fan out Rate Function
def fanOutRate(fcTable, lock):
    #print("Starting FOR... \n")
    
    startTime = time.time()
    for key in fcTable:
        connectPerSec = 0
        connectPerMin = 0
        connectPerFiveMin = 0

        for fc in fcTable[key]:
            aliveTime = startTime - fc.timeStamp
            #print(f"\t Alive time: {aliveTime}")
            if aliveTime <= 1.0:
                connectPerSec += 1
            if aliveTime <= 60.0:
                connectPerMin += 1
            if aliveTime <= 300.0:
                connectPerFiveMin += 1
        
        if connectPerSec > 5:
            print(f"\t Port Scanning detected by IP:{fcTable[key][0].srcIP} | fan out rate per:  Sec:{connectPerSec} Min:{connectPerMin} 5Min:{connectPerFiveMin}\n")
            print(f"\tReason: Fan-out rate per sec = {connectPerSec} (must be less than 5.)\n")
        if connectPerMin > 100:
            print(f"\t Port Scanning detected by IP:{fcTable[key][0].srcIP} | fan out rate per:  Sec:{connectPerSec} Min:{connectPerMin} 5Min:{connectPerFiveMin}\n")
            print(f"\tReason: Fan-out rate per min = {connectPerMin} (must be less than 5.)\n")

        if connectPerFiveMin > 300:
            print(f"\t Port Scanning detected by IP:{fcTable[key][0].srcIP} | fan out rate per:  Sec:{connectPerSec} Min:{connectPerMin} 5Min:{connectPerFiveMin}\n")
            print(f"\tReason: Fan-out rate per 5 min = {connectPerFiveMin} (must be less than 5.)\n")
    #print("Ending FOR...\n")

        
        
        
#----------------------------------------
# Main
#----------------------------------------

#Create thread lock
lock = threading.Lock()
while 1:
    #Create threads
    tableManagment = threading.Thread(target=scanForFirstConnect, args=(fcTable,lock))
    ttlChecker = threading.Thread(target=ttlCheck, args=(fcTable,lock))
    fanOutCalc = threading.Thread(target=fanOutRate, args=(fcTable,lock))

    #Start threads
    tableManagment.start()
    ttlChecker.start()
    fanOutCalc.start()

    tableManagment.join()
    ttlChecker.join()
    fanOutCalc.join()

    
    


#Test Code
# scanForFirstConnect(fcTable)
# print("Before ttlCheck.\n")
# for key in fcTable:
#     for fc in fcTable[key]:
#         print(f"\t srcIP: {fc.srcIP} dstIP: {fc.dstIP} dstPort: {fc.dstPort} TimeStamp: {fc.timeStamp} TimeActive {time.time() - fc.timeStamp}")
# time.sleep(60.0)
# print("After 5 min wait\n")
# for key in fcTable:
#     for fc in fcTable[key]:
#         print(f"\t srcIP: {fc.srcIP} dstIP: {fc.dstIP} dstPort: {fc.dstPort} TimeStamp: {fc.timeStamp} TimeActive {time.time() - fc.timeStamp}")

# print("After TTL Check")
# ttlCheck(fcTable)
# for key in fcTable:
#     for fc in fcTable[key]:
#         print(f"\t srcIP: {fc.srcIP} dstIP: {fc.dstIP} dstPort: {fc.dstPort} TimeStamp: {fc.timeStamp} TimeActive {time.time() - fc.timeStamp}")


# print(f"\t System Time: {time.time()}")




