## Dillon Shaver
# CSCI 5742
# Homework 2
# Program Purpose: Creates a class that stores first connection values (Source IP, Destination IP, Destination Port, TimeStamp)


class FirstConnect:
    
    def __init__(self, srcIP, dstIP, dstPort, timeStamp) -> None:
        self.srcIP = srcIP
        self.dstIP = dstIP
        self.dstPort = dstPort
        self.timeStamp = timeStamp

    def srcIP(self):
        return self.srcIP
    
    def dstIP(self):
        return self.dstIP

    def dstPort(self):
        return self.dstPort

    def timeStamp(self):
        return self.timeStamp



