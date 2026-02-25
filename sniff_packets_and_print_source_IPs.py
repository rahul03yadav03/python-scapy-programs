# Import everything from Scapy library
from scapy.all import *


# Define a function that will be called for every captured packet
def source_ip(packet):


    # Check if the captured packet contains an IP layer
    if packet.haslayer(IP):

        # Print confirmation that packet contains IP
        print("PACKET HAS IP")

        # Print the source IP address of the packet
        print("Packet Source IP: ",packet[IP].src)

        # Print the destination IP address of the packet
        print("Packet DEstination IP: ", packet[IP].dst)


# Start sniffing network packets
# prn=source_ip -> call the function for each packet
# count=10 -> stop after capturing 10 packets
sniff(prn=source_ip, count=10)
