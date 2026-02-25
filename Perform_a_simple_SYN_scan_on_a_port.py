#import scapy library
from scapy.all import *


# Prompt the user for the target IP and port number
target = input("Please enter your ip: ")
port = int(input("Please enter port number: "))


# Create a TCP SYN packet to the target IP on the specified port
# 'S' flag indicates SYN (used for initiating a TCP connection)
packet = IP(dst=target)/TCP(dport=port, flags="S")


# Send the SYN packet and wait for a response, with a timeout of 2 seconds
# 'sr1' sends the packet and returns the first response
response = sr1(packet, timeout=2, verbose=0)

# Check if there was a response
if response:

    # If the response contains a TCP layer, we proceed to check the flags
    if response.haslayer(TCP):

        # If the response contains a TCP layer, we proceed to check the flags# If the response flags are 0x12, it's a SYN-ACK, meaning the port is open
        if response[TCP].flags == 0x12:
            print("Port is open")

        # If the response flags are 0x14, it's a RST-ACK, meaning the port is closed
        elif response[TCP].flags == 0x14:
            print("Port is closed")


else:

    # If no response is received, print a message indicating the port may be filtered or the host is down 
    print("NO response (Filtered or host down)")

            
