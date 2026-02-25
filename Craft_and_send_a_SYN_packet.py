# Import all necessary Scapy networking functions
from scapy.all import *


# Ask user for target IP address
target_ip = input("Please enter your destination ip: ")


# Ask user for target port number and convert it to integer
target_port = int(input("Please enter your destination port: "))



# Craft a TCP SYN packet
# IP layer -> destination IP
# TCP layer -> destination port + SYN flag ("S")
packet = IP(dst = target_ip)/TCP(dport = target_port, flags="S")


# Send the packet and wait for 1 response
# timeout=10 -> wait up to 10 seconds
response = sr1(packet, timeout=10)


# Check if we received a response AND it contains a TCP layer
if response and response.haslayer(TCP):

    # If flags = 0x12 -> SYN-ACK -> Port is OPEN
    if response[TCP].flags == 0x12:
        print("Port is open (Received SYN-ACK)")

    # If flags = 0x14 -> RST-ACK -> Port is CLOSED
    elif response[TCP].flags == 0x14:
        print("Port is close (Received RST-ACK)")


# If no response was received
else:
    print("No response received")

print("SYN scan completed")
