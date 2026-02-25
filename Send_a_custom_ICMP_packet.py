# Import everything from the Scapy library
from scapy.all import *


# Create a custom ICMP  packet
# IP layer -> destination is 8.8.8.8 (Google DNS)
# ICMP layer -> default type is 8 
packet = IP(dst="8.8.8.8")/ICMP()


# Send the packet and wait for exactly one response
# timeout=10 -> wait up to 10 seconds
response = sr1(packet, timeout=10)


# Check if a response was received
if response:
    print("WE GOT RESPONSE")


    # Print the source IP address of the response
    print("Response Source: ",response.src)

    # Print the ICMP type field from the response
    print("Response Type: ",response[ICMP].type)


# Print completion message
print("SNIIFING COMPLETED!")
