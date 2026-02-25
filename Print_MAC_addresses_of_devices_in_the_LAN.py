# Import Scapy to work with packets
from scapy.all import *


# Ask the user for the network/subnet to scan
network = input("Please enter subnet (xxx.xxx.xxx.0/24): ")


# Create an ARP request for the given network
arp_request = ARP(pdst=network)


# Create an Ethernet frame to send the ARP request to all devices
broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")


# Combine the ARP request and Ethernet frame into one packet
packet = broadcast/arp_request


# Send the packet and receive responses
result = srp(packet, timeout=2, verbose=False)[0]


# Print column headers for the output
print("IP Address\t\tMAC Address")


# Loop through the responses and print the IP and MAC addresses
for send, receive in result:

    # Print IP and MAC of each device
    print(receive.psrc, "\t\t", receive.hwsrc)
