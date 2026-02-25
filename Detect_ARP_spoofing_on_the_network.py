# Import all necessary functions from Scapy
from scapy.all import *


# Dictionary to map IP addresses to MAC addresses
map_ip_mac = {}


# Function to detect ARP Spoofing
def arp_spoof(packet):

    # Check if the packet contains an ARP layer and if it is an ARP reply (op=2)
    if packet.haslayer(ARP) and packet[ARP].op ==2:

        # Get the source IP address from the ARP reply
        ip = packet[ARP].psrc

        # Get the source MAC address from the ARP reply
        mac = packet[ARP].hwsrc

        # Check if the IP address is already in the map
        if ip in map_ip_mac:

            # If the MAC address doesn't match the one already associated with the IP, it indicates spoofing
            if map_ip_mac[ip] != mac:

                # Alert for ARP Spoofing detected
                print(f"[ALERT] ARP Spoofing detected! IP: {ip} has multiple MAC addresses: {mac} is new ")

        else:

            # If the IP is not in the map, add the IP-MAC pair to the map
            map_ip_mac[ip] = mac
        

# Start sniffing for ARP packets
sniff(prn=arp_spoof, filter= "arp", store=0)

