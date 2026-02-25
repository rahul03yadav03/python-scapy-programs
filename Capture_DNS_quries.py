# Import all necessary functions from Scapy
from scapy.all import *


# Function to detect DNS queries
def dbs_detection(packet):

    # Check if the packet contains a DNS query (DNSQR layer)
    if packet.haslayer(DNSQR):

        # Get the requested domain name
        domain = packet[DNSQR].qname.decode()

        # Get the source IP address
        src_ip = packet[IP].src


        # Print the source IP and the domain being requested
        print(f"[DNS Query] {src_ip} requested {domain}")
         

# Start sniffing for DNS queries (UDP port 53)
sniff(prn=dbs_detection, filter = "udp port 53", store=0)
