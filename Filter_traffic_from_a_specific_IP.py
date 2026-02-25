# Import everything from the Scapy library
from scapy.all import *

# Ask the user to enter a specific IP address to monitor
ip = input("Please enter your IP: ")

# Define a function that will be called for every captured packet
def specific_ip(packet):


    # Check if the packet contains both IP and TCP layers
    if packet.haslayer(IP)and packet.haslayer(TCP):


        # Print confirmation message
        print("PACKET HAS IP LAYER")


        # Print the source IP address of the packet
        print("packet source IP: ",packet[IP].src)

        # Print the destination IP address of the packet
        print("packet destination IP: ",packet[IP].dst)

        # Print the source TCP port number
        print("packet source port: ",packet[TCP].sport)

        # Print the destination TCP port number
        print("packet destination port: ",packet[TCP].dport)



# Start sniffing network packets
# prn=specific_ip -> call the function for each captured packet
# filter=f"HOST {ip}" -> capture traffic  from the specified IP address
# count=10 -> stop after capturing 10 matching packets
sniff(prn = specific_ip, filter=f"host {ip}", count=10)
