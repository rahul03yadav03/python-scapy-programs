# Import everything from Scapy library
from scapy.all import *

#Define a function taht will be called for every captured http packet
def http_packet(packet):


    # Check if the captured packet contains an IP layer
    if packet.haslayer(IP):

        #Check if the captured packet conatins and TCP layer
        if packet.haslayer(TCP):

            # Print confirmation that packet contains TCP
            print("PACKET HAS TCP LAYER")


            # Print the source IP address of the packet
            print("Packet Source IP: ", packet[IP].src)

            # Print the destination IP address of the packet
            print("Packet destination IP: ", packet[IP].dst)


            #print the source port of the packet
            print("Packet Source Port: ", packet[TCP].sport)

            #Print the destination port of the packet
            print("Packet Destination Port: ", packet[TCP].dport)
            

# Start sniffing network packets
# prn=http_packet -> call the function for each packet
# filter="tcp port 80" -> capture only http packets
# count=10 -> stop after capturing 10 packets
sniff(prn=http_packet, filter = "tcp port 80", count=10)
