import scapy
from scapy.all import *
from scapy.all import IP, ICMP, UDP, TCP

def startsniff():
    user_filter = filters1()
    capture = packet_count()
    def display_traffic(packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            print(f"Layer: IP | Source: {src_ip} -> Destination: {dst_ip} | Protocol: {proto}")

    try:
        pcap = sniff(filter=user_filter, store=1, count = capture, prn = display_traffic)
    except KeyboardInterrupt as e:
         print("")
    cap = input("Would you like to export the packet capture? (Y/N)")
    if (cap == 'Y' or cap == 'y'):
        output_to_pcap(pcap)
        print("Packet capture exported!")
    else:
         print("Packet Capture Not exported!")


def filters1():
    return input("Enter Packet Capture filter(s) (i.e. 'tcp or udp' 'tcp and port 80'). Blank will result in no filters: ")

def output_to_pcap(pcap):
    wrpcap('output.pcap', pcap)

def packet_count():
    capture = input("Please specify # of packets you would like to capture, by default packet capture will be infinite: ")
    if (capture == ''):
            capture = 0
    return int(capture)
