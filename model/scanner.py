import scapy
from scapy.all import *


def main():
    print("Starting traffic sniffer")
    user_filter = filters()
    capture = packet_count()

    startsniff(user_filter, int (capture))

def startsniff(user_filter, capture):
    try:
        pcap = sniff(filter=user_filter, store=1, count = capture)
    except KeyboardInterrupt as e:
         print("")
    cap = input("Would you like to export the packet capture? (Y/N)")
    if (cap == 'Y' or cap == 'y'):
        output_to_pcap(pcap)
        print("Packet capture exported!")

def filters():
    return input("Enter Packet Capture filter(s) (i.e. 'tcp or udp' 'tcp and port 80'). Blank will result in no filters: ")

def output_to_pcap(pcap):
    wrpcap('output.pcap', pcap)

def packet_count():
    capture = input("Please specify # of packets you would like to capture, by default packet capture will be infinite: ")
    if (capture == ''):
            capture = 0
    return capture


def test():
     print("THIS WORKS")
#main()