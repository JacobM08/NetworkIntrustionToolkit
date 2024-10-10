import threading, scapy, time
from scapy.all import sniff, send, IP, ICMP

def sniff_packets():
    def process_packet(packet):
        print(packet.summary())

    sniff(prn = process_packet)

def send_packets():
    packet = IP(dst = "10.0.2.4")/ ICMP()
    while True:
        send(packet, verbose = True)
        time.sleep(1)

sniff_thread = threading.Thread(target=sniff_packets)
send_thread = threading.Thread(target=send_packets)
try:
    sniff_thread.start()
    send_thread.start()
except KeyboardInterrupt:
    sniff_thread.join()
    send_thread.join()
