
import scapy
from scapy.all import *
from scapy.layers.l2 import ARP, Ether

def main():
    target_IP = input ("Input target IP address: ")
    #router_IP = input("Enter Router IP address: ")
    #inface = input("Enter Interface name to operate on: ")
    target_mac = get_mac(target_IP)
    print(target_mac)
    gateway_ip = get_gateway()
    print(gateway_ip)


#Get MAC address of Victim/Target
def get_mac(target_IP):
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP (pdst=target_IP), timeout=2, retry = 10)
    for sent, rcv in ans:
        return rcv.hwsrc
    
#Get gateway IP address
def get_gateway():
    gateway_ip = conf.route.route("0.0.0.0")[2]
    return gateway_ip

#def send_spoof():

#def restore_session():

#def port_forwarding():


main()