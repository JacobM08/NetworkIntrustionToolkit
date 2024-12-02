from scapy.all import *
import struct


class TrafficSniffer:
    def __init__(self) -> None:
        self.packet_count = 0


    def convert_mac(self, mac):
        dest_mac = '' #Declare & Initialize
        source_mac = '' #Declare & Initialize
        mac = struct.unpack('!6s6s', mac[:12]) #Slice
        for i in mac[0]:
            dest_mac += (f'{i:02x}:') #format as AA:BB:CC:DD:EE:FF
        for i in mac[1]:
            source_mac += (f'{i:02x}:') #format as AA:BB:CC:DD:EE:FF
        return dest_mac[:-1], source_mac[:-1] #remove last colon at end or else there will be trailing
        
    def convert_eth_protocol(self, proto):
        protocol = socket.ntohs(struct.unpack('!H', proto[12:14])[0]) #Unpack protocol, ntohs convert 16 bit integer from network byte to host byte
        return protocol

    def convert_ip(self, header):
        proto = header[23]
        version = (header[14] >> 4) & 0xF #Bit shift to get top 4 most 
        headerlen = ((header[14]) & 0xF) * 4 #bit shift not needed to get bottom 4
        ttl = header[22]
        header = struct.unpack('!4s4s', header[26:34])
        source_ip = inet_ntoa(header[0])
        dest_ip = inet_ntoa(header[1])
        return source_ip, dest_ip, proto, version, headerlen, ttl

    def convert_ipv6(self, header):
        source_ip6 = socket.inet_ntop(socket.AF_INET6, header[8:24])
        dest_ip6 = socket.inet_ntop(socket.AF_INET6, header[24:40])
        return source_ip6, dest_ip6



    def packet_capture(self):
        try:
            while True:
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) #Establish socket connection

                raw_packet, addr = s.recvfrom(65536) #Read in raw packets
                self.packet_count += 1

                dest_mac, source_mac = self.convert_mac(raw_packet)
                ethernet_protocol = self.convert_eth_protocol(raw_packet)
                source_ip, dest_ip, protocol, vers, headlen, ttl = self.convert_ip(raw_packet)
                
                if ethernet_protocol == 8: #IPv4 Protocol
                    print("\nIPv4 Packet:")
                    print("Dest MAC: {} Source MAC: {}, Ethernet Protocol: {}".format(dest_mac,source_mac, ethernet_protocol))
                    print("Version: {}, Header Length: {}, TTL {}, Protocol: {}".format(vers, headlen, ttl, protocol))
                    print("Source IP: {}, Destination IP: {}".format(source_ip, dest_ip))

                    if protocol == 6: #TCP header
                        print("TCP Packet:")
                        tcp_pack = 14 + headlen
                    
                        # Unpack TCP header
                        tcp_header = struct.unpack('!HHLLBBHHH', raw_packet[tcp_pack:tcp_pack+20])
                        source_port = tcp_header[0]
                        dest_port = tcp_header[1]
                        sequence = tcp_header[2]
                        acknowledgment = tcp_header[3]
                    
                        # Calculate TCP header length
                        tcp_header_length = (tcp_header[4] >> 4) * 4
                    
                        print("Source Port: {}, Destination Port: {}".format(source_port, dest_port))
                        print("Sequence Number: {}, Acknowledgement: {}, TCP Header Length: {}".format(sequence,acknowledgment, tcp_header_length))
                        
                        #Decode unencrypted traffic using ASCII decoding
                        if dest_port == 80 or source_port == 80:
                            payload_start = 14 + headlen +tcp_header_length
                            payload = raw_packet[payload_start:]
                            try:
                                print("\nASCII Decode Attempt:")
                                payload = payload.decode('ascii', errors='ignore')
                                if 'Content-Encoding: gzip' not in payload:
                                    print(payload)
                            except:
                                print("Failed ASCII decode")
                                            


                    elif protocol == 17: #UDP header
                        print("UDP Packet")
                        udp_pack = 14 + headlen
                    
                        # Unpack UDP header
                        udp_header = struct.unpack('!HHHH', raw_packet[udp_pack:udp_pack+8])
                        source_port = udp_header[0]
                        dest_port = udp_header[1]
                        length = udp_header[2]
                        checksum = udp_header[3]

                        print("Source Port: {}, Destination Port: {}".format(source_port, dest_port))
                        print("Length: {}, Checksum: {}".format(length, checksum))

                elif ethernet_protocol == 56710: #packet is not an IPv4 packet
                    source_ip6, dest_ip6 = self.convert_ipv6(raw_packet[14:])
                    print("\nIPv6 Packet:")
                    print("Dest MAC: {} Source MAC: {}, Ethernet Protocol: {}".format(dest_mac,source_mac, ethernet_protocol))
                    print("Source IP: {}, Destination IP: {}".format(source_ip6, dest_ip6))

        except socket.error as e:
            if e.errno == 1:
                print("\nError: Root privileges required.")
                print("Please run the script with sudo.")
    
        except KeyboardInterrupt as e:
                print("Total Packet capture: {}".format(self.packet_count))
