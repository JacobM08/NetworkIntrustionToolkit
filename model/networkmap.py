from scapy.all import rdpcap
from scapy.all import *
import networkx as nx
import matplotlib.pyplot as plt
from collections import defaultdict

class networkMapper:
    def open_pcap(pcap_file):
        try:
            packets = rdpcap(pcap_file)
            return packets
        except FileNotFoundError:
            print(f"Error: Cannot find file {pcap_file}")
            return None

    def os_fingerprint(packet):
        if 'IP' in packet:
            ttl = packet['IP'].ttl
            if ttl <= 64:
                return 'Linux/Unix'
            elif ttl <= 128:
                return 'Windows'
            else:
                return 'Other'
        return 'Unknown'

    def analyze_packets(packets, self):
        print("Analyzing packets...")
        os_mapping = {}
        dns_responses_count = defaultdict(int)
        ip_packets = 0
        
        total_packets = len(packets)
        for packet_num in range(total_packets):
            if packet_num % 500 == 0:
                print(f"Processed {packet_num}/{total_packets} packets")

            packet = packets[packet_num]
                
            if packet.haslayer('IP'):
                ip_packets += 1
                src_ip = packet['IP'].src
                
                if src_ip not in os_mapping:
                    os_mapping[src_ip] = self.os_fingerprint(packet)
                
                if packet.haslayer('DNS') and packet.haslayer('DNSRR'):
                    dns_responses_count[src_ip] += 1

        dns_servers = set()  # Create empty set
        for ip, count in dns_responses_count.items():
            if count >= 3:  # If IP has 3 or more DNS responses, IP needs to be added to the set of DNS servers
                dns_servers.add(ip)
        
        print(f"Found {ip_packets} IP packets")
        print(f"Found {len(dns_servers)} DNS servers")
        print(f"Found {len(os_mapping)} unique IPs")
        
        return os_mapping, dns_servers, ip_packets

    def plot_map(packets, self):
        if not packets:
            print("No packets to analyze")
            return

        os_mapping, dns_servers, ip_packets = self.analyze_packets(packets)
        
        if ip_packets == 0:
            print("No IP packets found in capture")
            return

        print("Building network graph...")
        G = nx.DiGraph()
        
        edges_seen = set()
        for packet in packets:
            if packet.haslayer('IP'):
                src_ip = packet['IP'].src
                dst_ip = packet['IP'].dst
                
                if (src_ip, dst_ip) not in edges_seen:
                    edges_seen.add((src_ip, dst_ip))
                    
                    src_label = f"{src_ip}\n({os_mapping.get(src_ip, 'Unknown')})"
                    dst_label = f"{dst_ip}\n({os_mapping.get(dst_ip, 'Unknown')})"
                    
                    if src_ip in dns_servers:
                        src_label += "\n[DNS Server]"
                    if dst_ip in dns_servers:
                        dst_label += "\n[DNS Server]"
                    
                    G.add_node(src_ip, label=src_label)
                    G.add_node(dst_ip, label=dst_label)
                    G.add_edge(src_ip, dst_ip)

        if len(G.nodes()) == 0:
            print("No nodes added to graph")
            return

        print(f"Graph contains {len(G.nodes())} nodes and {len(G.edges())} edges")

        try:
            print("Generating layout...")
            pos = nx.kamada_kawai_layout(G)
            
            print("Creating plot...")
            # Close all existing figures
            plt.close('all')
            
            # Create a single figure with a specific ID
            fig = plt.figure(num=1, figsize=(12, 12))
            
            node_colors = []
            for node in G.nodes():
                if node in dns_servers:
                    node_colors.append('red')
                else:
                    node_colors.append('lightblue')
            
            nx.draw(G, pos,
                    labels={node: G.nodes[node]['label'] for node in G.nodes()},
                    node_size=2500,
                    node_color=node_colors,
                    font_size=8,
                    font_weight='bold',
                    edge_color='lightgrey',
                    arrows=True)
            
            legend_elements = [plt.Line2D([0], [0], marker='o', color='w', label='Regular Host',
                                        markerfacecolor='lightblue', markersize=10),
                            plt.Line2D([0], [0], marker='o', color='w', label='DNS Server',
                                        markerfacecolor='red', markersize=10)]
            plt.legend(handles=legend_elements, loc='upper left', bbox_to_anchor=(1, 1))
            
            plt.title('Network Topology Map')
            
            print("Displaying plot...")
            plt.show(block=True)
            
        except Exception as e:
            print(f"Error drawing graph: {str(e)}")
            import traceback
            traceback.print_exc()

    def netmap(self):
        packets = self.open_pcap('/home/kali/Documents/Networksniff/trace1.pcapng')
        if packets:
            self.plot_map(packets)
