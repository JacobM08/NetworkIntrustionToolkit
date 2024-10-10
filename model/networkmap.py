import scapy
from scapy.all import rdpcap, ifaces
from scapy.all import *
import networkx as nx
import matplotlib.pyplot as plt

# Load the PCAP file
packets = rdpcap('output.pcap')

# Create a directed graph
G = nx.DiGraph()

# Extract IP pairs from each packet
#ip_addy = get_if_addr(conf.iface)

def plot_map():
    for packet in packets:
        if packet.haslayer('IP'):
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            # Add nodes and edges to the graph
            G.add_edge(src_ip, dst_ip)

    # Draw the network topology
    pos = nx.spring_layout(G, k = 1.5)
    plt.figure(figsize=(10, 10))
    nx.draw(G, pos, with_labels=True, node_size=1500, node_color='grey', font_size=8, font_weight='bold', edge_color = 'lightgrey', arrows = True)
    plt.title('Network Topology')
    plt.show()

#plot_map()