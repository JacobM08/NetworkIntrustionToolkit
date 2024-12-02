# EECS 4480 Computer Security Project

   This is a project created by Jacob Medeiros of York University for the EECS 4480 Computer Security Project Course of the fourth year. 

## Abstract 
The purpose of this project is to understand how network traffic is captured and how unencrypted traffic can be analyzed. Additionally, the project aims to map a network topology and demonstrate what an adversary might look for when attempting lateral movement. Finally, the project explores a method of attack by implementing the Kaminsky attack.

## Contents
- [Installation](#installation) 🧰
- [Running the Program](#running-the-program) ⚙️
- [Sniffing](#sniffing)👃
- [Network Mapping](#network-mapping)🗺️
- [Attack Setup](#attack-setup) 🔧


## Resources Used

- Kaminsky Attack - SEED Labs: [Link](https://seedsecuritylabs.org/Labs_20.04/Networking/DNS/DNS_Remote/)
  - Utilized to configure lab environment
- Improving Scapy's Packet Sending Performance - Mad-Max Scapy: [Link](https://byt3bl33d3r.github.io/mad-max-scapy-improving-scapys-packet-sending-performance.html)
  - Utilized to understand how to improve Scapy packet send time
- NetworkX Documentation - NetworkX: [Link](https://networkx.org/documentation/stable/reference/introduction.html)
  - Utilized for creating network graphs
- Scapy Documentation - Scapy: [Link](https://scapy.readthedocs.io/en/latest/index.html)

## Installation 

Firstly, clone the repository from GitHub with the following command:
```bash
git clone https://github.com/JacobM08/4480Project
```

Next, navigate into the directory created:
```bash
cd 4480Project/controller
```
## Running the Program 

To run the program, enter the following command:
```bash
sudo python3 controller.py
```
*Note*: Please make sure you have Python 3 installed. The sniffing function establishes a socket connection, so running with sudo is required.

A menu with multiple options will appear, make the desired choice. Upon keyboard interruption (ctrl + C) you will be returned to the main menu

## Sniffing 

The sniffing function establishes a socket connection to capture traffic. It displays all the necessary information and ASCII decodes unencrypted packets containing a payload. The traffic capture operates on the default network interface.

## Network Mapping 

The network mapping function operates by opening the pcap file within the cloned repository with the name 'output.pcap'

## Attack Setup 

Please ensure that this attack is used strictly for educational purposes and that any unauthorized use of these techniques on systems without explicit permission is illegal.

To configure the Kaminsky attack follow the below steps:

- Understand your target, there are a few mutable fields.
   - targetDomain: This is the domain that you wish to have the attacker poison the cache of in the target DNS
   - targetDNS: This is the DNS server you wish to target, this DNS server's cache for example.com will change
   - attacker: This is the malicious name server that the attack is in control of
   - SourceIP: Attacker machines IP, this is used to send the DNS request
   - nsIPs: These are the name server IPs of the targetDomain.
   - Port: This is the source port where the DNS packets are sent to
