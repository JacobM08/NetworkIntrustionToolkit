import sys
import os, time
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from model.attack import *
from model.scanner import *
from model.networkmap import *

# Call the function

def call_scan():
    print("\n--------------------------------")
    print("\nStarting Network traffic Sniffer")
    print("\n--------------------------------")

    startsniff()
    main_menu()

def call_mitm():
    print("\n------------------")
    print("\nStarting MiTM Tool")
    print("\n------------------")

    attack_start()
    main_menu()

def call_networkmap():
    print("\n-----------------------")
    print("\nStarting Network Mapper")
    print("\n-----------------------")

    plot_map()
    main_menu

def main_menu():
    print("\n################################################################")
    print("\n# EECS 4480 Project - Network Intrustion Toolkit               #")
    print("\n# By: Jacob Medeiros 217248824                                 #")
    print("\n#                                                              #")
    print("\n# (1) Capture Network Traffic                                  #")
    print("\n# (2) Run a MiTM Attack                                        #")
    print("\n# (3) Map a Network Topology with a given pcap file            #")
    print("\n# (4) Exit                                                     #")
    print("\n################################################################")

    choice = input()

    if choice == '1':
            call_scan()
    elif choice == '2':
            call_mitm()
    elif choice == '3':
            call_networkmap()
    elif choice == '4':
            exit

main_menu()