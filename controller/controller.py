import sys
import os
import time
from colorama import Fore, Style  # For colored output
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from Model.mitmAttack import *
from Model.scanner import *
from Model.networkMap import *


def print_header(title, symbol="="):
    """Prints a stylized header with a given title."""
    print(Fore.CYAN + Style.BRIGHT + f"\n{symbol * 60}")
    print(Fore.GREEN + Style.BRIGHT + f"{title.center(60)}")
    print(Fore.CYAN + Style.BRIGHT + f"{symbol * 60}\n")

def call_scan():
    print_header("NETWORK TRAFFIC SNIFFER", "-")
    print(Fore.YELLOW + "Initializing Network Sniffer...")
    time.sleep(1)
    try:
        sniff = TrafficSniffer()  # Create an instance of the TrafficSniffer
        sniff.packet_capture()    # Start capturing packets
    except KeyboardInterrupt:
        print(Fore.RED + "\n\n[!] Keyboard Interrupt detected. Returning to main menu...\n")
        time.sleep(1)
    except Exception as e:
        print(Fore.RED + f"An error occurred while capturing traffic: {e}")
    finally:
        main_menu()  # Return to the main menu after execution

def call_mitm():
    print_header("MAN-IN-THE-MIDDLE (MiTM) TOOL", "-")
    print(Fore.YELLOW + "Launching MiTM Attack...")
    time.sleep(1)
    try:
        attack = KaminskyAttack() #Create an instance of the KaminskyAttack class
        attack.StartAttack() #Start attack
    except KeyboardInterrupt:
        print(Fore.RED + "\n\n[!] Keyboard Interrupt detected. Returning to main menu...\n")
        time.sleep(1)
    except Exception as e:
        print(Fore.RED + f"An error occurred while capturing traffic: {e}")
    finally:
        main_menu()  # Return to the main menu after execution

def call_networkmap():
    print_header("NETWORK TOPOLOGY MAPPER", "-")
    print(Fore.YELLOW + "Generating Network Map...")
    time.sleep(1)
    try:
        map = networkMapper()  # Create an instance of the network mapper
        map.netmap()    # Plot map
    except KeyboardInterrupt:
        print(Fore.RED + "\n\n[!] Keyboard Interrupt detected. Returning to main menu...\n")
        time.sleep(1)
    except Exception as e:
        print(Fore.RED + f"An error occurred while capturing traffic: {e}")
    finally:
        main_menu()  # Return to the main menu after execution

def main_menu():
    print(Fore.MAGENTA + Style.BRIGHT + "\n################################################################")
    print(Fore.CYAN + Style.BRIGHT + "# EECS 4480 Project - Network Intrusion Toolkit                #")
    print(Fore.CYAN + "# By: Jacob Medeiros 217248824                                 #")
    print(Fore.MAGENTA + "################################################################")
    print(Fore.YELLOW + Style.BRIGHT + """
    [1] Capture Network Traffic
    [2] Run a MiTM Attack
    [3] Map a Network Topology with a given pcap file
    [4] Exit
    """)
    
    try:
        choice = input(Fore.CYAN + Style.BRIGHT + "Enter your choice (1-4): ")
        if choice == '1':
            call_scan()
        elif choice == '2':
            call_mitm()
        elif choice == '3':
            call_networkmap()
        elif choice == '4':
            print(Fore.RED + Style.BRIGHT + "\nExiting... Goodbye!")
            sys.exit(0)
        else:
            print(Fore.RED + "\nInvalid choice! Please try again.")
            main_menu()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    print_header("WELCOME TO NETWORK INTRUSION TOOLKIT", "=")
    main_menu()
