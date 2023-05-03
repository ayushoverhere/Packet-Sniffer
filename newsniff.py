# import required modules
import sys
from scapy.all import *
from scapy.layers.http import HTTPRequest  # import HTTP packet
from colorama import init, Fore
import pyfiglet

# initialize colorama
init()
# define colors
GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET
BLUE = Fore.BLUE

# print banner
ascii_banner = pyfiglet.figlet_format("Packet Sniffer!")
print(ascii_banner)
print(f''' {BLUE}                     https://github.com/ayushoverhere/Packet-Sniffer
+ -- --=[ packet sniffer v0.2-dev                                                                       ]
+ -- --=[ packet filter - tcp, udp, ftp , ssh and so on                                                 ]
+ -- --=[ records visited websites,and print POST raw data, such as passwords, search queries, etc      ]
+ -- --=[ coded by: Ayush, Naman, Tripti and Kuldeep                                                    ]
''')

print("")

# print menu
print("Menu")
print("1: Packet Filter")
print("2: Record Visited Websites and Print POST Raw Data")
print("3: Generate Fake Packets")
print("4: Quit Program")

# get user input
ch = input("Enter your choice: ")

# handle user input
if ch == "1":
    # get filter input from user
    val = input("Enter your filter: ")
    # define callback function to print raw packet
    def packet_callback(packet):
        print(packet.show())
    # sniff packets and call packet_callback for each packet
    sniff(filter=val, prn=packet_callback, store=0)

elif ch == "2":
    # define function to sniff packets on port 80
    def sniff_packets(iface=None):
        """
        Sniff 80 port packets with `iface`, if None (default), then the
        Scapy's default interface is used
        """
        if iface:
            # sniff with specified interface
            sniff(filter="port 80", prn=process_packet, iface=iface, store=False)
        else:
            # sniff with default interface
            sniff(filter="port 80", prn=process_packet, store=False)

    # define function to process HTTP packets and print relevant information
    def process_packet(packet):
        """
        This function is executed whenever a packet is sniffed
        """
        if packet.haslayer(HTTPRequest):
            # if this packet is an HTTP Request
            # get the requested URL
            url = packet[HTTPRequest].Host.decode(
            ) + packet[HTTPRequest].Path.decode()
            # get the requester's IP Address
            ip = packet[IP].src
            # get the request method
            method = packet[HTTPRequest].Method.decode()
            print(f"\n{GREEN}[+] {ip} Requested {url} with {method}{RESET}")
            if packet.haslayer(Raw) and method == "POST":
                # if show_raw flag is enabled, has raw data, and the requested method is "POST"
                # then show raw
                print(
                    f"\n{RED}[*] Some useful Raw data: {packet[Raw].load}{RESET}")

    # start sniffing packets and processing them
    sniff_packets()
    
if (ch == "3"):
    # get the source IP address
    src_ip = input("Enter source IP address: ")
    # get the destination IP address
    dst_ip = input("Enter destination IP address: ")
    # get the source port number
    src_port = int(input("Enter source port number: "))
    # get the destination port number
    dst_port = int(input("Enter destination port number: "))
    # create a fake packet
    fake_packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port)
    # send the fake packet
    send(fake_packet)
    print("Fake packet sent!")
    # Show the fake packet
    print("\nFake packet:")
    fake_packet.show()

if (ch == "4"):
    # Exit the program
    sys.exit("Aborting...")
