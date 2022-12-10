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

ascii_banner = pyfiglet.figlet_format("Packet Sniffer!")

print(ascii_banner)
print(f''' {BLUE}                     https://github.com/ayushoverhere/Packet-Sniffer


+ -- --=[ packet sniffer v0.2-dev                                                                       ]
+ -- --=[ packet filter - tcp, udp, ftp , ssh and so on                                                 ]
+ -- --=[ records visited websites,and print POST raw data, such as passwords, search queries, etc      ]
+ -- --=[ coded by: Ayush, Naman, Tripti and Kuldeep                                                    ]
''')
print("")
print("Menu")
print("1: packet filter")
print("2: record visited websites,,and print POST raw data, such as passwords, search queries, etc")
print("3: to quit this program")
ch = input("Enter your choice: ")
if (ch == "1"):
    val = input("Enter your filter: ")
    # to print raw packet
    def packet_callback(packet):
        print(packet.show())
    # to call for raw packet
    sniff(filter=val, prn=packet_callback, store=0)

if (ch == "2"):

    def sniff_packets(iface=None):
        """
        Sniff 80 port packets with `iface`, if None (default), then the
        Scapy's default interface is used
        """
        if iface:
            # port 80 for http (generally)
            # `process_packet` is the callback
            sniff(filter="port 80", prn=process_packet, iface=iface, store=False)
        else:
            # sniff with default interface
            sniff(filter="port 80", prn=process_packet, store=False)

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

    sniff_packets()
if (ch == "3"):
    sys.exit("Aborting...")
