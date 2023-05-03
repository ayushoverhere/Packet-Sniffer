from scapy.all import sniff

val = input("Enter your filter: ")
def packet_callback(packet):
	print(packet.show())


def main():
   	sniff(filter=val, prn=packet_callback, store=0)

if __name__ == '__main__':
	main()
