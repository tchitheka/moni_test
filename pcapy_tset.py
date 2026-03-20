import pcapy as pcap

# Open a live capture on an interface (e.g., 'eth0')
# 65536 is the snaplen (max bytes per packet), 1 for promiscuous mode, 100ms timeout
cap = pcap.open_live('wlp0s20f3', 65536, 1, 100) # Use the appropriate interface name for your system

#print(f"Listening on device {cap.name()}")

# Capture packets in a loop
packet_count = 0
while True:
    (header, packet) = cap.next()
    if header is not None:
        packet_count += 1
        print(f"Packet number {packet_count} captured, length: {header.getlen()}")
