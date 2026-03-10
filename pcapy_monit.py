import pcapy
import struct
import socket
import time
import threading

# -----------------------------
# CONFIG
# -----------------------------
CAPTURE_INTERVAL = 10  # seconds between metric prints
FILTER = "icmp or tcp or udp port 53"  # capture relevant traffic

# Metrics dictionary
metrics = {
    "icmp_unreachable": 0,
    "icmp_ttl_exceeded": 0,
    "tcp_rst": 0,
    "dns_noerror": 0,
    "dns_nxdomain": 0
}

metrics_lock = threading.Lock()

# -----------------------------
# PACKET PARSING FUNCTION
# -----------------------------
def parse_packet(header, packet):
    eth_length = 14
    if len(packet) < eth_length + 20:
        return  # skip malformed packets

    # Ethernet header
    eth_header = packet[:eth_length]
    eth = struct.unpack("!6s6sH", eth_header)
    eth_protocol = socket.ntohs(eth[2])

    # Only IP
    if eth_protocol != 8:
        return

    # IP header
    ip_header = packet[eth_length:eth_length+20]
    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
    protocol = iph[6]

    # ---------------- ICMP ----------------
    if protocol == 1:
        icmp_offset = eth_length + 20
        if len(packet) < icmp_offset + 4:
            return
        icmp_header = packet[icmp_offset:icmp_offset+4]
        icmp_type, icmp_code, _, _ = struct.unpack("!BBH", icmp_header)
        with metrics_lock:
            if icmp_type == 3:
                metrics["icmp_unreachable"] += 1
            elif icmp_type == 11:
                metrics["icmp_ttl_exceeded"] += 1

    # ---------------- TCP ----------------
    elif protocol == 6:
        tcp_offset = eth_length + 20
        if len(packet) < tcp_offset + 20:
            return
        tcp_header = packet[tcp_offset:tcp_offset+20]
        tcph = struct.unpack("!HHLLBBHHH", tcp_header)
        flags = tcph[5]
        with metrics_lock:
            if flags & 0x04:  # RST flag
                metrics["tcp_rst"] += 1

    # ---------------- UDP (DNS) ----------------
    elif protocol == 17:
        udp_offset = eth_length + 20
        if len(packet) < udp_offset + 8 + 12:
            return
        udp_header = packet[udp_offset:udp_offset+8]
        src_port, dst_port, _, _ = struct.unpack("!HHHH", udp_header)
        if src_port == 53 or dst_port == 53:
            dns_offset = udp_offset + 8
            dns_header = packet[dns_offset:dns_offset+12]
            if len(dns_header) < 4:
                return
            transaction_id, flags = struct.unpack("!HH", dns_header[:4])
            qr = (flags >> 15) & 0x1  # 1=response,0=query
            rcode = flags & 0xF        # 0=NOERROR,3=NXDOMAIN
            with metrics_lock:
                if qr == 1 and rcode == 0:
                    metrics["dns_noerror"] += 1
                elif qr == 1 and rcode == 3:
                    metrics["dns_nxdomain"] += 1

# -----------------------------
# CAPTURE LOOP PER INTERFACE
# -----------------------------
def capture_loop(interface):
    try:
        cap = pcapy.open_live(interface, 65536, 1, 100)
        cap.setfilter(FILTER)
    except Exception as e:
        print(f"Failed to open interface {interface}: {e}")
        return

    while True:
        try:
            header, packet = cap.next()
            if packet:
                parse_packet(header, packet)
        except Exception:
            continue

# -----------------------------
# METRICS PRINTING LOOP
# -----------------------------
def print_metrics_loop():
    while True:
        time.sleep(CAPTURE_INTERVAL)
        with metrics_lock:
            print(f"--- Last {CAPTURE_INTERVAL}s ---")
            print(f"ICMP Unreachable : {metrics['icmp_unreachable']}")
            print(f"ICMP TTL Exceeded: {metrics['icmp_ttl_exceeded']}")
            print(f"TCP RST          : {metrics['tcp_rst']}")
            #print(f"DNS NOERROR      : {metrics['dns_noerror']}")
            print(f"DNS NXDOMAIN     : {metrics['dns_nxdomain']}")
            print("-------------------------------")
            # reset counters for next interval
            for key in metrics:
                metrics[key] = 0

# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":
    interfaces = pcapy.findalldevs()
    print("Monitoring interfaces:", interfaces)

    # Start capture thread per interface
    for iface in interfaces:
        t = threading.Thread(target=capture_loop, args=(iface,), daemon=True)
        t.start()

    # Start metrics reporting loop
    print_metrics_loop()