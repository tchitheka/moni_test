import pcapy
import struct
import socket
import threading
import time
import sys

from prometheus_client import start_http_server, Counter

# =============================
# CONFIG
# =============================
INTERFACE = "enp1s0"   # change if needed
SNAPLEN = 128             # increased for safer parsing
PROM_PORT = 8001

# =============================
# PROMETHEUS METRIC
# =============================
tcp_rst_total = Counter(
    'tcp_rst_total',
    'Total number of TCP packets with RST flag'
)

# =============================
# HELPER
# =============================
def is_local(ip):
    return ip.startswith("192.168") or ip.startswith("10.") or ip.startswith("172.")

# =============================
# PACKET PARSER
# =============================
def parse_packet(packet):
    eth_length = 14

    if len(packet) < eth_length + 20:
        return

    try:
        # Ethernet header
        eth_header = packet[:eth_length]
        eth = struct.unpack("!6s6sH", eth_header)
        eth_protocol = socket.ntohs(eth[2])

        # Only IPv4
        if eth_protocol != 8:
            return

        # IP header
        ip_header = packet[eth_length:eth_length+20]
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

        protocol = iph[6]
        if protocol != 6:
            return  # Not TCP

        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])

        ip_header_length = (iph[0] & 0xF) * 4
        tcp_offset = eth_length + ip_header_length

        if len(packet) < tcp_offset + 20:
            return

        # TCP header
        tcp_header = packet[tcp_offset:tcp_offset+20]
        tcph = struct.unpack("!HHLLBBHHH", tcp_header)

        src_port = tcph[0]
        dst_port = tcph[1]
        flags = tcph[5]

        # =============================
        # RST DETECTION
        # =============================
        if flags & 0x04:
            tcp_rst_total.inc()

            # Determine direction
            if is_local(src_ip):
                direction = "OUTGOING"
            elif is_local(dst_ip):
                direction = "INCOMING"
            else:
                direction = "UNKNOWN"

            timestamp = time.strftime("%H:%M:%S")

            print(
                f"[{timestamp}] [RST {direction}] "
                f"{src_ip}:{src_port} → {dst_ip}:{dst_port}",
                flush=True
            )

    except Exception as e:
        print(f"Parse error: {e}", file=sys.stderr, flush=True)


# =============================
# CAPTURE LOOP
# =============================
def capture_loop():
    try:
        cap = pcapy.open_live(INTERFACE, SNAPLEN, 1, 100)
        cap.setfilter("tcp")
        print(f"Capturing on interface: {INTERFACE}", flush=True)
    except Exception as e:
        print(f"Error opening interface: {e}", flush=True)
        return

    while True:
        try:
            _, packet = cap.next()
            if packet:
                parse_packet(packet)
        except Exception as e:
            print(f"Capture error: {e}", flush=True)


# =============================
# MAIN
# =============================
if __name__ == "__main__":
    start_http_server(PROM_PORT)
    print(f"TCP RST exporter running on :{PROM_PORT}/metrics", flush=True)

    threading.Thread(target=capture_loop, daemon=True).start()

    while True:
        time.sleep(1)