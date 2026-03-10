#!/usr/bin/env python3
import pcapy
import struct
import socket
import time
import threading

# -------------------------------
# Configuration
# -------------------------------
INTERFACES = ["lo", "wlp0s20f3"]  # monitor loopback + Wi-Fi
TCP_TIMEOUT = 3.0  # seconds for SYN tracking

# -------------------------------
# SYN tracking table for TCP failures
# Key: (dst_ip, dst_port), Value: timestamp of SYN sent
syn_table = {}
lock = threading.Lock()

# -------------------------------
# Helpers
# -------------------------------
def get_ip_offset(packet, datalink):
    if datalink == 1:  # Ethernet
        return 14
    elif datalink == 113:  # Linux cooked capture
        return 16
    elif datalink == 127:  # Radiotap
        radiotap_len = packet[2] + (packet[3] << 8)
        return radiotap_len
    return None

def parse_ip_header(packet, ip_offset):
    ip_header = packet[ip_offset:ip_offset+20]
    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
    protocol = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])
    return protocol, src_ip, dst_ip

def parse_tcp_header(packet, tcp_offset):
    tcp_header = packet[tcp_offset:tcp_offset+20]
    tcph = struct.unpack("!HHLLBBHHH", tcp_header)
    src_port = tcph[0]
    dst_port = tcph[1]
    flags = tcph[5]
    return src_port, dst_port, flags

def parse_icmp_header(packet, icmp_offset):
    icmph = struct.unpack("!BBH", packet[icmp_offset:icmp_offset+4])
    icmp_type, icmp_code = icmph[0], icmph[1]
    return icmp_type, icmp_code

def parse_udp_header(packet, udp_offset):
    udph = struct.unpack("!HHHH", packet[udp_offset:udp_offset+8])
    src_port, dst_port, length, checksum = udph
    return src_port, dst_port

def parse_dns_rcode(packet, udp_offset):
    # DNS header starts after UDP header (8 bytes)
    dns_header_offset = udp_offset + 8
    if len(packet) < dns_header_offset + 12:
        return None
    dns_header = struct.unpack("!HHHHHH", packet[dns_header_offset:dns_header_offset+12])
    flags = dns_header[1]
    rcode = flags & 0x000F
    return rcode

# -------------------------------
# Packet processing
# -------------------------------
def process_packet(packet, datalink):
    ip_offset = get_ip_offset(packet, datalink)
    if ip_offset is None:
        return

    protocol, src_ip, dst_ip = parse_ip_header(packet, ip_offset)

    # ICMP
    if protocol == 1:
        icmp_offset = ip_offset + 20
        icmp_type, icmp_code = parse_icmp_header(packet, icmp_offset)
        if icmp_type == 3:
            print(f"[ICMP] Destination unreachable: {src_ip} -> {dst_ip}, code={icmp_code}")
        elif icmp_type == 11:
            print(f"[ICMP] TTL exceeded: {src_ip} -> {dst_ip}")

    # TCP
    elif protocol == 6:
        tcp_offset = ip_offset + 20
        src_port, dst_port, flags = parse_tcp_header(packet, tcp_offset)
        syn_flag = (flags & 0x02) != 0
        ack_flag = (flags & 0x10) != 0
        rst_flag = (flags & 0x04) != 0

        key = (src_ip, dst_ip, dst_port)

        if syn_flag and not ack_flag:
            with lock:
                syn_table[key] = time.time()
        elif syn_flag and ack_flag:
            with lock:
                rev_key = (dst_ip, src_ip, src_port)
                if rev_key in syn_table:
                    del syn_table[rev_key]
                    print(f"[TCP] Connection established: {dst_ip}:{dst_port}")
        elif rst_flag:
            print(f"[TCP] RST received: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

    # UDP (DNS)
    elif protocol == 17:
        udp_offset = ip_offset + 20
        src_port, dst_port = parse_udp_header(packet, udp_offset)
        if src_port == 53 or dst_port == 53:
            rcode = parse_dns_rcode(packet, udp_offset)
            if rcode is not None:
                if rcode == 0:
                    print(f"[DNS] Success: {src_ip} -> {dst_ip}")
                else:
                    print(f"[DNS] Failure (RCODE={rcode}): {src_ip} -> {dst_ip}")

# -------------------------------
# Capture thread per interface
# -------------------------------
def capture_interface(iface):
    cap = pcapy.open_live(iface, 65536, 1, 100)
    datalink = cap.datalink()
    while True:
        try:
            (header, packet) = cap.next()
            process_packet(packet, datalink)
        except Exception:
            continue

# -------------------------------
# SYN timeout checker
# -------------------------------
def syn_timeout_checker():
    while True:
        now = time.time()
        with lock:
            expired = []
            for key, ts in syn_table.items():
                if now - ts > TCP_TIMEOUT:
                    src_ip, dst_ip, dst_port = key
                    print(f"[TCP] Connection failure (no SYN-ACK): {src_ip} -> {dst_ip}:{dst_port}")
                    expired.append(key)
            for key in expired:
                del syn_table[key]
        time.sleep(0.5)

# -------------------------------
# Main
# -------------------------------
def main():
    threads = []
    for iface in INTERFACES:
        t = threading.Thread(target=capture_interface, args=(iface,))
        t.daemon = True
        t.start()
        threads.append(t)

    t_checker = threading.Thread(target=syn_timeout_checker)
    t_checker.daemon = True
    t_checker.start()
    threads.append(t_checker)

    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()