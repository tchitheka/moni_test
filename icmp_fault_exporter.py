#!/usr/bin/env python3

import pcapy
import struct
import socket
import threading
import time
from collections import defaultdict
from prometheus_client import start_http_server, Counter, Gauge

# ============================================
# CONFIGURATION
# ============================================
#enp1s0
#wlp0s20f3
INTERFACE = "enp1s0"   # <-- CHANGE THIS to your LAN interface
PROM_PORT = 8002

# ============================================
# PROMETHEUS METRICS
# ============================================

# --- General ICMP traffic ---
icmp_packets_total = Counter(
    "icmp_packets_total",
    "Total ICMP packets observed"
)

icmp_echo_request_total = Counter(
    "icmp_echo_request_total",
    "ICMP echo request packets observed"
)

icmp_echo_reply_total = Counter(
    "icmp_echo_reply_total",
    "ICMP echo reply packets observed"
)

# --- ICMP fault counters ---
icmp_network_unreachable_total = Counter(
    "icmp_network_unreachable_total",
    "ICMP destination network unreachable events"
)

icmp_host_unreachable_total = Counter(
    "icmp_host_unreachable_total",
    "ICMP destination host unreachable events"
)

icmp_protocol_unreachable_total = Counter(
    "icmp_protocol_unreachable_total",
    "ICMP destination protocol unreachable events"
)

icmp_port_unreachable_total = Counter(
    "icmp_port_unreachable_total",
    "ICMP destination port unreachable events"
)

icmp_fragmentation_needed_total = Counter(
    "icmp_fragmentation_needed_total",
    "ICMP fragmentation needed events"
)

icmp_source_route_failed_total = Counter(
    "icmp_source_route_failed_total",
    "ICMP source route failed events"
)

icmp_redirect_total = Counter(
    "icmp_redirect_total",
    "ICMP redirect messages observed"
)

icmp_ttl_exceeded_total = Counter(
    "icmp_ttl_exceeded_total",
    "ICMP TTL exceeded messages observed"
)

icmp_parameter_problem_total = Counter(
    "icmp_parameter_problem_total",
    "ICMP parameter problem messages observed"
)

# --- Per-host visibility ---
host_icmp_packets = Gauge(
    "host_icmp_packets",
    "Observed ICMP packet count per source host",
    ["src_ip"]
)

host_icmp_faults = Gauge(
    "host_icmp_faults",
    "Observed ICMP fault count per source host",
    ["src_ip"]
)

# --- Dashboard summary gauges ---
network_health_score = Gauge(
    "network_health_score",
    "Simple ICMP-based network health score (0-100)"
)

active_fault_hosts = Gauge(
    "active_fault_hosts",
    "Number of hosts currently associated with observed ICMP faults"
)

# ============================================
# STATE
# ============================================

traffic_counter = defaultdict(int)
fault_counter = defaultdict(int)

lock = threading.Lock()

# ============================================
# HELPERS
# ============================================

def ip_to_str(raw):
    return socket.inet_ntoa(raw)

def inc_fault(src_ip):
    fault_counter[src_ip] += 1
    host_icmp_faults.labels(src_ip=src_ip).set(fault_counter[src_ip])

def update_health():
    """
    Lightweight health score based only on ICMP faults.
    Tune weights later if needed for your thesis.
    """
    score = 100

    score -= min(15, icmp_network_unreachable_total._value.get() * 2)
    score -= min(20, icmp_host_unreachable_total._value.get() * 2)
    score -= min(10, icmp_port_unreachable_total._value.get())
    score -= min(10, icmp_fragmentation_needed_total._value.get())
    score -= min(15, icmp_redirect_total._value.get())
    score -= min(20, icmp_ttl_exceeded_total._value.get() * 2)
    score -= min(10, icmp_parameter_problem_total._value.get())

    if score < 0:
        score = 0

    network_health_score.set(score)
    active_fault_hosts.set(len([ip for ip, count in fault_counter.items() if count > 0]))

def health_updater():
    while True:
        with lock:
            update_health()
        time.sleep(2)

# ============================================
# ICMP PARSER
# ============================================

def parse_icmp(ip_payload, src_ip, dst_ip):
    """
    Parse ICMP packet from IP payload.
    """
    icmp_packets_total.inc()

    if len(ip_payload) < 8:
        return

    icmp_type, icmp_code, checksum = struct.unpack("!BBH", ip_payload[:4])

    # ============================================
    # Successful ICMP traffic
    # ============================================

    if icmp_type == 8 and icmp_code == 0:
        icmp_echo_request_total.inc()

    elif icmp_type == 0 and icmp_code == 0:
        icmp_echo_reply_total.inc()

    # ============================================
    # Fault ICMP traffic
    # ============================================

    elif icmp_type == 3:   # Destination Unreachable

        if icmp_code == 0:
            icmp_network_unreachable_total.inc()
            inc_fault(src_ip)

        elif icmp_code == 1:
            icmp_host_unreachable_total.inc()
            inc_fault(src_ip)

        elif icmp_code == 2:
            icmp_protocol_unreachable_total.inc()
            inc_fault(src_ip)

        elif icmp_code == 3:
            icmp_port_unreachable_total.inc()
            inc_fault(src_ip)

        elif icmp_code == 4:
            icmp_fragmentation_needed_total.inc()
            inc_fault(src_ip)

        elif icmp_code == 5:
            icmp_source_route_failed_total.inc()
            inc_fault(src_ip)

    elif icmp_type == 5:   # Redirect
        icmp_redirect_total.inc()
        inc_fault(src_ip)

    elif icmp_type == 11 and icmp_code == 0:   # TTL exceeded
        icmp_ttl_exceeded_total.inc()
        inc_fault(src_ip)

    elif icmp_type == 12:  # Parameter problem
        icmp_parameter_problem_total.inc()
        inc_fault(src_ip)

# ============================================
# IPv4 PARSER
# ============================================

def parse_ipv4(data):
    """
    Parse IPv4 packet and extract ICMP if present.
    """
    if len(data) < 34:
        return

    # Ethernet header = 14 bytes
    ip_header = data[14:34]

    version_ihl = ip_header[0]
    ihl = (version_ihl & 0x0F) * 4
    proto = ip_header[9]

    src_ip = ip_to_str(ip_header[12:16])
    dst_ip = ip_to_str(ip_header[16:20])

    # Track per-host ICMP traffic
    traffic_counter[src_ip] += 1
    host_icmp_packets.labels(src_ip=src_ip).set(traffic_counter[src_ip])

    ip_payload = data[14 + ihl:]

    # Only ICMP
    if proto == 1:
        parse_icmp(ip_payload, src_ip, dst_ip)

# ============================================
# PACKET PROCESSOR
# ============================================

def process_packet(header, data):
    if len(data) < 14:
        return

    eth_type = struct.unpack("!H", data[12:14])[0]

    with lock:
        if eth_type == 0x0800:  # IPv4
            parse_ipv4(data)

# ============================================
# MAIN
# ============================================

def main():
    print(f"[*] Starting ICMP passive fault exporter on interface: {INTERFACE}")
    print(f"[*] Prometheus metrics available at: http://localhost:{PROM_PORT}/metrics")

    # Start Prometheus HTTP exporter
    start_http_server(PROM_PORT)

    # Start health updater thread
    t = threading.Thread(target=health_updater, daemon=True)
    t.start()

    # Open capture
    cap = pcapy.open_live(INTERFACE, 65536, 1, 100)

    # Capture ONLY ICMP for lightweight operation
    cap.setfilter("icmp")

    while True:
        try:
            header, packet = cap.next()

            if packet:
                process_packet(header, packet)

        except KeyboardInterrupt:
            print("\n[!] Stopped.")
            break

        except Exception as e:
            print(f"[WARN] {e}")
            continue

if __name__ == "__main__":
    main()