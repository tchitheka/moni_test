import subprocess
import time
import threading
import pcapy
import struct
import socket
import ipaddress
from collections import defaultdict, deque

from prometheus_client import start_http_server, Gauge, Counter, Histogram

# =============================
# Prometheus Metrics
# =============================
internet_status = Gauge('internet_connectivity_status', 'Internet connectivity (1=UP, 0=DOWN)')
internet_latency = Gauge('internet_check_latency_seconds', 'Latency to reach google.com')

internet_rtt_seconds = Histogram(
    'internet_rtt_seconds',
    'RTT latency across multiple targets',
    buckets=[
        0.05, 0.1, 0.15, 0.2, 0.25,
        0.3, 0.35, 0.4, 0.45, 0.5,
        0.75, 1.0, 2.0, 3.0, 5.0, 10.0
    ]
)

rtt_failures_total = Counter('rtt_failures_total', 'Total RTT failures')

lan_devices_total = Gauge('lan_devices_total', 'Active LAN devices')
device_flaps_total = Counter('device_flaps_total', 'Device flap events')

#Device last seen
device_last_seen_timestamp = Gauge(
    'device_last_seen_timestamp',
    'Last time a device was seen (epoch time)',
    ['mac', 'ip']
)

# Per-device flap counter (MAC + IP)
device_flaps_by_mac_total = Counter(
    'device_flaps_by_mac_total',
    'Flap events per LAN device',
    ['mac', 'ip']
)

# Per-device visibility
device_seen_by_mac = Gauge(
    'device_seen_by_mac',
    'Whether a LAN device is currently active (1=active, 0=inactive)',
    ['mac', 'ip']
)

# Per-device last flap timestamp
device_last_flap_timestamp_seconds = Gauge(
    'device_last_flap_timestamp_seconds',
    'Last flap timestamp per LAN device',
    ['mac', 'ip']
)

# =============================
# DNS METRICS
# =============================
dns_errors_total = Counter('dns_errors_total', 'DNS NXDOMAIN errors')
dns_success_total = Counter('dns_success_total', 'DNS successful responses')

# Drill-down DNS metrics
dns_queries_by_domain_total = Counter(
    'dns_queries_by_domain_total',
    'DNS queries observed per domain',
    ['domain']
)

dns_nxdomain_by_domain_total = Counter(
    'dns_nxdomain_by_domain_total',
    'DNS NXDOMAIN responses observed per domain',
    ['domain']
)

dns_success_by_domain_total = Counter(
    'dns_success_by_domain_total',
    'DNS successful responses observed per domain',
    ['domain']
)

# =============================
# Passive TCP metrics
# =============================
tcp_rst_errors_total = Counter(
    'tcp_rst_errors_total',
    'Total TCP packets observed with the RST flag (passive monitoring)'
)

tcp_syn_total = Counter(
    'tcp_syn_total',
    'Total initial TCP SYN packets observed (passive TCP connection attempts)'
)

# =============================
# Throughput metrics
# =============================
network_rx_bps = Gauge('network_rx_bps', 'Receive throughput (bits per second)', ['interface'])
network_tx_bps = Gauge('network_tx_bps', 'Transmit throughput (bits per second)', ['interface'])

# =============================
# ICMP Metrics
# =============================

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

# =============================
# UPDATED PER-HOST METRICS
# =============================
host_icmp_packets_total = Counter(
    "host_icmp_packets_total",
    "Total ICMP packets observed per source host",
    ["src_ip"]
)

host_icmp_faults_total = Counter(
    "host_icmp_faults_total",
    "Total ICMP fault events observed per source and destination",
    ["src_ip", "dst_ip", "fault_type"]  
)

# =============================
# Dashboard summary gauges
# =============================
network_health_score = Gauge(
    "network_health_score",
    "Simple ICMP-based network health score (0-100)"
)

active_fault_hosts = Gauge(
    "active_fault_hosts",
    "Number of source hosts that have ever been associated with observed ICMP faults since exporter start"
)

# =============================
# Config
# =============================
CHECK_INTERVAL = 5
ARP_CAPTURE_DURATION = 5
DEVICE_TIMEOUT = 12
FLAP_WINDOW = 60
CLEANUP_INTERVAL = 3600  # 1 hour
DEVICE_STALE_TIMEOUT = 86400  # 24 hours

# enp1s0 / wlp0s20f3
INTERFACE = "enp1s0"

STATIC_TARGETS = [("8.8.8.8", 53), ("1.1.1.1", 53)]

TOP_N = 5
DOMAIN_WINDOW = 300
UPDATE_INTERVAL = 300

# =============================
# Global State
# =============================

# MAC -> {
#   "last_seen": ts,
#   "ip": "...",
#   "online": True/False,
#   "last_offline": ts_or_None
# }
device_state = {}

domain_counts = defaultdict(int)
domain_timestamps = deque()
dynamic_targets = []

throughput_prev = {}

# ICMP state (used only for exporter-side summaries)
traffic_counter = defaultdict(int)
fault_counter = defaultdict(int)

# ICMP health score state
icmp_fault_totals = {
    "network_unreachable": 0,
    "host_unreachable": 0,
    "protocol_unreachable": 0,
    "port_unreachable": 0,
    "fragmentation_needed": 0,
    "source_route_failed": 0,
    "redirect": 0,
    "ttl_exceeded": 0,
    "parameter_problem": 0,
}

lock = threading.Lock()

# =============================
# Helper function to check if IP is private/local
# =============================
def is_private_ip(ip_str):
    """Check if an IP address is private/local (RFC 1918, loopback, link-local)"""
    try:
        ip = ipaddress.ip_address(ip_str)
        
        # Check for private IP ranges
        if ip.is_private:
            return True
        
        # Additional check for common local ranges not caught by is_private
        if ip.is_loopback:
            return True
        
        if ip.is_link_local:
            return True
        
        # Check for specific private ranges (redundant but explicit)
        private_ranges = [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '169.254.0.0/16',  # Link-local
            '127.0.0.0/8',     # Loopback
        ]
        
        for cidr in private_ranges:
            if ip in ipaddress.ip_network(cidr):
                return True
                
        return False
    except:
        # If we can't parse the IP, assume it's not private
        return False

# =============================
# THROUGHPUT FUNCTION
# =============================
def get_bytes(interface):
    try:
        with open("/proc/net/dev") as f:
            for line in f:
                if line.strip().startswith(interface + ":"):
                    data = line.split()
                    return int(data[1]), int(data[9])  # RX bytes, TX bytes
    except:
        pass
    return None, None

def throughput_monitor():
    global throughput_prev

    rx, tx = get_bytes(INTERFACE)
    if rx is None:
        print(f"Could not read /proc/net/dev for {INTERFACE}")
        return

    throughput_prev[INTERFACE] = (rx, tx)

    while True:
        time.sleep(CHECK_INTERVAL)

        rx1, tx1 = throughput_prev[INTERFACE]
        rx2, tx2 = get_bytes(INTERFACE)

        if rx2 is None:
            continue

        rx_rate = max(0, (rx2 - rx1) * 8 / CHECK_INTERVAL)
        tx_rate = max(0, (tx2 - tx1) * 8 / CHECK_INTERVAL)

        network_rx_bps.labels(interface=INTERFACE).set(rx_rate)
        network_tx_bps.labels(interface=INTERFACE).set(tx_rate)

        throughput_prev[INTERFACE] = (rx2, tx2)

# =============================
# RTT Functions (ACTIVE)
# =============================
def tcp_rtt(host, port):
    start = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=2)
        sock.close()
        return time.time() - start
    except:
        return None

def probe_target(host, port):
    rtt = tcp_rtt(host, port)

    if rtt is not None:
        internet_rtt_seconds.observe(rtt)
    else:
        rtt_failures_total.inc()

def latency_monitor():
    while True:
        with lock:
            targets = STATIC_TARGETS + dynamic_targets

        threads = []
        for host, port in targets:
            t = threading.Thread(target=probe_target, args=(host, port))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        time.sleep(2)

# =============================
# Internet Check
# =============================
def check_internet():
    start_time = time.time()
    try:
        result = subprocess.run(
            ["wget", "-q", "--spider", "--server-response", "https://www.google.com"],
            stderr=subprocess.PIPE,
            timeout=5
        )

        latency = time.time() - start_time
        internet_latency.set(latency)

        return 1 if "200 OK" in result.stderr.decode() else 0
    except:
        internet_latency.set(0)
        return 0

# =============================
# Cleanup stale devices
# =============================
def cleanup_stale_devices():
    """Remove device metrics that haven't been seen for a long time"""
    while True:
        time.sleep(CLEANUP_INTERVAL)
        now = time.time()
        
        with lock:
            stale_macs = []
            for mac, info in device_state.items():
                if now - info["last_seen"] > DEVICE_STALE_TIMEOUT:
                    stale_macs.append(mac)
            
            for mac in stale_macs:
                ip = device_state[mac].get("ip", "unknown")
                print(f"[CLEANUP] Removing stale device {mac} ({ip}) - not seen for {DEVICE_STALE_TIMEOUT/3600:.0f} hours")
                
                try:
                    # Remove from Prometheus metrics
                    device_seen_by_mac.remove(mac=mac, ip=ip)
                    device_last_seen_timestamp.remove(mac=mac, ip=ip)
                    device_flaps_by_mac_total.remove(mac=mac, ip=ip)
                    device_last_flap_timestamp_seconds.remove(mac=mac, ip=ip)
                except Exception as e:
                    print(f"Error removing metrics for {mac}: {e}")
                
                # Remove from state
                del device_state[mac]

# =============================
# ARP & IP Monitoring (FIXED - Now captures both ARP and IP traffic with IP filtering)
# =============================
def discover_lan_devices():
    global device_state
    
    try:
        # Capture both ARP and IP packets to detect active communication
        cap = pcapy.open_live(INTERFACE, 96, 1, 100)
        cap.setfilter("arp or ip")
    except Exception as e:
        print(f"LAN monitor failed to start: {e}")
        return 0

    start_time = time.time()
    devices_seen_this_cycle = set()  # Track devices seen in this cycle

    while time.time() - start_time < ARP_CAPTURE_DURATION:
        try:
            _, packet = cap.next()
            if not packet or len(packet) < 42:
                continue

            eth_type = struct.unpack("!H", packet[12:14])[0]
            
            sender_mac = None
            sender_ip = None
            
            # Handle ARP packets
            if eth_type == 0x0806:  # ARP
                arp = struct.unpack("!HHBBH6s4s6s4s", packet[14:42])
                sender_mac = ':'.join('%02x' % b for b in arp[5])
                sender_ip = socket.inet_ntoa(arp[6])
                
                # For ARP packets, only accept private IPs
                if not is_private_ip(sender_ip):
                    continue
            
            # Handle IP packets
            elif eth_type == 0x0800:  # IPv4
                # Extract source MAC from Ethernet header
                eth_header = packet[:14]
                eth = struct.unpack("!6s6sH", eth_header)
                sender_mac = ':'.join('%02x' % b for b in eth[1])  # Source MAC
                
                # Extract source IP from IP header
                ip_start = 14
                if len(packet) >= ip_start + 20:
                    ip_header = packet[ip_start:ip_start + 20]
                    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
                    sender_ip = socket.inet_ntoa(iph[8])  # Source IP
                    
                    # For IP packets, only accept private IPs
                    if not is_private_ip(sender_ip):
                        continue
            
            if not sender_mac or not sender_ip or sender_ip == "0.0.0.0":
                continue
                
            devices_seen_this_cycle.add(sender_mac)
            now = time.time()

            if sender_mac not in device_state:
                device_state[sender_mac] = {
                    "last_seen": now,
                    "ip": sender_ip,
                    "online": True,
                    "last_offline": None
                }
                print(f"[NEW DEVICE] {sender_mac} ({sender_ip}) discovered via {'ARP' if eth_type == 0x0806 else 'IP'} traffic")
                
                # Set the last seen timestamp for new device
                device_last_seen_timestamp.labels(mac=sender_mac, ip=sender_ip).set(now)
            else:
                if device_state[sender_mac]["online"] is False:
                    last_offline = device_state[sender_mac]["last_offline"]

                    if last_offline and (now - last_offline <= FLAP_WINDOW):
                        print(f"[FLAP] {sender_mac} ({sender_ip}) came back online")

                        device_flaps_total.inc()

                        device_flaps_by_mac_total.labels(
                            mac=sender_mac,
                            ip=sender_ip
                        ).inc()

                        # Store last flap time
                        device_last_flap_timestamp_seconds.labels(
                            mac=sender_mac,
                            ip=sender_ip
                        ).set(now)
                
                device_state[sender_mac]["online"] = True
                device_state[sender_mac]["last_offline"] = None
                device_state[sender_mac]["last_seen"] = now
                device_state[sender_mac]["ip"] = sender_ip
                
                # Update the last seen timestamp for existing device
                device_last_seen_timestamp.labels(mac=sender_mac, ip=sender_ip).set(now)

        except Exception:
            continue

    now = time.time()
    active_count = 0

    for mac, info in device_state.items():
        ip = info.get("ip", "unknown")
        
        # Double-check that stored IPs are private
        if ip != "unknown" and not is_private_ip(ip):
            # If somehow a public IP got stored, skip counting it
            continue

        if now - info["last_seen"] > DEVICE_TIMEOUT:
            if info["online"] is True:
                info["online"] = False
                info["last_offline"] = now
                print(f"[OFFLINE] {mac} ({ip}) marked offline")

            device_seen_by_mac.labels(mac=mac, ip=ip).set(0)
            # Note: Don't clear device_last_seen_timestamp, keep the last known time

        else:
            info["online"] = True
            device_seen_by_mac.labels(mac=mac, ip=ip).set(1)
            active_count += 1

    print(f"LAN devices discovered this cycle: {len(devices_seen_this_cycle)}, Active total: {active_count}")
    return active_count

# =============================
# DNS HELPERS (FIXED)
# =============================
def parse_dns_name(payload, offset):
    labels = []
    jumped = False
    original_offset = offset
    max_jumps = 10
    jumps = 0

    while offset < len(payload):
        if jumps > max_jumps:
            break

        length = payload[offset]

        if length == 0:
            offset += 1
            break

        # compression pointer
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(payload):
                break
            pointer = ((length & 0x3F) << 8) | payload[offset + 1]
            if pointer >= len(payload):
                break
            if not jumped:
                original_offset = offset + 2
            offset = pointer
            jumped = True
            jumps += 1
            continue

        offset += 1
        if offset + length > len(payload):
            break

        label = payload[offset:offset + length].decode(errors='ignore')
        labels.append(label)
        offset += length

    domain = ".".join(labels)
    return domain, (original_offset if jumped else offset)

def parse_dns_payload(dns_payload):
    if len(dns_payload) < 12:
        return None, None, None

    try:
        dns = struct.unpack("!HHHHHH", dns_payload[:12])
        flags = dns[1]
        qdcount = dns[2]

        qr = (flags >> 15) & 0x1
        rcode = flags & 0xF

        domain_name = None
        offset = 12

        if qdcount > 0:
            domain_name, offset = parse_dns_name(dns_payload, offset)

        return qr, rcode, domain_name
    except:
        return None, None, None

# =============================
# DNS Monitor (FIXED)
# =============================
def dns_monitor():
    global domain_counts

    try:
        cap = pcapy.open_live(INTERFACE, 65535, 1, 100)
        cap.setfilter("port 53")
    except Exception as e:
        print(f"DNS monitor failed to start: {e}")
        return

    print("DNS monitor started...")

    while True:
        try:
            _, packet = cap.next()
            if not packet or len(packet) < 34:
                continue

            eth_type = struct.unpack("!H", packet[12:14])[0]
            if eth_type != 0x0800:  # IPv4 only
                continue

            ip_start = 14
            if len(packet) < ip_start + 20:
                continue

            ip_header = packet[ip_start:ip_start + 20]
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            protocol = iph[6]
            ihl = (iph[0] & 0x0F) * 4

            if len(packet) < ip_start + ihl:
                continue

            transport_start = ip_start + ihl

            dns_payload = None

            # UDP DNS
            if protocol == 17:
                if len(packet) < transport_start + 8:
                    continue

                udp_header = packet[transport_start:transport_start + 8]
                src_port, dst_port, udp_len, udp_checksum = struct.unpack("!HHHH", udp_header)

                if src_port != 53 and dst_port != 53:
                    continue

                dns_payload = packet[transport_start + 8:]

            # TCP DNS
            elif protocol == 6:
                if len(packet) < transport_start + 20:
                    continue

                tcp_header = packet[transport_start:transport_start + 20]
                tcph = struct.unpack("!HHLLBBHHH", tcp_header)
                src_port = tcph[0]
                dst_port = tcph[1]
                tcp_header_len = ((tcph[4] >> 4) & 0xF) * 4

                if src_port != 53 and dst_port != 53:
                    continue

                if len(packet) < transport_start + tcp_header_len + 2:
                    continue

                tcp_payload = packet[transport_start + tcp_header_len:]

                if len(tcp_payload) < 2:
                    continue

                # TCP DNS has 2-byte length prefix
                dns_length = struct.unpack("!H", tcp_payload[:2])[0]
                if len(tcp_payload) < 2 + dns_length:
                    continue

                dns_payload = tcp_payload[2:2 + dns_length]

            else:
                continue

            if not dns_payload:
                continue

            qr, rcode, domain_name = parse_dns_payload(dns_payload)

            if qr is None:
                continue

            if qr == 1:
                if rcode == 3:
                    dns_errors_total.inc()
                    if domain_name:
                        dns_nxdomain_by_domain_total.labels(domain=domain_name).inc()

                elif rcode == 0:
                    dns_success_total.inc()
                    if domain_name:
                        dns_success_by_domain_total.labels(domain=domain_name).inc()

            elif qr == 0:
                if domain_name:
                    dns_queries_by_domain_total.labels(domain=domain_name).inc()

                    now = time.time()
                    with lock:
                        domain_counts[domain_name] += 1
                        domain_timestamps.append((now, domain_name))

        except Exception:
            continue

# =============================
# PASSIVE TCP Monitor
# =============================
def tcp_monitor():
    try:
        cap = pcapy.open_live(INTERFACE, 128, 1, 100)
        cap.setfilter("tcp")
    except Exception as e:
        print(f"TCP monitor failed to start: {e}")
        return

    print("Passive TCP monitor started...")

    while True:
        try:
            _, packet = cap.next()
            if not packet or len(packet) < 34:
                continue

            eth_length = 14
            eth_header = packet[:eth_length]
            eth = struct.unpack("!6s6sH", eth_header)
            eth_protocol = socket.ntohs(eth[2])

            if eth_protocol != 8:
                continue

            ip_header = packet[eth_length:eth_length+20]
            if len(ip_header) < 20:
                continue

            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

            protocol = iph[6]
            if protocol != 6:
                continue

            ip_header_length = (iph[0] & 0xF) * 4
            tcp_offset = eth_length + ip_header_length

            if len(packet) < tcp_offset + 20:
                continue

            tcp_header = packet[tcp_offset:tcp_offset+20]
            tcph = struct.unpack("!HHLLBBHHH", tcp_header)

            flags = tcph[5]

            syn = flags & 0x02
            ack = flags & 0x10
            rst = flags & 0x04

            if syn and not ack:
                tcp_syn_total.inc()

            if rst:
                tcp_rst_errors_total.inc()

        except:
            continue

# =============================
# ICMP HELPERS
# =============================
def ip_to_str(raw):
    return socket.inet_ntoa(raw)

def inc_fault(src_ip, dst_ip, fault_type):
    fault_counter[src_ip] += 1
    host_icmp_faults_total.labels(
        src_ip=src_ip,
        dst_ip=dst_ip,
        fault_type=fault_type
    ).inc()

def update_health():
    score = 100

    score -= min(15, icmp_fault_totals["network_unreachable"] * 2)
    score -= min(20, icmp_fault_totals["host_unreachable"] * 2)
    score -= min(10, icmp_fault_totals["port_unreachable"])
    score -= min(10, icmp_fault_totals["fragmentation_needed"])
    score -= min(15, icmp_fault_totals["redirect"])
    score -= min(20, icmp_fault_totals["ttl_exceeded"] * 2)
    score -= min(10, icmp_fault_totals["parameter_problem"])

    if score < 0:
        score = 0

    network_health_score.set(score)
    active_fault_hosts.set(len([ip for ip, count in fault_counter.items() if count > 0]))

def health_updater():
    while True:
        with lock:
            update_health()
        time.sleep(2)

# =============================
# ICMP PARSER (FIXED)
# =============================
def parse_icmp(ip_payload, src_ip, dst_ip):
    if len(ip_payload) < 8:
        return

    icmp_packets_total.inc()

    try:
        icmp_type, icmp_code, checksum = struct.unpack("!BBH", ip_payload[:4])
    except:
        return

    # Echo Request
    if icmp_type == 8 and icmp_code == 0:
        icmp_echo_request_total.inc()

    # Echo Reply
    elif icmp_type == 0 and icmp_code == 0:
        icmp_echo_reply_total.inc()

    # Destination Unreachable
    elif icmp_type == 3:
        if icmp_code == 0:
            icmp_network_unreachable_total.inc()
            icmp_fault_totals["network_unreachable"] += 1
            inc_fault(src_ip, dst_ip, "network_unreachable")

        elif icmp_code == 1:
            icmp_host_unreachable_total.inc()
            icmp_fault_totals["host_unreachable"] += 1
            inc_fault(src_ip, dst_ip, "host_unreachable")

        elif icmp_code == 2:
            icmp_protocol_unreachable_total.inc()
            icmp_fault_totals["protocol_unreachable"] += 1
            inc_fault(src_ip, dst_ip, "protocol_unreachable")

        elif icmp_code == 3:
            icmp_port_unreachable_total.inc()
            icmp_fault_totals["port_unreachable"] += 1
            inc_fault(src_ip, dst_ip, "port_unreachable")

        elif icmp_code == 4:
            icmp_fragmentation_needed_total.inc()
            icmp_fault_totals["fragmentation_needed"] += 1
            inc_fault(src_ip, dst_ip, "fragmentation_needed")

        elif icmp_code == 5:
            icmp_source_route_failed_total.inc()
            icmp_fault_totals["source_route_failed"] += 1
            inc_fault(src_ip, dst_ip, "source_route_failed")

    # Redirect
    elif icmp_type == 5:
        icmp_redirect_total.inc()
        icmp_fault_totals["redirect"] += 1
        inc_fault(src_ip, dst_ip, "redirect")

    # TTL exceeded
    elif icmp_type == 11:
        icmp_ttl_exceeded_total.inc()
        icmp_fault_totals["ttl_exceeded"] += 1
        inc_fault(src_ip, dst_ip, "ttl_exceeded")

    # Parameter problem
    elif icmp_type == 12:
        icmp_parameter_problem_total.inc()
        icmp_fault_totals["parameter_problem"] += 1
        inc_fault(src_ip, dst_ip, "parameter_problem")

# =============================
# IPv4 PARSER (ICMP only) - FIXED
# =============================
def parse_ipv4_for_icmp(packet):
    if len(packet) < 34:
        return

    ip_start = 14

    if len(packet) < ip_start + 20:
        return

    ip_header = packet[ip_start:ip_start + 20]

    version_ihl = ip_header[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4

    if version != 4 or ihl < 20:
        return

    if len(packet) < ip_start + ihl:
        return

    proto = ip_header[9]

    src_ip = ip_to_str(ip_header[12:16])
    dst_ip = ip_to_str(ip_header[16:20])

    if proto != 1:
        return

    host_icmp_packets_total.labels(src_ip=src_ip).inc()

    ip_payload = packet[ip_start + ihl:]
    parse_icmp(ip_payload, src_ip, dst_ip)

# =============================
# PASSIVE ICMP Monitor (FIXED)
# =============================
def icmp_monitor():
    try:
        cap = pcapy.open_live(INTERFACE, 65535, 1, 100)
        cap.setfilter("icmp")
    except Exception as e:
        print(f"ICMP monitor failed to start: {e}")
        return

    print("Passive ICMP monitor started...")

    while True:
        try:
            _, packet = cap.next()
            if not packet or len(packet) < 34:
                continue

            eth_type = struct.unpack("!H", packet[12:14])[0]

            if eth_type == 0x0800:  # IPv4
                with lock:
                    parse_ipv4_for_icmp(packet)

        except Exception:
            continue

# =============================
# Dynamic Targets
# =============================
def update_dynamic_targets():
    global dynamic_targets

    while True:
        time.sleep(UPDATE_INTERVAL)
        now = time.time()

        with lock:
            while domain_timestamps and now - domain_timestamps[0][0] > DOMAIN_WINDOW:
                _, old_domain = domain_timestamps.popleft()
                domain_counts[old_domain] -= 1
                if domain_counts[old_domain] <= 0:
                    del domain_counts[old_domain]

            top = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:TOP_N]
            dynamic_targets = [(d, 443) for d, _ in top if len(d) > 3]

# =============================
# Monitoring Threads
# =============================
def internet_monitor():
    while True:
        internet_status.set(check_internet())
        time.sleep(CHECK_INTERVAL)

def lan_monitor():
    while True:
        lan_devices_total.set(discover_lan_devices())
        time.sleep(CHECK_INTERVAL)

# =============================
# MAIN
# =============================
if __name__ == "__main__":
    start_http_server(8000)
    print("Exporter running on :8000")

    threading.Thread(target=internet_monitor, daemon=True).start()
    threading.Thread(target=lan_monitor, daemon=True).start()
    threading.Thread(target=dns_monitor, daemon=True).start()
    threading.Thread(target=latency_monitor, daemon=True).start()
    threading.Thread(target=update_dynamic_targets, daemon=True).start()
    threading.Thread(target=throughput_monitor, daemon=True).start()
    threading.Thread(target=health_updater, daemon=True).start()
    threading.Thread(target=cleanup_stale_devices, daemon=True).start()

    # Passive TCP monitor (RST + SYN)
    threading.Thread(target=tcp_monitor, daemon=True).start()

    # Passive ICMP monitor
    threading.Thread(target=icmp_monitor, daemon=True).start()

    while True:
        time.sleep(1)