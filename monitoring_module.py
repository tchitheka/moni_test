import subprocess
import time
import threading
import pcapy
import struct
import socket
from collections import defaultdict, deque

from prometheus_client import start_http_server, Gauge, Counter, Histogram

# =============================
# Prometheus Metrics
# =============================
internet_status = Gauge('internet_connectivity_status','Internet connectivity (1=UP, 0=DOWN)')
internet_latency = Gauge('internet_check_latency_seconds','Latency to reach google.com')

internet_rtt_seconds = Histogram(
    'internet_rtt_seconds',
    'RTT latency across multiple targets',
    buckets = [
    0.05,
    0.1,
    0.15,
    0.2,
    0.25,
    0.3,
    0.35,
    0.4,
    0.45,
    0.5,
    0.75,
    1.0,
    2.0
]
)

rtt_failures_total = Counter('rtt_failures_total','Total RTT failures')

lan_devices_total = Gauge('lan_devices_total','Active LAN devices')
device_flaps_total = Counter('device_flaps_total','Device flap events')

dns_errors_total = Counter('dns_errors_total','DNS NXDOMAIN errors')
dns_success_total = Counter('dns_success_total','DNS successful responses')

# =============================
# Config
# =============================
CHECK_INTERVAL = 10
ARP_CAPTURE_DURATION = 10
DEVICE_TIMEOUT = 60
FLAP_WINDOW = 120
INTERFACE = "wlp0s20f3"

# ✅ Static baseline targets (always included)
STATIC_TARGETS = [
    ("8.8.8.8", 53),
    ("1.1.1.1", 53),
]

# Dynamic config
TOP_N = 5
DOMAIN_WINDOW = 300  # 5 minutes
UPDATE_INTERVAL = 300

# =============================
# Global State
# =============================
device_last_seen = {}
device_last_disappeared = {}

# DNS tracking
domain_counts = defaultdict(int)
domain_timestamps = deque()
dynamic_targets = []

lock = threading.Lock()

# =============================
# RTT Functions
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
            ["wget","-q","--spider","--server-response","https://www.google.com"],
            stderr=subprocess.PIPE, timeout=5
        )

        latency = time.time() - start_time
        internet_latency.set(latency)

        return 1 if "200 OK" in result.stderr.decode() else 0
    except:
        internet_latency.set(0)
        return 0

# =============================
# ARP Monitoring
# =============================
def discover_lan_devices():
    global device_last_seen, device_last_disappeared

    try:
        cap = pcapy.open_live(INTERFACE, 65536, 1, 100)
        cap.setfilter("arp")
    except:
        return 0

    start_time = time.time()

    while time.time() - start_time < ARP_CAPTURE_DURATION:
        try:
            _, packet = cap.next()
            if not packet:
                continue

            arp = struct.unpack("!HHBBH6s4s6s4s", packet[14:42])
            mac = ':'.join('%02x' % b for b in arp[5])
            now = time.time()

            if mac in device_last_disappeared:
                if now - device_last_disappeared[mac] <= FLAP_WINDOW:
                    device_flaps_total.inc()
                del device_last_disappeared[mac]

            device_last_seen[mac] = now

        except:
            continue

    now = time.time()
    active = {}

    for mac, ts in device_last_seen.items():
        if now - ts <= DEVICE_TIMEOUT:
            active[mac] = ts
        else:
            device_last_disappeared[mac] = now

    device_last_seen = active
    return len(active)

# =============================
# DNS Monitor (with domain extraction)
# =============================
def dns_monitor():
    global domain_counts

    try:
        cap = pcapy.open_live(INTERFACE, 65536, 1, 100)
        cap.setfilter("udp port 53")
    except:
        return

    print("DNS monitor started...")

    while True:
        try:
            _, packet = cap.next()
            if not packet:
                continue

            ip_header = packet[14:34]
            if len(ip_header) < 20:
                continue

            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            if iph[6] != 17:
                continue

            ip_header_length = (iph[0] & 0xF) * 4
            udp_start = 14 + ip_header_length
            udph = struct.unpack("!HHHH", packet[udp_start:udp_start+8])

            dns_start = udp_start + 8
            dns_header = packet[dns_start:dns_start+12]

            if len(dns_header) < 12:
                continue

            dns = struct.unpack("!HHHHHH", dns_header)
            flags = dns[1]

            qr = (flags >> 15) & 0x1
            rcode = flags & 0xF

            # DNS response stats
            if qr == 1:
                if rcode == 3:
                    dns_errors_total.inc()
                elif rcode == 0:
                    dns_success_total.inc()

            # Extract domain (only queries)
            if qr == 0:
                query_start = dns_start + 12
                domain = []
                i = query_start

                while True:
                    length = packet[i]
                    if length == 0:
                        break
                    i += 1
                    domain.append(packet[i:i+length].decode(errors='ignore'))
                    i += length

                domain_name = ".".join(domain)

                now = time.time()
                with lock:
                    domain_counts[domain_name] += 1
                    domain_timestamps.append((now, domain_name))

        except:
            continue

# =============================
# Dynamic Target Updater
# =============================
def update_dynamic_targets():
    global dynamic_targets

    while True:
        time.sleep(UPDATE_INTERVAL)
        now = time.time()

        with lock:
            # Remove old entries
            while domain_timestamps and now - domain_timestamps[0][0] > DOMAIN_WINDOW:
                _, old_domain = domain_timestamps.popleft()
                domain_counts[old_domain] -= 1
                if domain_counts[old_domain] <= 0:
                    del domain_counts[old_domain]

            # Get top domains
            top = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:TOP_N]

            dynamic_targets = [(d, 443) for d, _ in top if len(d) > 3]

            print("Updated dynamic targets:", dynamic_targets)

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

    while True:
        time.sleep(1)