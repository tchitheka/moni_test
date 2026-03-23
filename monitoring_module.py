import subprocess
import time
import threading
import pcapy
import struct
import socket

from prometheus_client import start_http_server, Gauge, Counter, Histogram

# =============================
# Prometheus Metrics
# =============================
internet_status = Gauge(
    'internet_connectivity_status',
    'Internet connectivity (1=UP, 0=DOWN)'
)

# ❌ OLD (kept if you still want it)
internet_latency = Gauge(
    'internet_check_latency_seconds',
    'Latency to reach google.com'
)

# ✅ NEW: Histogram for tail latency
internet_rtt_seconds = Histogram(
    'internet_rtt_seconds',
    'RTT latency across multiple targets',
    buckets=(0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1, 2, 5)
)

# ✅ NEW: RTT failures
rtt_failures_total = Counter(
    'rtt_failures_total',
    'Total number of RTT measurement failures'
)

lan_devices_total = Gauge(
    'lan_devices_total',
    'Active LAN devices based on ARP observation'
)

device_flaps_total = Counter(
    'device_flaps_total',
    'Total number of device flap events'
)

dns_errors_total = Counter(
    'dns_errors_total',
    'Total number of DNS NXDOMAIN errors observed'
)

dns_success_total = Counter(
    'dns_success_total',
    'Total number of successful DNS responses observed'
)

# =============================
# Config
# =============================
CHECK_INTERVAL = 10
ARP_CAPTURE_DURATION = 10
DEVICE_TIMEOUT = 60
FLAP_WINDOW = 120

INTERFACE = "wlp0s20f3"

# ✅ Multi-destination targets
TARGETS = [
    ("8.8.8.8", 53),
    ("1.1.1.1", 53),
    ("9.9.9.9", 53),
    ("google.com", 443),
    ("cloudflare.com", 443),
]

# =============================
# Global State
# =============================
device_last_seen = {}
device_last_disappeared = {}

# =============================
# RTT Measurement (TCP)
# =============================
def tcp_rtt(host, port):
    start = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=2)
        sock.close()
        return time.time() - start
    except Exception:
        return None

# =============================
# Parallel RTT Worker
# =============================
def probe_target(host, port):
    rtt = tcp_rtt(host, port)

    if rtt is not None:
        internet_rtt_seconds.observe(rtt)
        print(f"[RTT] {host}:{port} = {rtt:.4f}s")
    else:
        rtt_failures_total.inc()
        print(f"[RTT FAIL] {host}:{port}")

# =============================
# RTT Monitor (parallel probing)
# =============================
def latency_monitor():
    while True:
        threads = []

        for host, port in TARGETS:
            t = threading.Thread(target=probe_target, args=(host, port))
            t.start()
            threads.append(t)

        # wait for all probes to finish
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
            [
                "wget",
                "-q",
                "--spider",
                "--server-response",
                "https://www.google.com"
            ],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            timeout=5
        )

        latency = time.time() - start_time
        internet_latency.set(latency)

        if "200 OK" in result.stderr.decode():
            return 1
        else:
            return 0

    except Exception:
        internet_latency.set(0)
        return 0

# =============================
# ARP Discovery + Flap Detection
# =============================
def discover_lan_devices():
    global device_last_seen, device_last_disappeared

    try:
        cap = pcapy.open_live(INTERFACE, 65536, 1, 100)
        cap.setfilter("arp")
    except Exception as e:
        print(f"Error opening interface {INTERFACE}: {e}")
        return 0

    start_time = time.time()

    while time.time() - start_time < ARP_CAPTURE_DURATION:
        try:
            header, packet = cap.next()
            if not packet:
                continue

            arp_header = packet[14:42]
            arp = struct.unpack("!HHBBH6s4s6s4s", arp_header)

            src_mac = ':'.join('%02x' % b for b in arp[5])
            now = time.time()

            if src_mac in device_last_disappeared:
                if now - device_last_disappeared[src_mac] <= FLAP_WINDOW:
                    device_flaps_total.inc()
                    print(f"[FLAP DETECTED] {src_mac}")

                del device_last_disappeared[src_mac]

            device_last_seen[src_mac] = now

        except Exception:
            continue

    now = time.time()
    active_devices = {}

    for mac, ts in device_last_seen.items():
        if now - ts <= DEVICE_TIMEOUT:
            active_devices[mac] = ts
        else:
            device_last_disappeared[mac] = now

    device_last_seen = active_devices

    return len(active_devices)

# =============================
# DNS Monitor
# =============================
def dns_monitor():
    try:
        cap = pcapy.open_live(INTERFACE, 65536, 1, 100)
        cap.setfilter("udp port 53")
    except Exception as e:
        print(f"DNS capture error: {e}")
        return

    print("DNS monitor started...")

    while True:
        try:
            header, packet = cap.next()
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

            udp_header = packet[udp_start:udp_start + 8]
            if len(udp_header) < 8:
                continue

            udph = struct.unpack("!HHHH", udp_header)
            if udph[0] != 53:
                continue

            dns_start = udp_start + 8
            dns_header = packet[dns_start:dns_start + 12]

            if len(dns_header) < 12:
                continue

            dns = struct.unpack("!HHHHHH", dns_header)
            flags = dns[1]

            qr = (flags >> 15) & 0x1
            rcode = flags & 0xF

            if qr == 1:
                if rcode == 3:
                    dns_errors_total.inc()
                elif rcode == 0:
                    dns_success_total.inc()

        except Exception:
            continue

# =============================
# Monitoring Threads
# =============================
def internet_monitor():
    while True:
        status = check_internet()
        internet_status.set(status)
        print("Internet UP" if status else "Internet DOWN")
        time.sleep(CHECK_INTERVAL)

def lan_monitor():
    while True:
        count = discover_lan_devices()
        lan_devices_total.set(count)
        print(f"Active devices: {count}")
        time.sleep(CHECK_INTERVAL)

# =============================
# MAIN
# =============================
if __name__ == "__main__":
    start_http_server(8000)
    print("Exporter running on http://localhost:8000/metrics")

    threading.Thread(target=internet_monitor, daemon=True).start()
    threading.Thread(target=lan_monitor, daemon=True).start()
    threading.Thread(target=dns_monitor, daemon=True).start()
    threading.Thread(target=latency_monitor, daemon=True).start()  # ✅ NEW

    while True:
        time.sleep(1)