import subprocess
import time
import threading
import pcapy
import struct

from prometheus_client import start_http_server, Gauge, Counter

# =============================
# Prometheus Metrics
# =============================
internet_status = Gauge(
    'internet_connectivity_status',
    'Internet connectivity (1=UP, 0=DOWN)'
)

internet_latency = Gauge(
    'internet_check_latency_seconds',
    'Latency to reach google.com'
)

lan_devices_total = Gauge(
    'lan_devices_total',
    'Active LAN devices based on ARP observation'
)

device_flaps_total = Counter(
    'device_flaps_total',
    'Total number of device flap events'
)

# =============================
# Config
# =============================
CHECK_INTERVAL = 10
ARP_CAPTURE_DURATION = 10
DEVICE_TIMEOUT = 60       # seconds before device is considered gone
FLAP_WINDOW = 120         # seconds to detect reappearance

INTERFACE = "wlp0s20f3"        # change to br-lan / wlan0 if needed

# =============================
# Global State
# =============================
device_last_seen = {}
device_last_disappeared = {}

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

    # Capture ARP packets
    while time.time() - start_time < ARP_CAPTURE_DURATION:
        try:
            header, packet = cap.next()
            if not packet:
                continue

            arp_header = packet[14:42]
            arp = struct.unpack("!HHBBH6s4s6s4s", arp_header)

            src_mac = ':'.join('%02x' % b for b in arp[5])
            now = time.time()

            # Flap detection
            if src_mac in device_last_disappeared:
                if now - device_last_disappeared[src_mac] <= FLAP_WINDOW:
                    device_flaps_total.inc()
                    print(f"[FLAP DETECTED] {src_mac}")

                del device_last_disappeared[src_mac]

            # Update last seen
            device_last_seen[src_mac] = now

        except Exception:
            continue

    # Remove stale devices
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

    while True:
        time.sleep(1)