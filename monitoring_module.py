import subprocess
import time
from prometheus_client import start_http_server, Gauge

# =============================
# Prometheus Metrics
# =============================
internet_status = Gauge(
    'internet_connectivity_status',
    'Internet connectivity (1=UP, 0=DOWN) based on HTTP 200'
)

internet_latency = Gauge(
    'internet_check_latency_seconds',
    'Time taken to get response from google.com'
)

CHECK_INTERVAL = 10  # seconds


# =============================
# Connectivity Check Function
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

        output = result.stderr.decode()

        if "200 OK" in output:
            return 1
        else:
            return 0

    except Exception:
        internet_latency.set(0)
        return 0


# =============================
# Monitoring Loop
# =============================
def monitor():
    while True:
        status = check_internet()

        if status == 1:
            print("Internet UP")
        else:
            print("Internet DOWN")

        internet_status.set(status)

        time.sleep(CHECK_INTERVAL)


# =============================
# MAIN
# =============================
if __name__ == "__main__":
    start_http_server(8000)
    print("Exporter running on http://localhost:8000/metrics")

    monitor()