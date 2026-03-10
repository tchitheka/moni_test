#!/bin/bash

echo "======================================"
echo "Community Network Fault Simulator"
echo "Generating faults every 2 seconds..."
echo "Press CTRL+C to stop"
echo "======================================"

while true
do

echo "[DNS FAILURE]"
dig nonexistentdomain.foo +time=1 +tries=1 > /dev/null 2>&1
sleep 2

echo "[DNS QUERY STORM]"
for i in {1..10}
do
    dig google.com +time=1 +tries=1 > /dev/null 2>&1
done
sleep 2

echo "[TCP SERVICE FAILURE]"
nc -vz 8.8.8.8 81 > /dev/null 2>&1
sleep 2

echo "[TCP RESET]"
nc -vz 127.0.0.1 81 > /dev/null 2>&1
sleep 2

echo "[ICMP HOST UNREACHABLE]"
ping -c 1 192.168.1.250 > /dev/null 2>&1
sleep 2

echo "[ROUTING TTL EVENT]"
traceroute -m 3 google.com > /dev/null 2>&1
sleep 2

echo "[ARP CONNECTIVITY FAILURE]"
ping -c 1 192.168.1.200 > /dev/null 2>&1
sleep 2

echo "[TRAFFIC DOMINANCE / CONGESTION]"
iperf3 -c iperf.he.net -t 5 > /dev/null 2>&1
sleep 2

done
