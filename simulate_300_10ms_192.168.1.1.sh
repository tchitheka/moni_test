#!/bin/bash
# Simulates a high-latency, unstable connection
# 200ms delay, 10ms jitter, 5% packet loss, and 0.5% corruption
sudo tc qdisc replace dev wlp0s20f3 root netem \
    delay 300ms 10ms \
    loss 5% \
    corrupt 0.5%
