while true; do
  sudo ip link set dev enp1s0 down
  sleep 15
  sudo ip link set dev enp1s0 up
  sleep 20
done
