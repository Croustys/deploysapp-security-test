#!/bin/sh
# Returns 0 (vulnerable) if on host network namespace
# Check if we can see host-level interfaces like eth0 with host IP ranges
interfaces=$(ip link show 2>/dev/null | grep -v 'lo\|eth' | wc -l)
# On host network, we'd see many interfaces
if [ "$interfaces" -gt 5 ]; then
  echo "Many network interfaces visible ($interfaces) — may be on host network"
  ip link show 2>/dev/null
  exit 0
fi
# Check if docker bridge (172.17.0.1) is directly accessible as a local interface
if ip addr show 2>/dev/null | grep -q "172.17.0.1"; then
  echo "Docker bridge IP 172.17.0.1 is a local interface — on host network"
  exit 0
fi
echo "Network appears isolated. Interfaces: $interfaces"
exit 1
