#!/bin/sh
# Returns 0 (vulnerable) if sharing host PID namespace
# If we can see PID 1 and it is NOT an init process typical of containers
pid1_cmd=$(cat /proc/1/cmdline 2>/dev/null | tr '\0' ' ')
pid1_comm=$(cat /proc/1/comm 2>/dev/null)
total_pids=$(ls /proc | grep -c '^[0-9]' 2>/dev/null || echo 0)

if [ "$total_pids" -gt 50 ]; then
  echo "Large number of visible PIDs ($total_pids) — likely sharing host PID namespace"
  echo "PID 1: $pid1_comm ($pid1_cmd)"
  exit 0
fi
echo "PID namespace appears isolated. Visible PIDs: $total_pids, PID1: $pid1_comm"
exit 1
