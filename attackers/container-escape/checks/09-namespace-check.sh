#!/bin/sh
# Verify container is running in properly isolated namespaces
# Returns 0 (issue found) if not properly isolated

echo "Namespace isolation check:"
ls -la /proc/self/ns/ 2>/dev/null || echo "Cannot read namespaces"

# Compare container's namespaces with host init (PID 1) namespaces
MISMATCH=0
for ns in mnt pid net uts ipc user; do
  container_ns=$(readlink "/proc/self/ns/$ns" 2>/dev/null)
  host_ns=$(readlink "/proc/1/ns/$ns" 2>/dev/null)
  if [ -n "$container_ns" ] && [ -n "$host_ns" ] && [ "$container_ns" = "$host_ns" ]; then
    echo "  SHARED: $ns namespace matches host ($container_ns)"
    MISMATCH=1
  else
    echo "  ISOLATED: $ns namespace ($container_ns)"
  fi
done

if [ "$MISMATCH" -eq 1 ]; then
  echo "Container shares one or more namespaces with host"
  exit 0
fi
echo "All checked namespaces are isolated"
exit 1
