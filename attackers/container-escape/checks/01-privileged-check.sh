#!/bin/sh
# Returns 0 (vulnerable) if running as privileged container
if grep -q "0000003fffffffff" /proc/self/status 2>/dev/null; then
  echo "Container is privileged (all capabilities present)"
  exit 0
fi
# Check via /proc/self/status CapEff
cap=$(grep CapEff /proc/self/status | awk '{print $2}')
if [ "$cap" = "0000003fffffffff" ] || [ "$cap" = "000001ffffffffff" ]; then
  echo "Full capability set — running privileged. CapEff: $cap"
  exit 0
fi
echo "Not privileged. CapEff: $cap"
exit 1
