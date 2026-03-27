#!/bin/sh
# cgroup v1 release_agent escape test
# DANGEROUS — only runs if ENABLE_DANGEROUS_TESTS=1
# Based on the well-known Felix Wilhelm cgroup escape technique
# Returns 0 if escape is possible (VULNERABLE)

if [ "${ENABLE_DANGEROUS_TESTS:-0}" != "1" ]; then
  echo "Skipped — set ENABLE_DANGEROUS_TESTS=1 to enable"
  exit 2
fi

# Check if cgroup v1 is available with writable release_agent
CGROUP_PATH=$(find /sys/fs/cgroup -name "release_agent" 2>/dev/null | head -1)
if [ -z "$CGROUP_PATH" ]; then
  echo "No cgroup v1 release_agent found — not vulnerable"
  exit 1
fi

if [ ! -w "$CGROUP_PATH" ]; then
  echo "release_agent exists at $CGROUP_PATH but is not writable — protected"
  exit 1
fi

echo "release_agent found and WRITABLE at: $CGROUP_PATH"
echo "cgroup v1 release_agent escape is POSSIBLE"
echo "An attacker could write a shell command to execute arbitrary code on the host"
# NOTE: We do NOT actually execute the escape — just detect the condition
exit 0
