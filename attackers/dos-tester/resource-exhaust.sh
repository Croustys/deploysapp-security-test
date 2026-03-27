#!/bin/bash
# Resource exhaustion tests — verifies container limits are enforced
# All tests should hit limits and fail gracefully (not crash the host)
set -e

REPORT_DIR="/reports"
mkdir -p "$REPORT_DIR"

echo "============================================================"
echo "Resource Exhaustion Tests"
echo "These tests verify container CPU/memory limits stop runaway processes"
echo "============================================================"

echo ""
echo "[RES-001] Testing memory exhaustion protection..."
# Try to allocate 512MB — should be killed if mem_limit is set
python3 -c "
import sys
try:
    data = bytearray(512 * 1024 * 1024)
    print('FAIL: Allocated 512MB — no memory limit enforced')
    sys.exit(0)
except MemoryError:
    print('PASS: MemoryError raised — memory limit is enforced')
    sys.exit(1)
" && echo "VULNERABLE: No memory limit" || echo "PROTECTED: Memory limit enforced"

echo ""
echo "[RES-002] Testing concurrent connection flood..."
# Send 200 concurrent requests and check if rate limiting kicks in
BLOCKED=0
for i in $(seq 1 200); do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Host: webapp.localhost" http://traefik:80/health 2>/dev/null || echo "000")
  if [ "$status" = "429" ] || [ "$status" = "503" ]; then
    BLOCKED=$((BLOCKED + 1))
  fi
done
if [ "$BLOCKED" -gt 0 ]; then
  echo "PASS: Rate limiting triggered — $BLOCKED requests blocked (429/503)"
else
  echo "WARN: No rate limiting observed in 200 rapid requests"
fi

echo ""
echo "Resource exhaustion tests complete."
