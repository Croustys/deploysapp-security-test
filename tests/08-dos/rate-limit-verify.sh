#!/bin/bash
# 08 — DoS / Rate limiting tests
BASE="${BASE_URL:-http://traefik:80}"
REPORT_DIR="/reports"
mkdir -p "$REPORT_DIR"
RESULTS="$REPORT_DIR/08-dos.json"

FINDINGS=()
PASS=0
FAIL=0

echo "============================================================"
echo "08 — DoS / Rate Limiting Tests"
echo "============================================================"

# 1. Rate limit enforcement — rapid requests from single IP
echo ""
echo "[DOS-001] Rate limit enforcement (50 rapid requests)..."
BLOCKED=0
for i in $(seq 1 50); do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    "$BASE/health" -H "Host: webapp.localhost" 2>/dev/null)
  [ "$status" = "429" ] && BLOCKED=$((BLOCKED+1))
done

if [ "$BLOCKED" -gt 0 ]; then
  echo "  ✓  Rate limiting active — $BLOCKED/50 requests blocked (HTTP 429)"
  PASS=$((PASS+1))
else
  echo "  ⚠  No rate limiting — all 50 rapid requests succeeded"
  FAIL=$((FAIL+1))
  FINDINGS+=('{"id":"DOS-001","title":"No rate limiting on HTTP endpoints","severity":"medium","status":"vulnerable","evidence":"50 rapid requests completed with no 429 responses","remediation":"Configure Traefik rate limiting middleware"}')
fi

# 2. Large payload handling
echo ""
echo "[DOS-002] Large payload handling (10MB POST)..."
dd if=/dev/zero bs=1M count=10 2>/dev/null | \
  curl -s -o /dev/null -w "%{http_code}" -X POST \
  "$BASE/upload" \
  -H "Host: webapp.localhost" \
  -F "file=@-;filename=bigfile.bin" \
  --max-time 10 2>/dev/null | \
  read -r status || status="000"

if [ "$status" = "413" ] || [ "$status" = "400" ]; then
  echo "  ✓  Large payload rejected (HTTP $status)"
  PASS=$((PASS+1))
else
  echo "  ⚠  Large payload accepted (HTTP $status) — potential DoS vector"
  FAIL=$((FAIL+1))
  FINDINGS+=("{\"id\":\"DOS-002\",\"title\":\"No request body size limit\",\"severity\":\"medium\",\"status\":\"vulnerable\",\"evidence\":\"10MB payload returned HTTP $status (not 413)\",\"remediation\":\"Configure Traefik client max body size limit\"}")
fi

# 3. Slow request detection
echo ""
echo "[DOS-003] Slowloris simulation (slow headers)..."
# Send partial HTTP request very slowly — check if connection is held open
timeout 5 bash -c '
  exec 3<>/dev/tcp/traefik/80
  printf "GET / HTTP/1.1\r\nHost: webapp.localhost\r\n" >&3
  sleep 4
  printf "X-Slow: header\r\n" >&3
  sleep 1
  echo "Connection held open for 5s" >&2
  exec 3>&-
' 2>&1 || true
echo "  Check Traefik read-timeout configuration to prevent slow-loris attacks"

FINDINGS_JSON=$(IFS=,; echo "[${FINDINGS[*]:-}]")
cat > "$RESULTS" <<EOF
{
  "category": "08-dos",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "findings": $FINDINGS_JSON,
  "summary": { "passed": $PASS, "failed": $FAIL }
}
EOF
echo ""
echo "Results: $PASS passed, $FAIL FAILED. Report: $RESULTS"
