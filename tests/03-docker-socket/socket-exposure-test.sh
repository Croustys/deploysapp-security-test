#!/bin/bash
# 03 — Docker socket exposure tests
REPORT_DIR="/reports"
mkdir -p "$REPORT_DIR"
RESULTS="$REPORT_DIR/03-docker-socket.json"

FINDINGS=()
PASS=0
FAIL=0

echo "============================================================"
echo "03 — Docker Socket Exposure Tests"
echo "============================================================"

# 1. Is the socket mounted in this container?
echo ""
echo "[SOCK-001] Docker socket in current container..."
if [ -S /var/run/docker.sock ]; then
  echo "  ⚠  /var/run/docker.sock is mounted in this container"
  if curl -s --unix-socket /var/run/docker.sock http://localhost/version 2>/dev/null | grep -q "ApiVersion"; then
    echo "  ⚠  Docker API fully accessible via socket — container escape possible"
    FAIL=$((FAIL+1))
    FINDINGS+=('{"id":"SOCK-001","title":"Docker socket mounted and accessible","severity":"critical","status":"vulnerable","evidence":"curl to /var/run/docker.sock returned Docker API version info","remediation":"Never mount Docker socket in tenant containers. Use alternative container build solutions."}')
  else
    echo "  Socket exists but API not responsive"
    PASS=$((PASS+1))
  fi
else
  echo "  ✓  Docker socket not mounted"
  PASS=$((PASS+1))
fi

# 2. Docker API over TCP (unencrypted 2375)
echo ""
echo "[SOCK-002] Docker API over TCP 2375 (unencrypted)..."
for host in docker traefik "172.17.0.1" "172.28.0.1" "172.29.0.1"; do
  if curl -s --max-time 3 "http://$host:2375/version" 2>/dev/null | grep -q "ApiVersion"; then
    echo "  ⚠  Docker API exposed on $host:2375 — CRITICAL"
    FAIL=$((FAIL+1))
    FINDINGS+=("{\"id\":\"SOCK-002\",\"title\":\"Docker API exposed over TCP on $host\",\"severity\":\"critical\",\"status\":\"vulnerable\",\"evidence\":\"$host:2375 returned Docker version info\"}")
  else
    echo "  ✓  $host:2375 not accessible"
    PASS=$((PASS+1))
  fi
done

# 3. Docker API over TCP 2376 (TLS)
echo ""
echo "[SOCK-003] Docker API over TCP 2376 (TLS)..."
if curl -s --max-time 3 "https://traefik:2376/version" --insecure 2>/dev/null | grep -q "ApiVersion"; then
  echo "  ⚠  Docker API accessible over TLS on 2376 — verify client cert auth is enforced"
  FAIL=$((FAIL+1))
  FINDINGS+=('{"id":"SOCK-003","title":"Docker API accessible on port 2376","severity":"high","status":"warning","evidence":"TLS Docker API port 2376 is accessible","remediation":"Ensure mutual TLS is enforced on Docker API port 2376"}')
else
  echo "  ✓  Docker TLS API not accessible"
  PASS=$((PASS+1))
fi

FINDINGS_JSON=$(IFS=,; echo "[${FINDINGS[*]:-}]")
cat > "$RESULTS" <<EOF
{
  "category": "03-docker-socket",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "findings": $FINDINGS_JSON,
  "summary": { "passed": $PASS, "failed": $FAIL }
}
EOF
echo ""
echo "Results: $PASS passed, $FAIL FAILED. Report: $RESULTS"
