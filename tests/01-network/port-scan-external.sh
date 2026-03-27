#!/bin/bash
# 01-network: External port scan — what's visible from outside Docker networks
# Run from the attacker-net perspective

BASE="${TRAEFIK_HOST:-traefik}"
REPORT_DIR="/reports"
mkdir -p "$REPORT_DIR"
RESULTS="$REPORT_DIR/01-network.json"

FINDINGS=()
PASS=0
FAIL=0

check_port() {
  local id="$1" host="$2" port="$3" expected_open="$4" desc="$5" severity="$6"
  if nc -z -w3 "$host" "$port" 2>/dev/null; then
    status="open"
  else
    status="closed"
  fi

  if [ "$expected_open" = "yes" ] && [ "$status" = "open" ]; then
    echo "  ✓  EXPECTED OPEN: $desc ($host:$port)"
    PASS=$((PASS+1))
  elif [ "$expected_open" = "no" ] && [ "$status" = "closed" ]; then
    echo "  ✓  EXPECTED CLOSED: $desc ($host:$port)"
    PASS=$((PASS+1))
  elif [ "$expected_open" = "no" ] && [ "$status" = "open" ]; then
    echo "  ⚠  UNEXPECTED OPEN: $desc ($host:$port) — should be blocked"
    FAIL=$((FAIL+1))
    FINDINGS+=("{\"id\":\"$id\",\"title\":\"$desc exposed externally\",\"severity\":\"$severity\",\"status\":\"vulnerable\",\"evidence\":\"$host:$port is open\"}")
  else
    echo "  ⚠  EXPECTED OPEN BUT CLOSED: $desc ($host:$port)"
    PASS=$((PASS+1))
  fi
}

echo "============================================================"
echo "01 — External Port Scan"
echo "============================================================"

check_port "NET-E01" "$BASE" "80"   "yes" "HTTP (Traefik entrypoint)"      "info"
check_port "NET-E02" "$BASE" "443"  "yes" "HTTPS (Traefik entrypoint)"     "info"
check_port "NET-E03" "$BASE" "8080" "no"  "Traefik dashboard (8080)"       "medium"
check_port "NET-E04" "$BASE" "2375" "no"  "Docker API unencrypted"         "critical"
check_port "NET-E05" "$BASE" "2376" "no"  "Docker API TLS"                 "critical"
check_port "NET-E06" "internal-service" "9000" "no" "Internal billing service" "critical"
check_port "NET-E07" "internal-db" "5432" "no" "PostgreSQL"                "high"
check_port "NET-E08" "auth-service" "8081" "no" "Auth service direct"      "high"

FINDINGS_JSON=$(IFS=,; echo "[${FINDINGS[*]:-}]")
cat > "$RESULTS" <<EOF
{
  "category": "01-network",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "findings": $FINDINGS_JSON,
  "summary": { "passed": $PASS, "failed": $FAIL }
}
EOF

echo ""
echo "Results: $PASS passed, $FAIL FAILED. Report: $RESULTS"
