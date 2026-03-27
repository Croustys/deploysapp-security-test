#!/bin/bash
# Network segmentation and lateral movement test
set -e

REPORT_DIR="/reports"
mkdir -p "$REPORT_DIR"
RESULTS_FILE="$REPORT_DIR/11-inter-service.json"

PASS=0
FAIL=0
FINDINGS=()

check_reach() {
  local id="$1" host="$2" port="$3" desc="$4" severity="$5"
  echo ""
  echo "[$id] Testing: $desc ($host:$port)"
  if nc -z -w3 "$host" "$port" 2>/dev/null; then
    echo "  ⚠  REACHABLE — $desc is accessible (should be blocked)"
    FAIL=$((FAIL+1))
    FINDINGS+=("{\"id\":\"$id\",\"title\":\"$desc reachable from attacker\",\"severity\":\"$severity\",\"status\":\"vulnerable\",\"evidence\":\"$host:$port is accessible\"}")
  else
    echo "  ✓  BLOCKED — $desc correctly isolated"
    PASS=$((PASS+1))
  fi
}

echo "============================================================"
echo "Network Segmentation & Lateral Movement Tests"
echo "============================================================"

# Internal services should NOT be reachable from attacker/tenant nets
check_reach "NET-001" "internal-service"  "9000" "Internal billing service"      "critical"
check_reach "NET-002" "metadata.internal" "80"   "Metadata mock service"         "critical"
check_reach "NET-003" "internal-db"       "5432" "PostgreSQL from attacker-net"  "high"
check_reach "NET-004" "auth-service"      "8081" "Auth service from attacker-net" "high"
check_reach "NET-005" "secrets-manager"   "8082" "Secrets manager direct access" "high"
check_reach "NET-006" "traefik"           "8080" "Traefik dashboard port"        "medium"

# Docker API
check_reach "NET-007" "172.28.0.1" "2375" "Docker API on platform gateway"   "critical"
check_reach "NET-008" "172.29.0.1" "2375" "Docker API on tenant gateway"     "critical"

FINDINGS_JSON=$(IFS=,; echo "[${FINDINGS[*]:-}]")
cat > "$RESULTS_FILE" <<EOF
{
  "category": "11-inter-service",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "findings": $FINDINGS_JSON,
  "summary": { "passed": $PASS, "failed": $FAIL }
}
EOF

echo ""
echo "============================================================"
echo "Results: $PASS blocked, $FAIL REACHABLE (should be 0)"
echo "============================================================"
