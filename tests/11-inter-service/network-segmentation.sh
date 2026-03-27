#!/bin/bash
# 11 — Inter-service network segmentation tests
# Tests whether tenant services can reach platform infrastructure or each other
REPORT_DIR="/reports"
mkdir -p "$REPORT_DIR"
RESULTS="$REPORT_DIR/11-inter-service.json"

FINDINGS=()
PASS=0
FAIL=0

should_block() {
  local id="$1" host="$2" port="$3" title="$4" severity="$5"
  if nc -z -w3 "$host" "$port" 2>/dev/null; then
    echo "  ⚠  REACHABLE (should be blocked): $host:$port"
    FAIL=$((FAIL+1))
    FINDINGS+=("{\"id\":\"$id\",\"title\":\"$title\",\"severity\":\"$severity\",\"status\":\"vulnerable\",\"evidence\":\"$host:$port reachable from tenant context\",\"remediation\":\"Apply Docker network segmentation to block this path\"}")
  else
    echo "  ✓  BLOCKED: $host:$port"
    PASS=$((PASS+1))
  fi
}

echo "============================================================"
echo "11 — Inter-Service Network Segmentation"
echo "============================================================"

echo ""
echo "Testing: Can tenant services reach platform infrastructure?"
should_block "SEG-001" "auth-service"    "8081" "Auth service reachable from tenant"    "high"
should_block "SEG-002" "secrets-manager" "8082" "Secrets manager reachable from tenant" "high"

echo ""
echo "Testing: Can tenant services reach internal-net?"
should_block "SEG-003" "internal-service" "9000" "Internal billing service from tenant" "critical"
should_block "SEG-004" "metadata.internal" "80" "Metadata service from tenant"          "critical"

echo ""
echo "Testing: Can services reach Docker control plane?"
should_block "SEG-005" "172.28.0.1" "2375" "Docker API on platform gateway"            "critical"
should_block "SEG-006" "172.29.0.1" "2375" "Docker API on tenant gateway"              "critical"

FINDINGS_JSON=$(IFS=,; echo "[${FINDINGS[*]:-}]")
cat > "$RESULTS" <<EOF
{
  "category": "11-inter-service",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "findings": $FINDINGS_JSON,
  "summary": { "passed": $PASS, "failed": $FAIL }
}
EOF
echo ""
echo "Results: $PASS passed, $FAIL FAILED. Report: $RESULTS"
