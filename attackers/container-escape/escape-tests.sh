#!/bin/bash
# Container escape and isolation test suite
# Runs all check scripts and aggregates results into JSON

REPORT_DIR="/reports"
mkdir -p "$REPORT_DIR"
CHECKS_DIR="/checks"
RESULTS_FILE="$REPORT_DIR/02-container-isolation.json"

PASS=0
FAIL=0
FINDINGS=()

run_check() {
  local id="$1"
  local title="$2"
  local script="$3"
  local severity="$4"  # If this PASSES (escape succeeds), that's the vulnerability severity

  echo ""
  echo "────────────────────────────────────────"
  echo "[$id] $title"

  output=$("$script" 2>&1)
  exit_code=$?

  if [ $exit_code -eq 0 ]; then
    # Script returned 0 = escape/check SUCCEEDED = VULNERABLE
    echo "  ⚠  VULNERABLE — $title succeeded"
    FAIL=$((FAIL + 1))
    FINDINGS+=("{\"id\":\"$id\",\"title\":\"$title\",\"severity\":\"$severity\",\"status\":\"vulnerable\",\"evidence\":$(echo "$output" | head -5 | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')}")
  else
    # Script returned non-zero = escape FAILED = host is protected
    echo "  ✓  PROTECTED — $title blocked"
    PASS=$((PASS + 1))
  fi
}

echo "============================================================"
echo "Container Escape & Isolation Tests"
echo "ENABLE_DANGEROUS_TESTS=${ENABLE_DANGEROUS_TESTS:-0}"
echo "============================================================"

run_check "CE-001" "Running as privileged container"      "$CHECKS_DIR/01-privileged-check.sh"  "critical"
run_check "CE-002" "Docker socket accessible"             "$CHECKS_DIR/02-docker-socket.sh"     "critical"
run_check "CE-003" "Host PID namespace shared"            "$CHECKS_DIR/03-host-pid.sh"          "high"
run_check "CE-004" "Host network namespace"               "$CHECKS_DIR/04-host-network.sh"      "high"
run_check "CE-005" "Dangerous Linux capabilities present" "$CHECKS_DIR/05-capabilities.sh"      "high"
run_check "CE-006" "Sensitive host paths mounted"         "$CHECKS_DIR/08-sensitive-mounts.sh"  "high"
run_check "CE-007" "Isolated namespaces check"            "$CHECKS_DIR/09-namespace-check.sh"   "medium"

if [ "${ENABLE_DANGEROUS_TESTS:-0}" = "1" ]; then
  run_check "CE-008" "cgroup v1 release_agent escape"     "$CHECKS_DIR/06-cgroup-escape.sh"     "critical"
  run_check "CE-009" "Dangerous /proc paths accessible"   "$CHECKS_DIR/07-proc-mount.sh"        "high"
else
  echo ""
  echo "[CE-008] cgroup escape: SKIPPED (set ENABLE_DANGEROUS_TESTS=1 to enable)"
  echo "[CE-009] /proc paths:   SKIPPED (set ENABLE_DANGEROUS_TESTS=1 to enable)"
fi

# Build JSON report
FINDINGS_JSON=$(IFS=,; echo "[${FINDINGS[*]}]")
CRITICAL=$(echo "$FINDINGS_JSON" | grep -o '"critical"' | wc -l | tr -d ' ')
HIGH=$(echo "$FINDINGS_JSON"     | grep -o '"high"'     | wc -l | tr -d ' ')

cat > "$RESULTS_FILE" <<EOF
{
  "category": "02-container-isolation",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "findings": $FINDINGS_JSON,
  "summary": {
    "passed": $PASS,
    "failed": $FAIL,
    "critical": $CRITICAL,
    "high": $HIGH
  }
}
EOF

echo ""
echo "============================================================"
echo "Results: $PASS protected, $FAIL VULNERABLE"
echo "Report:  $RESULTS_FILE"
echo "============================================================"
