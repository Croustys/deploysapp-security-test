#!/bin/bash
# 10 — Privilege escalation inside containers
REPORT_DIR="/reports"
mkdir -p "$REPORT_DIR"
RESULTS="$REPORT_DIR/10-privilege-escalation.json"

FINDINGS=()
PASS=0
FAIL=0

echo "============================================================"
echo "10 — Privilege Escalation Tests (inside container context)"
echo "============================================================"

echo ""
echo "[PRIV-001] SUID/SGID binaries..."
SUID_FILES=$(find / -perm /4000 -type f 2>/dev/null | grep -v "^/proc\|^/sys")
if [ -n "$SUID_FILES" ]; then
  echo "  ⚠  SUID binaries found:"
  echo "$SUID_FILES" | head -20
  # Check for specifically dangerous ones
  DANGEROUS=$(echo "$SUID_FILES" | grep -E "python|perl|bash|sh|find|vim|less|more|awk|sed|nmap|nc|curl|wget" || true)
  if [ -n "$DANGEROUS" ]; then
    echo "  ⚠  DANGEROUS SUID binaries: $DANGEROUS"
    FAIL=$((FAIL+1))
    FINDINGS+=("{\"id\":\"PRIV-001\",\"title\":\"Dangerous SUID binary in container\",\"severity\":\"high\",\"status\":\"vulnerable\",\"evidence\":\"$DANGEROUS\"}")
  else
    echo "  ✓  No dangerous SUID binaries (standard ones present: OK)"
    PASS=$((PASS+1))
  fi
fi

echo ""
echo "[PRIV-002] sudo configuration..."
sudo -l 2>/dev/null && {
  echo "  ⚠  sudo accessible — check output above for misconfigured rules"
  FAIL=$((FAIL+1))
  FINDINGS+=('{"id":"PRIV-002","title":"sudo accessible in container","severity":"medium","status":"warning","evidence":"sudo -l succeeded in container"}')
} || echo "  ✓  sudo not accessible or not installed"

echo ""
echo "[PRIV-003] Writable files in sensitive locations..."
WRITABLE=$(find /etc /usr/bin /usr/sbin /bin /sbin -writable 2>/dev/null | head -10)
if [ -n "$WRITABLE" ]; then
  echo "  ⚠  Writable sensitive paths found:"
  echo "$WRITABLE"
  FAIL=$((FAIL+1))
  FINDINGS+=("{\"id\":\"PRIV-003\",\"title\":\"Writable files in sensitive system directories\",\"severity\":\"high\",\"status\":\"vulnerable\",\"evidence\":\"$WRITABLE\"}")
else
  echo "  ✓  No writable sensitive system paths"
  PASS=$((PASS+1))
fi

echo ""
echo "[PRIV-004] Current user / UID check..."
CURRENT_USER=$(whoami 2>/dev/null || id 2>/dev/null)
echo "  Running as: $CURRENT_USER"
if id | grep -q "uid=0(root)"; then
  echo "  ⚠  Running as root — containers should use non-root user"
  FAIL=$((FAIL+1))
  FINDINGS+=('{"id":"PRIV-004","title":"Container running as root","severity":"medium","status":"vulnerable","evidence":"Container process UID is 0 (root)","remediation":"Add USER directive in Dockerfile to run as non-root"}')
else
  echo "  ✓  Running as non-root user"
  PASS=$((PASS+1))
fi

FINDINGS_JSON=$(IFS=,; echo "[${FINDINGS[*]:-}]")
cat > "$RESULTS" <<EOF
{
  "category": "10-privilege-escalation",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "findings": $FINDINGS_JSON,
  "summary": { "passed": $PASS, "failed": $FAIL }
}
EOF
echo ""
echo "Results: $PASS passed, $FAIL FAILED. Report: $RESULTS"
