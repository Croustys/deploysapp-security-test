#!/bin/bash
# 14 — Log leakage tests: PII and secrets in logs
REPORT_DIR="/reports"
mkdir -p "$REPORT_DIR"
RESULTS="$REPORT_DIR/14-logs-leakage.json"

FINDINGS=()
PASS=0
FAIL=0

TRAEFIK_LOG="/logs/access.log"

echo "============================================================"
echo "14 — Log Leakage Tests"
echo "============================================================"

# Generate requests with secrets in them so we can check if logs capture them
echo ""
echo "Generating test requests with sensitive data in URLs/headers..."
BASE="${BASE_URL:-http://traefik:80}"

# Send requests with secrets in query params (should NOT appear in logs)
curl -s "$BASE/search?q=secret123&password=admin123" \
  -H "Host: webapp.localhost" -o /dev/null 2>/dev/null || true
curl -s "$BASE/search?api_key=api-key-12345-super-secret" \
  -H "Host: webapp.localhost" -o /dev/null 2>/dev/null || true

sleep 2  # Let logs flush

# 1. Check Traefik access log for sensitive query params
echo ""
echo "[LOG-001] Checking Traefik access log for secrets in query strings..."
if [ -f "$TRAEFIK_LOG" ]; then
  for pattern in "password=" "api_key=" "secret=" "token=" "JWT_SECRET"; do
    if grep -q "$pattern" "$TRAEFIK_LOG" 2>/dev/null; then
      echo "  ⚠  Sensitive pattern '$pattern' found in access log"
      FAIL=$((FAIL+1))
      FINDINGS+=("{\"id\":\"LOG-001\",\"title\":\"Sensitive data in Traefik access logs\",\"severity\":\"high\",\"status\":\"vulnerable\",\"evidence\":\"Pattern '$pattern' found in $TRAEFIK_LOG\",\"remediation\":\"Configure Traefik to redact sensitive query parameters from logs\"}")
    fi
  done
  echo "  ✓  Access log checked"
  PASS=$((PASS+1))
else
  echo "  INFO: Traefik access log not mounted at $TRAEFIK_LOG"
fi

# 2. Check if /debug endpoint (env vars) leaks into logs via error messages
echo ""
echo "[LOG-002] Checking if env vars appear in application error logs..."
# Trigger an error that would include env vars in traceback
curl -s "$BASE/search?q=1'%3B%20DROP%20TABLE%20users%3B%20--" \
  -H "Host: webapp.localhost" -o /dev/null 2>/dev/null || true

echo "  (Inspect container logs with: docker logs dst-webapp | grep -i secret)"
echo "  Manual check required for application-level log inspection"

# 3. Check for plaintext passwords in DB logs
echo ""
echo "[LOG-003] PostgreSQL connection string leakage check..."
echo "  Connection strings with passwords should not appear in process listings or logs"
if ps aux 2>/dev/null | grep -q "password="; then
  echo "  ⚠  Password found in process arguments"
  FAIL=$((FAIL+1))
  FINDINGS+=('{"id":"LOG-003","title":"Database password in process arguments","severity":"high","status":"vulnerable","evidence":"password= found in ps aux output"}')
else
  echo "  ✓  No passwords in process arguments"
  PASS=$((PASS+1))
fi

FINDINGS_JSON=$(IFS=,; echo "[${FINDINGS[*]:-}]")
cat > "$RESULTS" <<EOF
{
  "category": "14-logs-leakage",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "findings": $FINDINGS_JSON,
  "summary": { "passed": $PASS, "failed": $FAIL }
}
EOF
echo ""
echo "Results: $PASS passed, $FAIL FAILED. Report: $RESULTS"
