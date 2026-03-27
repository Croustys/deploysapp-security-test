#!/bin/bash
# 06 — OWASP Top 10 manual checks (supplement to ZAP automated scan)
BASE="${BASE_URL:-http://traefik:80}"
WEBAPP_HOST="webapp.localhost"
API_HOST="api.localhost"
REPORT_DIR="/reports"
mkdir -p "$REPORT_DIR"
RESULTS="$REPORT_DIR/06-api-security.json"

FINDINGS=()
PASS=0
FAIL=0

vuln() {
  local id="$1" title="$2" severity="$3" evidence="$4" cwe="$5"
  FAIL=$((FAIL+1))
  FINDINGS+=("{\"id\":\"$id\",\"title\":\"$title\",\"severity\":\"$severity\",\"status\":\"vulnerable\",\"evidence\":\"$evidence\",\"cwe\":\"$cwe\"}")
  echo "  ⚠  VULNERABLE: $title"
}
ok() { PASS=$((PASS+1)); echo "  ✓  OK: $1"; }

echo "============================================================"
echo "06 — OWASP Top 10 / API Security Tests"
echo "============================================================"

# A01: SQL Injection
echo ""
echo "[API-001] SQL Injection..."
resp=$(curl -s "$BASE/search?q=1'%20OR%20'1'='1" -H "Host: $WEBAPP_HOST" 2>/dev/null)
if echo "$resp" | grep -qiE "alice|bob|carol|syntax error|pg_"; then
  vuln "API-001" "SQL Injection on /search endpoint" "critical" "SQLi payload returned user data" "CWE-89"
else
  ok "SQLi payload did not return obvious data"
fi

# A03: XSS
echo ""
echo "[API-002] Reflected XSS..."
resp=$(curl -s "$BASE/greet?name=<script>alert(1)</script>" -H "Host: $WEBAPP_HOST" 2>/dev/null)
if echo "$resp" | grep -q "<script>alert(1)</script>"; then
  vuln "API-002" "Reflected XSS on /greet endpoint" "high" "Script tag reflected unescaped in response" "CWE-79"
else
  ok "XSS payload escaped"
fi

# A05: Security Misconfiguration — debug endpoint
echo ""
echo "[API-003] Debug endpoint exposing env vars..."
resp=$(curl -s "$BASE/debug" -H "Host: $WEBAPP_HOST" 2>/dev/null)
if echo "$resp" | grep -qiE "JWT_SECRET|DB_PASS|API_KEY|SECRET"; then
  vuln "API-003" "Debug endpoint exposes secrets in env vars" "high" "Env vars including secrets returned by /debug" "CWE-215"
else
  ok "Debug endpoint does not expose secrets (or does not exist)"
fi

# A01: Broken Access Control — admin without auth
echo ""
echo "[API-004] Broken access control — admin route..."
resp=$(curl -s "$BASE/admin" -H "Host: $WEBAPP_HOST" -w "\nHTTP %{http_code}" 2>/dev/null)
if echo "$resp" | grep -q "200"; then
  vuln "API-004" "Admin endpoint accessible without authentication" "high" "HTTP 200 on /admin with no credentials" "CWE-862"
else
  ok "Admin endpoint requires auth"
fi

# A07: IDOR
echo ""
echo "[API-005] IDOR — access other users' data..."
resp=$(curl -s "$BASE/user/2" -H "Host: $WEBAPP_HOST" 2>/dev/null)
if echo "$resp" | grep -qiE "alice|ssn|credit_card"; then
  vuln "API-005" "IDOR on /user/<id> — no ownership check" "high" "Accessed user 2's PII data including SSN/credit card without owning that account" "CWE-639"
else
  ok "IDOR test: user data not returned without auth"
fi

# A02: Cryptographic failures — check HTTPS redirect
echo ""
echo "[API-006] HTTP to HTTPS redirect..."
status=$(curl -s -o /dev/null -w "%{http_code}" --max-redirs 0 "$BASE/" -H "Host: $WEBAPP_HOST" 2>/dev/null)
if [ "$status" = "301" ] || [ "$status" = "302" ]; then
  ok "HTTP redirects to HTTPS"
elif [ "$status" = "200" ]; then
  vuln "API-006" "No HTTPS redirect — plaintext HTTP accepted" "medium" "HTTP 200 on plain HTTP request, no redirect to HTTPS" "CWE-319"
fi

# A06: Vulnerable components — check /debug/info on API
echo ""
echo "[API-007] Package version disclosure..."
resp=$(curl -s "$BASE/debug/info" -H "Host: $API_HOST" 2>/dev/null)
if echo "$resp" | grep -qiE "express|jsonwebtoken|packages"; then
  vuln "API-007" "Package versions exposed via /debug/info" "low" "Dependency versions visible — aids targeted CVE attacks" "CWE-200"
else
  ok "Package versions not exposed"
fi

# CORS misconfiguration
echo ""
echo "[API-008] CORS misconfiguration..."
resp=$(curl -s -I "$BASE/" -H "Host: $WEBAPP_HOST" -H "Origin: https://evil.com" 2>/dev/null)
if echo "$resp" | grep -qi "access-control-allow-origin: \*\|access-control-allow-origin: https://evil.com"; then
  vuln "API-008" "Permissive CORS — allows requests from any origin" "medium" "Access-Control-Allow-Origin reflects attacker origin or wildcard" "CWE-942"
else
  ok "CORS not misconfigured"
fi

# Mass assignment
echo ""
echo "[API-009] Mass assignment — injecting role field..."
resp=$(curl -s -X PUT "$BASE/users/2" \
  -H "Host: $API_HOST" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}' 2>/dev/null)
if echo "$resp" | grep -q '"role":"admin"'; then
  vuln "API-009" "Mass assignment allows role elevation" "high" "PUT /users/2 with {role:admin} accepted and reflected back" "CWE-915"
else
  ok "Mass assignment blocked"
fi

FINDINGS_JSON=$(IFS=,; echo "[${FINDINGS[*]:-}]")
cat > "$RESULTS" <<EOF
{
  "category": "06-api-security",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "findings": $FINDINGS_JSON,
  "summary": { "passed": $PASS, "failed": $FAIL }
}
EOF
echo ""
echo "Results: $PASS passed, $FAIL FAILED. Report: $RESULTS"
