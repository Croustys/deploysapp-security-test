#!/bin/bash
# 04 — Reverse proxy header injection tests
BASE="${BASE_URL:-http://traefik:80}"
REPORT_DIR="/reports"
mkdir -p "$REPORT_DIR"
RESULTS="$REPORT_DIR/04-reverse-proxy.json"

FINDINGS=()
PASS=0
FAIL=0

echo "============================================================"
echo "04 — Reverse Proxy Security Tests"
echo "============================================================"

# 1. Host header injection
echo ""
echo "[PROXY-001] Host header injection..."
resp=$(curl -s "$BASE/" -H "Host: evil.com" -o /dev/null -w "%{http_code}" 2>/dev/null)
echo "  Response to Host: evil.com → HTTP $resp"

# 2. X-Forwarded-For spoofing (bypass IP-based rate limits)
echo ""
echo "[PROXY-002] X-Forwarded-For spoofing..."
resp=$(curl -s "$BASE/health" \
  -H "Host: webapp.localhost" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -w "\nHTTP %{http_code}" 2>/dev/null | tail -1)
echo "  XFF spoof response: $resp"

# 3. X-Auth-User header bypass (attempt to inject auth headers)
echo ""
echo "[PROXY-003] X-Auth-User header injection (auth bypass)..."
resp=$(curl -s "$BASE/auth/admin" \
  -H "Host: webapp.localhost" \
  -H "X-Auth-User: admin" \
  -H "X-Auth-Role: admin" \
  -w "\nHTTP %{http_code}" 2>/dev/null)
echo "  Response: $resp"
if echo "$resp" | grep -q "admin panel"; then
  echo "  ⚠  VULNERABLE: Auth bypass via injected X-Auth-User header"
  FAIL=$((FAIL+1))
  FINDINGS+=('{"id":"PROXY-003","title":"Auth bypass via X-Auth-User header injection","severity":"critical","status":"vulnerable","evidence":"admin panel accessed without valid JWT"}')
else
  echo "  ✓  PROTECTED: X-Auth-User header stripped by proxy"
  PASS=$((PASS+1))
fi

# 4. Traefik dashboard exposure check
echo ""
echo "[PROXY-004] Traefik dashboard accessibility..."
resp=$(curl -s -o /dev/null -w "%{http_code}" "http://traefik:8080/dashboard/" 2>/dev/null)
if [ "$resp" = "200" ]; then
  echo "  ⚠  VULNERABLE: Dashboard accessible without auth (HTTP 200)"
  FAIL=$((FAIL+1))
  FINDINGS+=('{"id":"PROXY-004","title":"Traefik dashboard accessible without authentication","severity":"medium","status":"vulnerable","evidence":"HTTP 200 on /dashboard/ without credentials"}')
elif [ "$resp" = "401" ] || [ "$resp" = "403" ]; then
  echo "  ✓  PROTECTED: Dashboard requires auth (HTTP $resp)"
  PASS=$((PASS+1))
else
  echo "  ✓  Dashboard not accessible (HTTP $resp)"
  PASS=$((PASS+1))
fi

# 5. Path traversal through proxy
echo ""
echo "[PROXY-005] Path traversal attempts..."
for path in "/../etc/passwd" "/..%2Fetc%2Fpasswd" "/%2e%2e/etc/passwd"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "$BASE$path" -H "Host: webapp.localhost")
  echo "  $path → HTTP $status"
done

# 6. HTTP verb tampering
echo ""
echo "[PROXY-006] HTTP verb tampering..."
for method in TRACE OPTIONS DELETE PUT; do
  status=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "$BASE/" -H "Host: webapp.localhost")
  echo "  $method / → HTTP $status"
done

FINDINGS_JSON=$(IFS=,; echo "[${FINDINGS[*]:-}]")
cat > "$RESULTS" <<EOF
{
  "category": "04-reverse-proxy",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "findings": $FINDINGS_JSON,
  "summary": { "passed": $PASS, "failed": $FAIL }
}
EOF
echo ""
echo "Results: $PASS passed, $FAIL FAILED. Report: $RESULTS"
