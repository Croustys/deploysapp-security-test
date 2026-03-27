#!/bin/bash
# 07 — Secrets and credential leakage tests
BASE="${BASE_URL:-http://traefik:80}"
REPORT_DIR="/reports"
mkdir -p "$REPORT_DIR"
RESULTS="$REPORT_DIR/07-secrets.json"

FINDINGS=()
PASS=0
FAIL=0

echo "============================================================"
echo "07 — Secrets / Credential Leakage Tests"
echo "============================================================"

check_endpoint() {
  local id="$1" url="$2" host_hdr="$3" patterns="$4" title="$5" severity="$6"
  resp=$(curl -s "$url" -H "Host: $host_hdr" 2>/dev/null)
  for pattern in $patterns; do
    if echo "$resp" | grep -qi "$pattern"; then
      echo "  ⚠  LEAK FOUND [$id]: $pattern in $url"
      FAIL=$((FAIL+1))
      FINDINGS+=("{\"id\":\"$id\",\"title\":\"$title\",\"severity\":\"$severity\",\"status\":\"vulnerable\",\"evidence\":\"Pattern '$pattern' found in $url\"}")
      return
    fi
  done
  echo "  ✓  No leakage at $url"
  PASS=$((PASS+1))
}

echo ""
echo "[SEC-001] Webapp /debug endpoint..."
check_endpoint "SEC-001" "$BASE/debug"       "webapp.localhost" "JWT_SECRET DB_PASS API_KEY SECRET" "Secrets in webapp /debug" "high"

echo ""
echo "[SEC-002] API /debug/env endpoint..."
check_endpoint "SEC-002" "$BASE/debug/env"   "api.localhost"    "JWT_SECRET DB_PASS API_KEY SECRET" "Secrets in API /debug/env" "high"

echo ""
echo "[SEC-003] API /admin endpoint..."
check_endpoint "SEC-003" "$BASE/admin"       "api.localhost"    "jwt_secret db_password" "Secrets in API /admin" "high"

echo ""
echo "[SEC-004] Checking for .env file exposure..."
check_endpoint "SEC-004" "$BASE/.env"        "webapp.localhost" "JWT_SECRET PASSWORD API_KEY"  ".env file exposure" "critical"

echo ""
echo "[SEC-005] Checking for .git directory exposure..."
status=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/.git/config" -H "Host: webapp.localhost")
if [ "$status" = "200" ]; then
  echo "  ⚠  VULNERABLE: .git/config accessible"
  FAIL=$((FAIL+1))
  FINDINGS+=('{"id":"SEC-005","title":".git directory exposed","severity":"high","status":"vulnerable","evidence":"HTTP 200 on /.git/config"}')
else
  echo "  ✓  .git not accessible (HTTP $status)"
  PASS=$((PASS+1))
fi

echo ""
echo "[SEC-006] Checking response headers for version leakage..."
headers=$(curl -sI "$BASE/" -H "Host: webapp.localhost" 2>/dev/null)
for hdr in "Server:" "X-Powered-By:" "X-AspNet" "X-Runtime:"; do
  if echo "$headers" | grep -qi "$hdr"; then
    echo "  ⚠  Version leaked in header: $(echo "$headers" | grep -i "$hdr")"
    FAIL=$((FAIL+1))
    FINDINGS+=("{\"id\":\"SEC-006\",\"title\":\"Version info in response headers\",\"severity\":\"low\",\"status\":\"vulnerable\",\"evidence\":\"$hdr present in response headers\"}")
  fi
done

FINDINGS_JSON=$(IFS=,; echo "[${FINDINGS[*]:-}]")
cat > "$RESULTS" <<EOF
{
  "category": "07-secrets",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "findings": $FINDINGS_JSON,
  "summary": { "passed": $PASS, "failed": $FAIL }
}
EOF
echo ""
echo "Results: $PASS passed, $FAIL FAILED. Report: $RESULTS"
