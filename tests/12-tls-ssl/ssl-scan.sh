#!/bin/bash
# 12 — TLS/SSL configuration tests
BASE_HOST="${BASE_HOST:-traefik}"
BASE_PORT="${BASE_PORT:-443}"
REPORT_DIR="/reports"
mkdir -p "$REPORT_DIR"
RESULTS="$REPORT_DIR/12-tls-ssl.json"

FINDINGS=()
PASS=0
FAIL=0

echo "============================================================"
echo "12 — TLS/SSL Configuration Tests"
echo "============================================================"

# 1. TLS version support
echo ""
echo "[TLS-001] Protocol version tests..."
for proto in ssl2 ssl3 tls1 tls1_1; do
  result=$(curl -s --"$proto" -o /dev/null -w "%{http_code}" \
    "https://$BASE_HOST:$BASE_PORT/" \
    -H "Host: webapp.localhost" \
    --insecure --max-time 5 2>/dev/null || echo "failed")
  if [ "$result" != "failed" ] && [ "$result" != "000" ]; then
    echo "  ⚠  $proto accepted (HTTP $result) — should be disabled"
    FAIL=$((FAIL+1))
    FINDINGS+=("{\"id\":\"TLS-001-$proto\",\"title\":\"Insecure protocol $proto accepted\",\"severity\":\"high\",\"status\":\"vulnerable\",\"evidence\":\"Server accepted $proto handshake\"}")
  else
    echo "  ✓  $proto rejected"
    PASS=$((PASS+1))
  fi
done

# 2. TLS 1.2 and 1.3 available
echo ""
echo "[TLS-002] Checking TLS 1.2/1.3 support..."
for proto in tls1_2 tls1_3; do
  result=$(curl -s --"$proto" -o /dev/null -w "%{http_code}" \
    "https://$BASE_HOST:$BASE_PORT/" \
    -H "Host: webapp.localhost" \
    --insecure --max-time 5 2>/dev/null || echo "failed")
  if [ "$result" != "failed" ] && [ "$result" != "000" ]; then
    echo "  ✓  $proto supported (HTTP $result)"
    PASS=$((PASS+1))
  else
    echo "  ⚠  $proto not supported — may limit compatibility"
    FAIL=$((FAIL+1))
    FINDINGS+=("{\"id\":\"TLS-002-$proto\",\"title\":\"$proto not supported\",\"severity\":\"low\",\"status\":\"info\",\"evidence\":\"$proto connection failed\"}")
  fi
done

# 3. Certificate validity
echo ""
echo "[TLS-003] Certificate details..."
cert_info=$(echo | openssl s_client -connect "$BASE_HOST:$BASE_PORT" \
  -servername webapp.localhost 2>/dev/null | \
  openssl x509 -noout -dates -subject -issuer 2>/dev/null || echo "failed")
echo "  $cert_info"

# 4. HSTS header
echo ""
echo "[TLS-004] HSTS header check..."
hsts=$(curl -sI "https://$BASE_HOST:$BASE_PORT/" \
  -H "Host: webapp.localhost" \
  --insecure 2>/dev/null | grep -i "strict-transport-security" || echo "")
if [ -n "$hsts" ]; then
  echo "  ✓  HSTS present: $hsts"
  PASS=$((PASS+1))
else
  echo "  ⚠  HSTS header missing"
  FAIL=$((FAIL+1))
  FINDINGS+=('{"id":"TLS-004","title":"HSTS header missing","severity":"medium","status":"vulnerable","evidence":"Strict-Transport-Security header not present in HTTPS response"}')
fi

# 5. Weak ciphers
echo ""
echo "[TLS-005] Checking for NULL/EXPORT/RC4 ciphers..."
WEAK_CIPHERS="NULL EXPORT RC4 DES anon"
for cipher in $WEAK_CIPHERS; do
  result=$(curl -s --ciphers "$cipher" -o /dev/null -w "%{http_code}" \
    "https://$BASE_HOST:$BASE_PORT/" \
    -H "Host: webapp.localhost" \
    --insecure --max-time 5 2>/dev/null || echo "failed")
  if [ "$result" != "failed" ] && [ "$result" != "000" ]; then
    echo "  ⚠  Weak cipher $cipher accepted"
    FAIL=$((FAIL+1))
    FINDINGS+=("{\"id\":\"TLS-005-$cipher\",\"title\":\"Weak cipher $cipher accepted\",\"severity\":\"high\",\"status\":\"vulnerable\"}")
  else
    echo "  ✓  Cipher $cipher rejected"
    PASS=$((PASS+1))
  fi
done

FINDINGS_JSON=$(IFS=,; echo "[${FINDINGS[*]:-}]")
cat > "$RESULTS" <<EOF
{
  "category": "12-tls-ssl",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "findings": $FINDINGS_JSON,
  "summary": { "passed": $PASS, "failed": $FAIL }
}
EOF
echo ""
echo "Results: $PASS passed, $FAIL FAILED. Report: $RESULTS"
