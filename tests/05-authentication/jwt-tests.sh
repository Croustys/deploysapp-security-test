#!/bin/bash
# 05 — JWT security tests: none algorithm, weak secret, expired tokens
BASE="${BASE_URL:-http://traefik:80}"
AUTH_BASE="http://auth-service:8081"
REPORT_DIR="/reports"
mkdir -p "$REPORT_DIR"
RESULTS="$REPORT_DIR/05-authentication.json"

FINDINGS=()
PASS=0
FAIL=0

b64url_encode() {
  echo -n "$1" | base64 | tr '+/' '-_' | tr -d '='
}

echo "============================================================"
echo "05 — Authentication Tests"
echo "============================================================"

# 1. Get valid token first
echo ""
echo "[AUTH-001] Obtaining test JWT..."
TOKEN=$(curl -s -X POST "$AUTH_BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","password":"admin123"}' 2>/dev/null | \
  python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null)

if [ -n "$TOKEN" ]; then
  echo "  ✓  Token obtained: ${TOKEN:0:30}..."
else
  echo "  ✗  Could not obtain token"
fi

# 2. Test alg:none attack
echo ""
echo "[AUTH-002] JWT alg:none attack..."
HEADER=$(b64url_encode '{"alg":"none","typ":"JWT"}')
PAYLOAD=$(b64url_encode '{"user":"admin","role":"admin"}')
NONE_TOKEN="${HEADER}.${PAYLOAD}."

resp=$(curl -s "$AUTH_BASE/auth/validate" \
  -H "Authorization: Bearer $NONE_TOKEN" \
  -w "\nHTTP %{http_code}" 2>/dev/null | tail -1)

if echo "$resp" | grep -q "200"; then
  echo "  ⚠  VULNERABLE: alg:none accepted (HTTP 200)"
  FAIL=$((FAIL+1))
  FINDINGS+=('{"id":"AUTH-002","title":"JWT alg:none accepted","severity":"critical","status":"vulnerable","evidence":"Server accepted unsigned JWT with alg:none","cwe":"CWE-347","cvss":9.1}')
else
  echo "  ✓  PROTECTED: alg:none rejected ($resp)"
  PASS=$((PASS+1))
fi

# 3. Weak secret brute force
echo ""
echo "[AUTH-003] JWT weak secret test..."
for secret in "" "secret" "secret123" "password" "jwt" "test" "admin" "changeme"; do
  # Try to re-sign token with common weak secrets
  if python3 -c "
import hmac, hashlib, base64, sys
token = '$TOKEN'
if not token: sys.exit(1)
parts = token.split('.')
msg = (parts[0] + '.' + parts[1]).encode()
sig = hmac.new('$secret'.encode(), msg, hashlib.sha256).digest()
expected = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
actual = parts[2] if len(parts) > 2 else ''
sys.exit(0 if expected == actual else 1)
" 2>/dev/null; then
    echo "  ⚠  VULNERABLE: Token signed with weak secret: '$secret'"
    FAIL=$((FAIL+1))
    FINDINGS+=("{\"id\":\"AUTH-003\",\"title\":\"JWT signed with weak secret\",\"severity\":\"high\",\"status\":\"vulnerable\",\"evidence\":\"Token verified with secret: $secret\",\"cwe\":\"CWE-521\"}")
    break
  fi
done

# 4. No token expiry check
echo ""
echo "[AUTH-004] JWT expiry enforcement..."
if [ -n "$TOKEN" ]; then
  # Decode payload and check for exp field
  PAYLOAD_B64=$(echo "$TOKEN" | cut -d. -f2)
  # Add padding
  PAD=$(( 4 - ${#PAYLOAD_B64} % 4 ))
  [ $PAD -ne 4 ] && PAYLOAD_B64="${PAYLOAD_B64}$(printf '=%.0s' $(seq 1 $PAD))"
  HAS_EXP=$(echo "$PAYLOAD_B64" | base64 -d 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if 'exp' in d else 'no')" 2>/dev/null || echo "unknown")
  if [ "$HAS_EXP" = "no" ]; then
    echo "  ⚠  VULNERABLE: Token has no expiry (exp claim missing)"
    FAIL=$((FAIL+1))
    FINDINGS+=('{"id":"AUTH-004","title":"JWT issued without expiry","severity":"medium","status":"vulnerable","evidence":"Token payload missing exp claim — tokens never expire","cwe":"CWE-613"}')
  else
    echo "  ✓  Token has expiry claim"
    PASS=$((PASS+1))
  fi
fi

# 5. Brute force rate limiting
echo ""
echo "[AUTH-005] Login brute force rate limiting..."
BLOCKED=0
for i in $(seq 1 20); do
  status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$AUTH_BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"user":"admin","password":"wrongpass"}' 2>/dev/null)
  if [ "$status" = "429" ]; then
    BLOCKED=$((BLOCKED+1))
  fi
done
if [ "$BLOCKED" -gt 0 ]; then
  echo "  ✓  Rate limiting triggered after repeated failures"
  PASS=$((PASS+1))
else
  echo "  ⚠  No rate limiting on login endpoint after 20 failed attempts"
  FAIL=$((FAIL+1))
  FINDINGS+=('{"id":"AUTH-005","title":"No brute force protection on login endpoint","severity":"medium","status":"vulnerable","evidence":"20 failed login attempts with no rate limiting"}')
fi

FINDINGS_JSON=$(IFS=,; echo "[${FINDINGS[*]:-}]")
cat > "$RESULTS" <<EOF
{
  "category": "05-authentication",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "findings": $FINDINGS_JSON,
  "summary": { "passed": $PASS, "failed": $FAIL }
}
EOF
echo ""
echo "Results: $PASS passed, $FAIL FAILED. Report: $RESULTS"
