#!/bin/bash
# 09 — SSRF tests (MOST CRITICAL for a PaaS platform)
# Tests whether the SSRF vulnerability in vulnerable-webapp can be used
# to reach internal services, cloud metadata, Docker API, and local files.

BASE="${BASE_URL:-http://traefik:80}"
WEBAPP_HOST="webapp.localhost"
REPORT_DIR="/reports"
mkdir -p "$REPORT_DIR"
RESULTS="$REPORT_DIR/09-ssrf.json"

FINDINGS=()
PASS=0
FAIL=0

ssrf_test() {
  local id="$1" target_url="$2" title="$3" severity="$4"
  local patterns="$5" remediation="$6" cwe="${7:-CWE-918}"

  echo ""
  echo "[$id] $title"
  echo "  Target: $target_url"

  resp=$(curl -s --max-time 5 \
    "$BASE/fetch?url=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$target_url")" \
    -H "Host: $WEBAPP_HOST" 2>/dev/null)

  VULNERABLE=0
  for pattern in $patterns; do
    if echo "$resp" | grep -qi "$pattern"; then
      VULNERABLE=1
      break
    fi
  done

  if [ "$VULNERABLE" -eq 1 ]; then
    echo "  ⚠  VULNERABLE: SSRF successful — sensitive data returned"
    echo "  Evidence (first 200 chars): ${resp:0:200}"
    FAIL=$((FAIL+1))
    FINDINGS+=("{\"id\":\"$id\",\"title\":\"$title\",\"severity\":\"$severity\",\"status\":\"vulnerable\",\"evidence\":\"SSRF request returned sensitive data matching pattern\",\"endpoint\":\"/fetch?url=$target_url\",\"remediation\":\"$remediation\",\"cwe\":\"$cwe\",\"cvss\":9.1}")
  else
    echo "  ✓  BLOCKED or no sensitive data returned"
    PASS=$((PASS+1))
  fi
}

echo "============================================================"
echo "09 — SSRF Tests (CRITICAL)"
echo "============================================================"
echo "All tests route through: $BASE/fetch?url=<target>"

# 1. Internal billing service (should be on isolated internal-net)
ssrf_test "SSRF-001" \
  "http://internal-service:9000/" \
  "SSRF to internal billing service" \
  "critical" \
  "internal-billing stripe_secret_key FAKEFAKEFAKE tenant_records" \
  "Block RFC1918 ranges at proxy. Implement SSRF allowlist. Ensure internal-net is not reachable from tenant-net." \
  "CWE-918"

# 2. AWS metadata service (cloud credential theft)
ssrf_test "SSRF-002" \
  "http://metadata.internal/latest/meta-data/iam/security-credentials/deploysapp-ec2-role" \
  "SSRF to AWS EC2 metadata service (IAM credential theft)" \
  "critical" \
  "AccessKeyId SecretAccessKey AKIAIOSFODNN7EXAMPLE" \
  "Block link-local (169.254.0.0/16) at proxy level. Use IMDSv2 with PUT-based tokens. Consider metadata endpoint restrictions." \
  "CWE-918"

# 3. Docker API (if exposed on TCP)
ssrf_test "SSRF-003" \
  "http://172.28.0.1:2375/version" \
  "SSRF to Docker daemon API (unencrypted TCP)" \
  "critical" \
  "ApiVersion Version KernelVersion" \
  "Do not expose Docker API over TCP. Use socket with read-only access only where needed." \
  "CWE-918"

# 4. Docker gateway / host
ssrf_test "SSRF-004" \
  "http://172.29.0.1/" \
  "SSRF to tenant-net gateway (Docker bridge)" \
  "high" \
  "Server: nginx Server: apache" \
  "Block RFC1918 gateway IPs at proxy." \
  "CWE-918"

# 5. Traefik dashboard via SSRF
ssrf_test "SSRF-005" \
  "http://traefik:8080/api/rawdata" \
  "SSRF to Traefik dashboard API" \
  "high" \
  "routers services middlewares entryPoints" \
  "Restrict Traefik dashboard to specific IPs. Require authentication." \
  "CWE-918"

# 6. Auth service via SSRF
ssrf_test "SSRF-006" \
  "http://auth-service:8081/auth/admin" \
  "SSRF to auth service admin endpoint" \
  "high" \
  "admin panel internal platform" \
  "Ensure internal service endpoints are not bypassed via SSRF. Apply network policies." \
  "CWE-918"

# 7. file:// scheme
echo ""
echo "[SSRF-007] file:// scheme SSRF..."
resp=$(curl -s --max-time 5 \
  "$BASE/fetch?url=file:///etc/passwd" \
  -H "Host: $WEBAPP_HOST" 2>/dev/null)
if echo "$resp" | grep -q "root:"; then
  echo "  ⚠  VULNERABLE: file:// scheme allowed — /etc/passwd returned"
  FAIL=$((FAIL+1))
  FINDINGS+=('{"id":"SSRF-007","title":"SSRF allows file:// scheme — arbitrary file read","severity":"critical","status":"vulnerable","evidence":"file:///etc/passwd returned system password file","remediation":"Block non-http(s) URL schemes. Validate and sanitize URL parameter.","cwe":"CWE-918","cvss":9.8}')
else
  echo "  ✓  file:// scheme blocked or file not returned"
  PASS=$((PASS+1))
fi

FINDINGS_JSON=$(IFS=,; echo "[${FINDINGS[*]:-}]")
cat > "$RESULTS" <<EOF
{
  "category": "09-ssrf",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "findings": $FINDINGS_JSON,
  "summary": { "passed": $PASS, "failed": $FAIL, "critical": $(echo "$FINDINGS_JSON" | grep -o '"critical"' | wc -l | tr -d ' '), "high": $(echo "$FINDINGS_JSON" | grep -o '"high"' | wc -l | tr -d ' ') }
}
EOF

echo ""
echo "============================================================"
echo "SSRF Results: $PASS blocked, $FAIL VULNERABLE"
if [ "$FAIL" -gt 0 ]; then
  echo "⚠  CRITICAL: SSRF vulnerabilities found — DO NOT launch until fixed"
fi
echo "Report: $RESULTS"
echo "============================================================"
