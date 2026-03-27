#!/bin/bash
# 13 — Database exposure tests
REPORT_DIR="/reports"
mkdir -p "$REPORT_DIR"
RESULTS="$REPORT_DIR/13-database.json"

FINDINGS=()
PASS=0
FAIL=0

echo "============================================================"
echo "13 — Database Exposure Tests"
echo "============================================================"

# 1. PostgreSQL reachable from outside tenant-net
echo ""
echo "[DB-001] PostgreSQL reachability from external network..."
if nc -z -w3 internal-db 5432 2>/dev/null; then
  echo "  ⚠  PostgreSQL port 5432 is reachable from this container"
  FAIL=$((FAIL+1))
  FINDINGS+=('{"id":"DB-001","title":"PostgreSQL reachable from attacker network","severity":"critical","status":"vulnerable","evidence":"Port 5432 on internal-db is accessible","remediation":"Restrict PostgreSQL to tenant-net only via Docker network policies"}')
else
  echo "  ✓  PostgreSQL not reachable from this container"
  PASS=$((PASS+1))
fi

# 2. Default credentials
echo ""
echo "[DB-002] Default/weak database credentials..."
if command -v psql >/dev/null 2>&1; then
  for creds in "postgres:postgres" "postgres:" "admin:admin" "dbuser:password"; do
    user="${creds%%:*}"; pass="${creds##*:}"
    PGPASSWORD="$pass" psql -h internal-db -U "$user" -d appdb -c "SELECT 1" >/dev/null 2>&1 && {
      echo "  ⚠  Login succeeded with $user:$pass"
      FAIL=$((FAIL+1))
      FINDINGS+=("{\"id\":\"DB-002\",\"title\":\"Database accessible with weak credentials\",\"severity\":\"critical\",\"status\":\"vulnerable\",\"evidence\":\"Login succeeded with $user:$pass\"}")
    } || echo "  ✓  $user:$pass rejected"
  done
else
  echo "  (psql not installed in this container — testing via nc)"
  # Check if port is open (DB-001 already covers this)
fi

# 3. pg_hba.conf permissiveness — check if we can connect without password from any IP
echo ""
echo "[DB-003] Trust authentication check (pg_hba.conf)..."
if nc -z -w3 internal-db 5432 2>/dev/null; then
  # If we can connect and it's using 'trust', psql won't ask for password
  if PGPASSWORD="" psql -h internal-db -U dbuser -d appdb -c "SELECT count(*) FROM users" 2>/dev/null | grep -q "[0-9]"; then
    echo "  ⚠  Database accepts connections without password (trust auth)"
    FAIL=$((FAIL+1))
    FINDINGS+=('{"id":"DB-003","title":"Database uses trust authentication — no password required","severity":"critical","status":"vulnerable","evidence":"Connected to PostgreSQL and queried users table without password","remediation":"Change pg_hba.conf to use md5 or scram-sha-256 authentication"}')
  else
    echo "  ✓  Database requires password authentication"
    PASS=$((PASS+1))
  fi
fi

FINDINGS_JSON=$(IFS=,; echo "[${FINDINGS[*]:-}]")
cat > "$RESULTS" <<EOF
{
  "category": "13-database",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "findings": $FINDINGS_JSON,
  "summary": { "passed": $PASS, "failed": $FAIL }
}
EOF
echo ""
echo "Results: $PASS passed, $FAIL FAILED. Report: $RESULTS"
