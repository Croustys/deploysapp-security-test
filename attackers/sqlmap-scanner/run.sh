#!/bin/bash
set -e
REPORT_DIR="/reports"
mkdir -p "$REPORT_DIR"
BASE="${BASE_URL:-http://traefik:80}"

echo "[sqlmap] Testing SQLi on vulnerable-webapp /search endpoint..."
python /sqlmap/sqlmap.py \
  -u "$BASE/search?q=test" \
  --host-header="webapp.localhost" \
  --batch \
  --level=3 \
  --risk=2 \
  --dbs \
  --output-dir="$REPORT_DIR/sqlmap" \
  --forms 2>&1 | tee "$REPORT_DIR/sqlmap-webapp.txt" || true

echo "[sqlmap] Done."
