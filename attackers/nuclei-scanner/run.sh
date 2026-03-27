#!/bin/sh
set -e

REPORT_DIR="/reports"
mkdir -p "$REPORT_DIR"

WEBAPP_URL="${WEBAPP_URL:-http://traefik:80}"
API_URL="${API_URL:-http://traefik:80}"

echo "[nuclei] Updating templates..."
nuclei -update-templates -silent || true

echo "[nuclei] Running default template scan against webapp..."
nuclei -u "$WEBAPP_URL" \
       -H "Host: webapp.localhost" \
       -severity critical,high,medium \
       -json \
       -o "$REPORT_DIR/nuclei-webapp.json" \
       -silent || true

echo "[nuclei] Running default template scan against API..."
nuclei -u "$API_URL" \
       -H "Host: api.localhost" \
       -severity critical,high,medium \
       -json \
       -o "$REPORT_DIR/nuclei-api.json" \
       -silent || true

echo "[nuclei] Running custom platform templates..."
nuclei -u "$WEBAPP_URL" \
       -H "Host: webapp.localhost" \
       -t /custom-templates/ \
       -json \
       -o "$REPORT_DIR/nuclei-custom.json" \
       -silent || true

echo "[nuclei] Done. Results in $REPORT_DIR/"
