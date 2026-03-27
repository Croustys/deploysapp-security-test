#!/bin/sh
# Trivy: scan all target images for CVEs and hardcoded secrets
set -e

REPORT_DIR="/reports"
mkdir -p "$REPORT_DIR"

IMAGES="
deploysapp-security-test-vulnerable-webapp
deploysapp-security-test-vulnerable-api
deploysapp-security-test-internal-db
deploysapp-security-test-internal-service
deploysapp-security-test-metadata-mock
deploysapp-security-test-auth-service
"

echo "============================================================"
echo "Trivy Image Scan — CVEs and Secrets"
echo "============================================================"

for img in $IMAGES; do
  echo ""
  echo "[trivy] Scanning $img..."

  # CVE scan
  trivy image \
    --format json \
    --output "$REPORT_DIR/trivy-${img}-cves.json" \
    --severity HIGH,CRITICAL \
    --quiet \
    "$img" 2>/dev/null || echo "  Image $img not found, skipping"

  # Secret scan
  trivy image \
    --scanners secret \
    --format json \
    --output "$REPORT_DIR/trivy-${img}-secrets.json" \
    --quiet \
    "$img" 2>/dev/null || true
done

echo ""
echo "[trivy] All scans complete. Results in $REPORT_DIR/"
