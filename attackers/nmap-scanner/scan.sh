#!/bin/bash
# Nmap scanner — port scan and service enumeration
set -e

REPORT_DIR="/reports"
mkdir -p "$REPORT_DIR"

TRAEFIK_HOST="${TRAEFIK_HOST:-traefik}"
TENANT_SUBNET="172.29.0.0/24"
INTERNAL_SUBNET="172.31.0.0/24"

echo "============================================================"
echo "[nmap] Starting network scan..."
echo "============================================================"

# 1. External scan: what's exposed through Traefik
echo "[nmap] Scanning Traefik (external-facing)..."
nmap -sV -sC -p 80,443,8080,8181 "$TRAEFIK_HOST" \
     -oJ "$REPORT_DIR/nmap-traefik.json" \
     -oN "$REPORT_DIR/nmap-traefik.txt" || true

# 2. Internal tenant network scan (insider threat simulation)
echo "[nmap] Scanning tenant network $TENANT_SUBNET..."
nmap -sV -p- --min-rate 1000 "$TENANT_SUBNET" \
     -oJ "$REPORT_DIR/nmap-tenant.json" \
     -oN "$REPORT_DIR/nmap-tenant.txt" || true

# 3. Attempt to reach internal network (should be blocked)
echo "[nmap] Attempting to reach internal network $INTERNAL_SUBNET..."
nmap -sn "$INTERNAL_SUBNET" \
     -oJ "$REPORT_DIR/nmap-internal.json" \
     -oN "$REPORT_DIR/nmap-internal.txt" || true

# 4. Check if Docker API is exposed
echo "[nmap] Checking for exposed Docker API (port 2375/2376)..."
nmap -p 2375,2376 "$TRAEFIK_HOST" docker \
     -oJ "$REPORT_DIR/nmap-docker-api.json" \
     -oN "$REPORT_DIR/nmap-docker-api.txt" || true

echo "[nmap] Scans complete. Results in $REPORT_DIR/"
