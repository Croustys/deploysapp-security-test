#!/bin/bash
# Tear down all containers and clean up reports
set -e
cd "$(dirname "$0")/.."

echo "[cleanup] Stopping all containers..."
docker compose --profile attack down -v --remove-orphans 2>/dev/null || true
docker compose down -v --remove-orphans 2>/dev/null || true

echo "[cleanup] Removing report files..."
rm -rf reports/raw/* reports/html/* 2>/dev/null || true

echo "[cleanup] Removing generated certs..."
rm -f platform/traefik/certs/cert.pem platform/traefik/certs/key.pem 2>/dev/null || true

echo "[cleanup] Done."
