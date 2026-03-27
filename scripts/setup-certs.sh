#!/bin/bash
# Generates self-signed TLS certificates for Traefik testing
set -e

CERT_DIR="$(dirname "$0")/../platform/traefik/certs"
mkdir -p "$CERT_DIR"

if [ -f "$CERT_DIR/cert.pem" ]; then
  echo "[certs] Certificates already exist, skipping generation."
  exit 0
fi

echo "[certs] Generating self-signed TLS certificate..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout "$CERT_DIR/key.pem" \
  -out "$CERT_DIR/cert.pem" \
  -subj "/C=US/ST=Test/L=Test/O=DeploysappSecTest/CN=*.localhost" \
  -addext "subjectAltName=DNS:*.localhost,DNS:localhost,IP:127.0.0.1"

echo "[certs] Done: $CERT_DIR/cert.pem + key.pem"
