#!/bin/sh
# Simulates a platform secrets injection service.
# Intentional vulnerability: secrets are exposed as plain-text env vars
# and could leak via /debug endpoints on tenant services.
echo "secrets-manager: injecting secrets into environment..."
echo "POSTGRES_PASSWORD=${POSTGRES_PASSWORD}"
echo "API_KEY=${API_KEY}"
echo "AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}"
# Keep running so docker compose doesn't restart it
sleep infinity
