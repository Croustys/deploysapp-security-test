#!/bin/bash
# Poll health endpoints until all targets are ready
set -e

BASE="${BASE_URL:-http://traefik:80}"
MAX_WAIT=120
INTERVAL=3
ELAPSED=0

endpoints=(
  "$BASE/health|webapp.localhost|vulnerable-webapp"
  "$BASE/health|api.localhost|vulnerable-api"
  "http://auth-service:8081/health||auth-service"
  "http://internal-service:9000/health||internal-service"
)

echo "Waiting for all services to be ready (max ${MAX_WAIT}s)..."

all_ready() {
  for entry in "${endpoints[@]}"; do
    url="${entry%%|*}"; rest="${entry#*|}"
    host="${rest%%|*}"; name="${rest##*|}"
    header_arg=""
    [ -n "$host" ] && header_arg="-H Host:$host"
    status=$(curl -s -o /dev/null -w "%{http_code}" $header_arg "$url" --max-time 3 2>/dev/null || echo "000")
    [ "$status" != "200" ] && return 1
  done
  return 0
}

while ! all_ready; do
  if [ "$ELAPSED" -ge "$MAX_WAIT" ]; then
    echo "ERROR: Services did not become ready within ${MAX_WAIT}s"
    exit 1
  fi
  echo "  Waiting... (${ELAPSED}s elapsed)"
  sleep "$INTERVAL"
  ELAPSED=$((ELAPSED + INTERVAL))
done

echo "All services ready after ${ELAPSED}s"
