#!/bin/bash
# Service banner grabbing and version detection
BASE="${TRAEFIK_HOST:-traefik}"

echo "============================================================"
echo "01 — Service Enumeration / Banner Grabbing"
echo "============================================================"

echo ""
echo "[HTTP] Traefik server headers:"
curl -sI "http://$BASE/" -H "Host: webapp.localhost" 2>/dev/null | grep -iE "server:|x-powered-by:|traefik" || echo "  No server headers leaked"

echo ""
echo "[HTTP] Checking for version disclosure in error pages:"
curl -s "http://$BASE/nonexistent-path-12345" -H "Host: webapp.localhost" 2>/dev/null | head -20

echo ""
echo "[HTTP] Checking API info endpoint:"
curl -s "http://$BASE/" -H "Host: api.localhost" 2>/dev/null | python3 -m json.tool 2>/dev/null || true

echo ""
echo "[HTTP] Checking for common sensitive paths:"
for path in /.env /.git/config /server-status /phpinfo.php /wp-admin/ /admin /robots.txt /.well-known/; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "http://$BASE$path" -H "Host: webapp.localhost")
  echo "  $path → HTTP $status"
done
