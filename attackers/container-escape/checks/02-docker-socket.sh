#!/bin/sh
# Returns 0 (vulnerable) if Docker socket is accessible
SOCKET="/var/run/docker.sock"
if [ -S "$SOCKET" ]; then
  echo "Docker socket found at $SOCKET"
  # Try to actually use it
  if curl -s --unix-socket "$SOCKET" http://localhost/version 2>/dev/null | grep -q "ApiVersion"; then
    echo "Docker API is accessible via socket — full container control possible"
    exit 0
  fi
  echo "Socket exists but API not accessible"
  exit 0
fi
echo "Docker socket not accessible"
exit 1
