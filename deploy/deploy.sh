#!/bin/bash
# Deploy pkghawk on the Hetzner server
# Usage: ssh root@<server-ip> 'cd /opt/pkghawk && bash deploy/deploy.sh'

set -euo pipefail

echo "=== Pulling latest code ==="
git pull origin main

echo "=== Building and starting containers ==="
docker compose -f deploy/docker-compose.prod.yml build --no-cache
docker compose -f deploy/docker-compose.prod.yml up -d

echo "=== Reloading Nginx ==="
nginx -t && systemctl reload nginx

echo "=== Health check ==="
sleep 3
STATUS=$(curl -sf http://127.0.0.1:8000/health | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null || echo "error")
echo "Health: $STATUS"

if [ "$STATUS" = "error" ]; then
    echo "WARNING: Health check failed. Check logs:"
    echo "  docker compose -f deploy/docker-compose.prod.yml logs app"
    exit 1
fi

echo "=== Deployed successfully ==="
