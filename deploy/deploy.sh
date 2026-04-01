#!/bin/bash
# Deploy pkghawk by pulling the latest image from ghcr.io
# Usage: cd /opt/pkghawk && bash deploy/deploy.sh

set -euo pipefail

echo "=== Pulling latest image ==="
docker pull ghcr.io/gopikannappan/pkghawk:latest

echo "=== Restarting containers ==="
docker compose -f deploy/docker-compose.prod.yml up -d

echo "=== Health check ==="
sleep 5
STATUS=$(curl -sf http://127.0.0.1:8000/health | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])" 2>/dev/null || echo "error")
echo "Health: $STATUS"

if [ "$STATUS" = "error" ]; then
    echo "WARNING: Health check failed. Check logs:"
    echo "  docker compose -f deploy/docker-compose.prod.yml logs app"
    exit 1
fi

echo "=== Deployed successfully ==="
