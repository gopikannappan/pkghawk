#!/bin/bash
# Run this on a fresh Hetzner CX21 (Ubuntu 22.04+)
# Usage: ssh root@<server-ip> 'bash -s' < deploy/setup-server.sh

set -euo pipefail

echo "=== Installing Docker ==="
apt-get update
apt-get install -y ca-certificates curl gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

echo "=== Installing Nginx + Certbot ==="
apt-get install -y nginx certbot python3-certbot-nginx

echo "=== Creating app directory ==="
mkdir -p /opt/pkghawk

echo "=== Done. Next steps: ==="
echo "1. Clone repo:  cd /opt/pkghawk && git clone https://github.com/gopikannappan/pkghawk ."
echo "2. Create env:  cp .env.example deploy/.env.prod && nano deploy/.env.prod"
echo "3. Copy nginx:  cp deploy/nginx.conf /etc/nginx/sites-available/pkghawk"
echo "4. Enable site: ln -sf /etc/nginx/sites-available/pkghawk /etc/nginx/sites-enabled/"
echo "5. Get TLS:     certbot --nginx -d pkghawk.dev -d api.pkghawk.dev"
echo "6. Deploy:      cd /opt/pkghawk && bash deploy/deploy.sh"
