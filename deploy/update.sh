#!/usr/bin/env bash
# update.sh — pull latest code and restart service
set -euo pipefail

APP_DIR="/opt/ofortmaut"
SERVICE_NAME="ofortmaut"

cd "$APP_DIR"
git fetch origin main
git checkout -f origin/main
venv/bin/pip install -r requirements.txt -q
cp deploy/ofortmaut.service /etc/systemd/system/"${SERVICE_NAME}".service
systemctl daemon-reload
systemctl restart "$SERVICE_NAME"
echo "Updated. Status: $(systemctl is-active $SERVICE_NAME)"
