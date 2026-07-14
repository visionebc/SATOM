#!/bin/bash
# Evaluate the proactive health checks and dispatch new alerts (email + in-app
# bell). Runs on every node (cert / device-reachability / git-lag are node-local
# truths). Invoked by fm-alerts.timer.
set -euo pipefail
set -a; . /opt/fortinet-manager/.env; set +a
cd /opt/fortinet-manager
exec env FLASK_APP=wsgi:app venv/bin/flask alerts-run
