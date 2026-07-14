#!/bin/bash
# Evaluate the proactive health checks and dispatch new alerts (email + in-app
# bell). Runs on every node (cert / device-reachability / git-lag are node-local
# truths). Invoked by ofortmaut-alerts.timer.
set -euo pipefail
set -a; . /opt/ofortmaut/.env; set +a
cd /opt/ofortmaut
exec env FLASK_APP=wsgi:app venv/bin/flask alerts-run
