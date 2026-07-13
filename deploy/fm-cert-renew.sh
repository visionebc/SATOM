#!/bin/bash
# Auto-renew the node's CA-issued service cert if within the renewal threshold.
# No-op for imported/bootstrap certs and on nodes without the internal CA key.
set -euo pipefail
set -a; . /opt/fortinet-manager/.env; set +a
cd /opt/fortinet-manager
exec env FLASK_APP=wsgi:app venv/bin/flask cert-renew
