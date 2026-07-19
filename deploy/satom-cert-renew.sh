#!/bin/bash
# Auto-renew the node's CA-issued service cert if within the renewal threshold.
# No-op for imported/bootstrap certs and on nodes without the internal CA key.
set -euo pipefail
set -a; . /opt/satom/.env; set +a
cd /opt/satom
exec env FLASK_APP=wsgi:app venv/bin/flask cert-renew
