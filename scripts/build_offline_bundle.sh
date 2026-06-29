#!/usr/bin/env bash
#
# Build an OFFLINE install bundle for Fortinet Manager (web).
#
# Run this on a box WITH internet + the SAME OS/arch/Python as the air-gapped
# target (native wheels are platform-specific — psycopg[binary], cryptography,
# cffi, paramiko's deps).  Produces:
#   * ./wheelhouse/             — every dependency wheel (+ pip/setuptools/wheel)
#   * dist/fortinet-manager-offline-<date>.tar.gz — app source + wheelhouse
#
# On the target:
#   tar xzf fortinet-manager-offline-<date>.tar.gz -C /opt
#   cd /opt/fortinet-manager && ./scripts/install.sh --offline
set -euo pipefail

cd "$(dirname "$0")/.."          # app root
ROOT="$(pwd)"
DATE="${1:-$(date +%Y%m%d)}"     # allow caller to pass a fixed stamp
OUT="dist/fortinet-manager-offline-$DATE.tar.gz"

echo "==> Downloading wheels into ./wheelhouse (this host: $(python3 -V), $(uname -m))"
rm -rf wheelhouse && mkdir -p wheelhouse
python3 -m pip download -d wheelhouse -r requirements.txt
# the bootstrap trio so `pip install --no-index` can upgrade pip offline too
python3 -m pip download -d wheelhouse pip setuptools wheel

echo "==> Staging the bundle"
mkdir -p dist
# exclude local state / secrets / caches — a fresh install must start empty
tar czf "$OUT" \
  --exclude='./.git' \
  --exclude='./venv' \
  --exclude='./.env' \
  --exclude='./dist' \
  --exclude='./data/*.db' \
  --exclude='./data/system_backups' \
  --exclude='./reports/*' \
  --exclude='**/*.pre-*' \
  --exclude='**/__pycache__' \
  --transform 's,^\.,fortinet-manager,' \
  .

echo "==> Done: $OUT"
echo "    wheels: $(ls wheelhouse | wc -l)  size: $(du -h "$OUT" | cut -f1)"
echo
echo "Copy $OUT to the air-gapped host, then:"
echo "  tar xzf $(basename "$OUT") -C /opt && cd /opt/fortinet-manager && ./scripts/install.sh --offline"
