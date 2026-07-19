#!/usr/bin/env bash
# ============================================================================
# build-offline-bundle.sh — Genera el instalador OFFLINE de SATOM.
#
# Se ejecuta en una máquina Debian 12 amd64 CON internet (misma distro/arch
# que el destino). Produce:
#
#     dist/satom-offline-<version>-debian12-amd64.tar.gz
#       └── satom-installer/
#           ├── install-satom.sh     (el mismo instalador; detecta bundle/)
#           ├── INSTALL.md               (manual para el equipo de sistemas)
#           └── bundle/
#               ├── debs/     cierre COMPLETO de dependencias .deb
#               ├── wheels/   toda la paquetería Python (pip download)
#               └── app.tar.gz  código de la app (git archive del repo prod)
#
# Uso:  sudo bash installers/build-offline-bundle.sh [ref-git]   (default: main)
# ============================================================================
set -euo pipefail

REF="${1:-main}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(cat "$REPO_DIR/VERSION" 2>/dev/null || echo 0.0)"
OUT="$REPO_DIR/dist"
STAGE="$OUT/satom-installer"
PKGS=(python3 python3-venv python3-pip postgresql nginx rsync openssl curl ca-certificates)

echo "==> Bundle offline SATOM v${VERSION} (ref ${REF})"
command -v apt-get >/dev/null || { echo "Necesita Debian/apt"; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "Ejecuta con sudo (apt necesita root)"; exit 1; }

rm -rf "$STAGE"; mkdir -p "$STAGE/bundle/debs" "$STAGE/bundle/wheels"

echo "==> 1/4 Descargando .debs (cierre completo de dependencias)"
apt-get update -qq
DEPS=$(apt-cache depends --recurse --no-recommends --no-suggests --no-conflicts \
        --no-breaks --no-replaces --no-enhances "${PKGS[@]}" \
        | grep '^[a-z0-9]' | sort -u)
(cd "$STAGE/bundle/debs" && apt-get download $DEPS 2>/dev/null || true)
N=$(ls "$STAGE/bundle/debs" | wc -l)
echo "    $N paquetes .deb"
[ "$N" -gt 50 ] || { echo "ERROR: muy pocos debs — algo falló"; exit 1; }

echo "==> 2/4 Descargando wheels de Python (requirements.txt)"
python3 -m venv /tmp/ofm-bundle-venv
/tmp/ofm-bundle-venv/bin/pip -q install --upgrade pip
/tmp/ofm-bundle-venv/bin/pip download -q -r "$REPO_DIR/requirements.txt" \
    -d "$STAGE/bundle/wheels"
/tmp/ofm-bundle-venv/bin/pip download -q pip setuptools wheel -d "$STAGE/bundle/wheels"
echo "    $(ls "$STAGE/bundle/wheels" | wc -l) wheels/sdists"

echo "==> 3/4 Empaquetando el código de la app (git archive ${REF})"
git -C "$REPO_DIR" archive --format=tar.gz -o "$STAGE/bundle/app.tar.gz" "$REF"

echo "==> 4/4 Instalador + manual + tarball final"
cp "$REPO_DIR/installers/install-satom.sh" "$STAGE/"
cp "$REPO_DIR/docs/INSTALL.md" "$STAGE/" 2>/dev/null || true
chmod +x "$STAGE/install-satom.sh"

TARBALL="$OUT/satom-offline-${VERSION}-debian12-amd64.tar.gz"
tar -C "$OUT" -czf "$TARBALL" satom-installer
sha256sum "$TARBALL" | tee "$TARBALL.sha256"
echo ""
echo "Listo: $TARBALL ($(du -h "$TARBALL" | cut -f1))"
echo "En el destino:  tar xzf $(basename "$TARBALL") && cd satom-installer && sudo bash install-satom.sh"
