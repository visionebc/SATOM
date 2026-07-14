#!/usr/bin/env bash
# ============================================================================
# build-offline-bundle-rhel.sh — Genera el instalador OFFLINE de OFortMAut
# para la familia RHEL (RHEL / Rocky / AlmaLinux 9, x86_64).
#
# Se ejecuta EN una máquina o contenedor RHEL-9 CON internet — p.ej.:
#
#   docker run --rm -v /ruta/al/repo:/src -w /src rockylinux:9 \
#       bash installers/build-offline-bundle-rhel.sh
#
# Produce:
#     dist/ofortmaut-offline-<version>-rhel9-x86_64.tar.gz
#       └── ofortmaut-installer/
#           ├── install-ofortmaut.sh   (mismo instalador; detecta bundle/rpms)
#           ├── INSTALL.md
#           └── bundle/
#               ├── rpms/    cierre COMPLETO de dependencias .rpm
#               ├── wheels/  paquetería Python para python3.11 (pip download)
#               └── app.tar.gz  código de la app
#
# El código de la app sale de `git archive` si el repo está presente, o del
# tarball indicado en APP_TARBALL= (útil dentro de un contenedor sin .git).
# ============================================================================
set -euo pipefail

REF="${1:-main}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(cat "$REPO_DIR/VERSION" 2>/dev/null || echo 0.0)"
OUT="${BUNDLE_OUT:-$REPO_DIR/dist}"
STAGE="$OUT/ofortmaut-installer"
# Debe coincidir con REQUIRED_PKGS (dnf) del instalador + SELinux best-effort.
# python3.11: el python3 del sistema en EL9 es 3.9 y los pines exigen >= 3.10.
PKGS=(python3.11 python3.11-pip postgresql-server postgresql nginx rsync
      openssl curl ca-certificates policycoreutils-python-utils)

echo "==> Bundle offline OFortMAut v${VERSION} — familia RHEL (el9, x86_64)"
command -v dnf >/dev/null || { echo "Necesita familia RHEL/dnf (usa rockylinux:9)"; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "Ejecuta como root (dnf lo necesita)"; exit 1; }

echo "==> 0/4 Herramientas de build (dnf-plugins-core, python3.11, tar)"
dnf -y -q install dnf-plugins-core python3.11 python3.11-pip git-core tar gzip findutils >/dev/null

rm -rf "$STAGE"; mkdir -p "$STAGE/bundle/rpms" "$STAGE/bundle/wheels" "$OUT"

echo "==> 1/4 Descargando .rpms (cierre completo de dependencias)"
dnf download -q --resolve --alldeps --destdir "$STAGE/bundle/rpms" "${PKGS[@]}"
N=$(ls "$STAGE/bundle/rpms" | wc -l)
echo "    $N paquetes .rpm"
[ "$N" -gt 40 ] || { echo "ERROR: muy pocos rpms — algo falló"; exit 1; }

echo "==> 2/4 Descargando wheels de Python 3.11 (requirements.txt)"
python3.11 -m pip -q download -r "$REPO_DIR/requirements.txt" -d "$STAGE/bundle/wheels"
python3.11 -m pip -q download pip setuptools wheel -d "$STAGE/bundle/wheels"
echo "    $(ls "$STAGE/bundle/wheels" | wc -l) wheels/sdists"

echo "==> 3/4 Empaquetando el código de la app"
if [ -n "${APP_TARBALL:-}" ]; then
    cp "$APP_TARBALL" "$STAGE/bundle/app.tar.gz"
    echo "    código desde APP_TARBALL=$APP_TARBALL"
else
    git -C "$REPO_DIR" archive --format=tar.gz -o "$STAGE/bundle/app.tar.gz" "$REF"
    echo "    código desde git archive ${REF}"
fi

echo "==> 4/4 Instalador + manual + tarball final"
cp "$REPO_DIR/installers/install-ofortmaut.sh" "$STAGE/"
cp "$REPO_DIR/docs/INSTALL.md" "$STAGE/" 2>/dev/null || true
chmod +x "$STAGE/install-ofortmaut.sh"

TARBALL="$OUT/ofortmaut-offline-${VERSION}-rhel9-x86_64.tar.gz"
tar -C "$OUT" -czf "$TARBALL" ofortmaut-installer
( cd "$OUT" && sha256sum "$(basename "$TARBALL")" > "$(basename "$TARBALL").sha256" )
rm -rf "$STAGE"
echo "==> LISTO: $TARBALL"
echo "    $(cat "$TARBALL.sha256")"
