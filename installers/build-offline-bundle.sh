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
# sudo: el modelo de privilegio escribe /etc/sudoers.d y valida con visudo — sin él
# la instalación OFFLINE aborta DESPUÉS de crear el usuario (ver install-satom.sh [PFSUDO]).
# openssh-*: canal de replicación de data/ en modo cluster; sin red no hay dónde bajarlo.
PKGS=(python3 python3-venv python3-pip postgresql nginx rsync openssl curl ca-certificates
      sudo openssh-client openssh-server)

echo "==> Bundle offline SATOM v${VERSION} (ref ${REF})"
command -v apt-get >/dev/null || { echo "Necesita Debian/apt"; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "Ejecuta con sudo (apt necesita root)"; exit 1; }

rm -rf "$STAGE"; mkdir -p "$STAGE/bundle/debs" "$STAGE/bundle/wheels" "$STAGE/bundle/lego"

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
python3 -m venv /tmp/satom-bundle-venv
/tmp/satom-bundle-venv/bin/pip -q install --upgrade pip
/tmp/satom-bundle-venv/bin/pip download -q -r "$REPO_DIR/requirements.txt" \
    -d "$STAGE/bundle/wheels"
/tmp/satom-bundle-venv/bin/pip download -q pip setuptools wheel -d "$STAGE/bundle/wheels"
echo "    $(ls "$STAGE/bundle/wheels" | wc -l) wheels/sdists"

echo "==> 3/4 Empaquetando el código de la app (git archive ${REF})"
git -C "$REPO_DIR" archive --format=tar.gz -o "$STAGE/bundle/app.tar.gz" "$REF"

# --- ACME client: el binario estático de lego viaja en el bundle para que una
# instalación OFFLINE tenga el protocolo ACME/Let's Encrypt operativo. El
# sha256 del release se verifica AQUÍ, en la máquina de build (la que sí tiene red).
LEGO_VERSION="${LEGO_VERSION:-5.2.2}"
_lt="$(mktemp -d)"
curl -fsSLo "$_lt/lego.tgz" "https://github.com/go-acme/lego/releases/download/v${LEGO_VERSION}/lego_v${LEGO_VERSION}_linux_amd64.tar.gz"
curl -fsSLo "$_lt/sums"    "https://github.com/go-acme/lego/releases/download/v${LEGO_VERSION}/lego_${LEGO_VERSION}_checksums.txt"
_exp="$(grep "lego_v${LEGO_VERSION}_linux_amd64.tar.gz$" "$_lt/sums" | awk '{print $1}')"
_got="$(sha256sum "$_lt/lego.tgz" | awk '{print $1}')"
[ -n "$_exp" ] && [ "$_exp" = "$_got" ] || { echo "lego sha256 mismatch"; exit 1; }
tar xzf "$_lt/lego.tgz" -C "$STAGE/bundle/lego" lego
chmod 0755 "$STAGE/bundle/lego/lego"
rm -rf "$_lt"
echo "    lego ${LEGO_VERSION} anadido al bundle (sha256 verificado)"

echo "==> 4/4 Instalador + manual + tarball final"
cp "$REPO_DIR/installers/install-satom.sh" "$STAGE/"
cp "$REPO_DIR/docs/INSTALL.md" "$STAGE/" 2>/dev/null || true
chmod +x "$STAGE/install-satom.sh"

TARBALL="$OUT/satom-offline-${VERSION}-debian12-amd64.tar.gz"
tar -C "$OUT" -czf "$TARBALL" satom-installer
# El .sha256 lleva SOLO el basename: asi "sha256sum -c fichero.sha256" funciona
# en el directorio de descarga del usuario (con ruta absoluta fallaba).
( cd "$(dirname "$TARBALL")" && sha256sum "$(basename "$TARBALL")" > "$(basename "$TARBALL").sha256" )
cat "$TARBALL.sha256"
echo ""
echo "Listo: $TARBALL ($(du -h "$TARBALL" | cut -f1))"
echo "En el destino:  tar xzf $(basename "$TARBALL") && cd satom-installer && sudo bash install-satom.sh"
