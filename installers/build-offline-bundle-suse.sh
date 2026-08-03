#!/usr/bin/env bash
# ============================================================================
# build-offline-bundle-suse.sh — Genera el instalador OFFLINE de SATOM
# para la familia SUSE (openSUSE Leap 15.6 / SLES 15, x86_64).
#
# Se ejecuta EN una máquina o contenedor openSUSE CON internet — p.ej.:
#
#   docker run --rm -v /ruta/al/repo:/src -v /ruta/app.tar.gz:/app.tar.gz:ro \
#       -e APP_TARBALL=/app.tar.gz -w /src opensuse/leap:15.6 \
#       bash installers/build-offline-bundle-suse.sh
#
# Produce:
#     dist/satom-offline-<version>-suse15-x86_64.tar.gz
#       └── satom-installer/
#           ├── install-satom.sh   (mismo instalador; detecta bundle/rpms-suse)
#           ├── INSTALL.md
#           └── bundle/
#               ├── rpms-suse/  cierre COMPLETO de dependencias .rpm + repodata
#               ├── wheels/     paquetería Python para python3.11
#               ├── lego/       cliente ACME estático
#               └── app.tar.gz  código de la app
#
# POR QUÉ UN DIRECTORIO PROPIO Y NO 'rpms/'
# -----------------------------------------
# Los dos bundles son .rpm y NO son intercambiables: los nombres de paquete
# difieren (python311 vs python3.11), las versiones de las librerías base
# difieren, y zypper y dnf no leen los repos igual. Un directorio distinto
# convierte "bundle equivocado" en un error explícito del instalador en vez de
# una resolución de dependencias que falla a mitad de la instalación.
#
# POR QUÉ SE DESCARGA CONTRA UNA RAÍZ VACÍA
# -----------------------------------------
# zypper sólo descarga lo que le falta a ESTA máquina. El contenedor de build ya
# trae media distribución instalada, así que un `--download-only` normal produce
# un bundle que sólo funciona en un destino idéntico al build host. Con
# `--root <dir vacío>` zypper cree que no hay nada instalado y baja el cierre
# COMPLETO — el equivalente de `dnf download --resolve --alldeps` en RHEL.
# ============================================================================
set -euo pipefail

REF="${1:-main}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(cat "$REPO_DIR/VERSION" 2>/dev/null || echo 0.0)"
OUT="${BUNDLE_OUT:-$REPO_DIR/dist}"
STAGE="$OUT/satom-installer"
FAKEROOT="${FAKEROOT:-/tmp/satom-node}"

# Debe coincidir con REQUIRED_PKGS (zypper) del instalador + SSH_PKGS (cluster).
# [SATOM-ABI-OFFLINE] Las librerias del sistema contra las que se compila
# el interprete van EXPLICITAS. Hasta ahora llegaban al bundle solo porque
# la resolucion contra una raiz vacia las arrastraba como dependencia de
# python3.11 — es decir, por suerte. Sin ellas, una imagen base con
# libexpat viejo no puede completar la instalacion offline: el interprete
# falla al importar pyexpat con 'undefined symbol' y no hay red para
# repararlo. install-satom.sh las instala desde aqui cuando detecta el
# desajuste; este listado garantiza que estan.
PKGS=(python311 python311-pip postgresql-server postgresql nginx rsync
      openssl curl ca-certificates sudo openssh
      libexpat1 libopenssl3 libsqlite3-0 libz1)

echo "==> Bundle offline SATOM v${VERSION} — familia SUSE (leap 15, x86_64)"
command -v zypper >/dev/null || { echo "Necesita familia SUSE/zypper (usa opensuse/leap:15.6)"; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "Ejecuta como root (zypper lo necesita)"; exit 1; }

echo "==> 0/4 Herramientas de build (createrepo_c, python311, tar)"
zypper --non-interactive --gpg-auto-import-keys refresh >/dev/null
zypper --non-interactive install -y createrepo_c python311 python311-pip tar gzip \
       findutils curl awk >/dev/null 2>&1 || \
zypper --non-interactive install -y createrepo_c python311 python311-pip tar gzip \
       findutils curl >/dev/null

rm -rf "$STAGE" "$FAKEROOT"
mkdir -p "$STAGE/bundle/rpms-suse" "$STAGE/bundle/wheels" "$STAGE/bundle/lego" "$OUT" "$FAKEROOT"

echo "==> 1/4 Descargando .rpms (cierre completo contra una raíz vacía)"
# Los repos se COPIAN, no se parsean: `zypper lr` es salida para humanos y su
# formato cambia entre versiones. zypper --root lee los .repo de <root>/etc/zypp.
mkdir -p "$FAKEROOT/etc/zypp/repos.d"
cp /etc/zypp/repos.d/*.repo "$FAKEROOT/etc/zypp/repos.d/"
# os-release TIENE que viajar: los .repo usan $releasever y zypper lo deriva del
# os-release DE LA RAIZ. Sin él, las URLs quedan mal formadas, el refresh parece
# funcionar y todos los paquetes se reportan como "not found in package names" —
# un fallo que se lee como "esta distro no tiene python311".
cp /etc/os-release "$FAKEROOT/etc/os-release"
SUSE_RELEASEVER="${SUSE_RELEASEVER:-$(. /etc/os-release; echo "$VERSION_ID")}"
echo "    releasever=${SUSE_RELEASEVER}"

zypper --non-interactive --root "$FAKEROOT" --releasever "$SUSE_RELEASEVER" \
       --no-gpg-checks refresh >/dev/null 2>&1 || true
zypper --non-interactive --root "$FAKEROOT" --releasever "$SUSE_RELEASEVER" \
       --no-gpg-checks install --download-only --no-recommends \
       --auto-agree-with-licenses "${PKGS[@]}" >/dev/null

find "$FAKEROOT" -name '*.rpm' -exec cp -n {} "$STAGE/bundle/rpms-suse/" \;
N=$(ls "$STAGE/bundle/rpms-suse"/*.rpm 2>/dev/null | wc -l)
echo "    $N paquetes .rpm"
[ "$N" -gt 60 ] || { echo "ERROR: muy pocos rpms ($N) — la raíz vacía no resolvió el cierre"; exit 1; }
# Metadatos: en el destino zypper usa bundle/rpms-suse como repo local vía
# --reposd-dir, sin tocar los repos del sistema y sin red.
createrepo_c -q "$STAGE/bundle/rpms-suse"

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

# --- ACME client: el binario estático de lego viaja en el bundle para que una
# instalación OFFLINE tenga ACME/Let's Encrypt operativo. El sha256 del release
# se verifica AQUÍ, en la máquina de build (la que sí tiene red).
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

TARBALL="$OUT/satom-offline-${VERSION}-suse15-x86_64.tar.gz"
tar -C "$OUT" -czf "$TARBALL" satom-installer
( cd "$OUT" && sha256sum "$(basename "$TARBALL")" > "$(basename "$TARBALL").sha256" )
rm -rf "$STAGE" "$FAKEROOT"
echo "==> LISTO: $TARBALL"
echo "    $(cat "$TARBALL.sha256")"
