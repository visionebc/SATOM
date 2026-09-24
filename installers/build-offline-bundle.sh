#!/usr/bin/env bash
# ============================================================================
# build-offline-bundle.sh — Builds the SATOM OFFLINE installer.
#
# Run it on a Debian 12 amd64 machine WITH internet access (same distro/arch
# as the target). It produces:
#
#     dist/satom-offline-<version>-debian12-amd64.tar.gz
#       └── satom-installer/
#           ├── install-satom.sh     (the same installer; it detects bundle/)
#           ├── INSTALL.md               (manual for the systems team)
#           └── bundle/
#               ├── debs/     FULL .deb dependency closure
#               ├── wheels/   every Python package (pip download)
#               └── app.tar.gz  application code (git archive of the prod repo)
#
# Usage:  sudo bash installers/build-offline-bundle.sh [git-ref]   (default: main)
# ============================================================================
set -euo pipefail

REF="${1:-main}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(cat "$REPO_DIR/VERSION" 2>/dev/null || echo 0.0)"
OUT="$REPO_DIR/dist"
STAGE="$OUT/satom-installer"
# sudo: the privilege model writes /etc/sudoers.d and validates it with visudo.
# Without it an OFFLINE install aborts AFTER creating the service account
# (see install-satom.sh [PFSUDO]).
# openssh-*: replication channel for data/ in cluster mode; with no network
# there is nowhere to fetch it from.
PKGS=(python3 python3-venv python3-pip postgresql nginx rsync openssl curl ca-certificates
      sudo openssh-client openssh-server git)

echo "==> SATOM offline bundle v${VERSION} (ref ${REF})"
command -v apt-get >/dev/null || { echo "Requires Debian/apt"; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo (apt needs root)"; exit 1; }

rm -rf "$STAGE"; mkdir -p "$STAGE/bundle/debs" "$STAGE/bundle/wheels" "$STAGE/bundle/lego" "$STAGE/bundle/victoria-metrics"

echo "==> 1/4 Downloading .debs (full dependency closure)"
apt-get update -qq
DEPS=$(apt-cache depends --recurse --no-recommends --no-suggests --no-conflicts \
        --no-breaks --no-replaces --no-enhances "${PKGS[@]}" \
        | grep '^[a-z0-9]' | sort -u)
(cd "$STAGE/bundle/debs" && apt-get download $DEPS 2>/dev/null || true)
N=$(ls "$STAGE/bundle/debs" | wc -l)
echo "    $N .deb packages"
[ "$N" -gt 50 ] || { echo "ERROR: too few debs — something went wrong"; exit 1; }

echo "==> 2/4 Downloading Python wheels (requirements.txt)"
python3 -m venv /tmp/satom-bundle-venv
/tmp/satom-bundle-venv/bin/pip -q install --upgrade pip
/tmp/satom-bundle-venv/bin/pip download -q -r "$REPO_DIR/requirements.txt" \
    -d "$STAGE/bundle/wheels"
/tmp/satom-bundle-venv/bin/pip download -q pip setuptools wheel -d "$STAGE/bundle/wheels"
echo "    $(ls "$STAGE/bundle/wheels" | wc -l) wheels/sdists"

echo "==> 3/4 Packaging the application code (git archive ${REF})"
git -C "$REPO_DIR" archive --format=tar.gz -o "$STAGE/bundle/app.tar.gz" "$REF"

# --- ACME client: the static lego binary ships in the bundle so that an
# OFFLINE install has a working ACME/Let's Encrypt client. The release sha256
# is verified HERE, on the build machine (the one that does have network).
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
echo "    lego ${LEGO_VERSION} added to the bundle (sha256 verified)"

# --- Metrics store: the VictoriaMetrics binary ships in the bundle so that an
# install with no internet access still has data in /monitoring/analytics.
# The sha256 is that of the EXTRACTED binary (victoria-metrics-prod), pinned
# here and re-verified by the installer.
# NOTE: the same tag publishes -cluster and -enterprise builds; enterprise is
# NOT Apache-2.0. The artefact name is pinned on purpose.   [SATOM-METRICS-BUNDLE]
VM_VERSION="${VM_VERSION:-1.148.0}"
VM_SHA256="${VM_SHA256:-bde7ea38c7c9b341a0bb1f37294d6d619ff0318d70174008b57d83cd4f5698f3}"
_vt="$(mktemp -d)"
curl -fsSLo "$_vt/vm.tgz" "https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/v${VM_VERSION}/victoria-metrics-linux-amd64-v${VM_VERSION}.tar.gz" \
  || { echo "victoria-metrics: download failed"; exit 1; }
tar xzf "$_vt/vm.tgz" -C "$_vt" victoria-metrics-prod \
  || { echo "victoria-metrics: the tarball does not contain victoria-metrics-prod"; exit 1; }
_got="$(sha256sum "$_vt/victoria-metrics-prod" | awk '{print $1}')"
[ "$_got" = "$VM_SHA256" ] || { echo "victoria-metrics sha256 mismatch: $_got"; exit 1; }
install -m 0755 "$_vt/victoria-metrics-prod" "$STAGE/bundle/victoria-metrics/victoria-metrics"
rm -rf "$_vt"
echo "    victoria-metrics ${VM_VERSION} added to the bundle (sha256 verified)"


echo "==> 4/4 Installer + manual + final tarball"
cp "$REPO_DIR/installers/install-satom.sh" "$STAGE/"
cp "$REPO_DIR/installers/satom-setup.sh" "$STAGE/"   # guided installer; uses the sibling install-satom.sh
cp "$REPO_DIR/docs/INSTALL.md" "$STAGE/" 2>/dev/null || true
chmod +x "$STAGE/install-satom.sh" "$STAGE/satom-setup.sh"

TARBALL="$OUT/satom-offline-${VERSION}-debian12-amd64.tar.gz"
tar -C "$OUT" -czf "$TARBALL" satom-installer
# The .sha256 holds ONLY the basename, so "sha256sum -c file.sha256" works in
# the user's download directory (with an absolute path it failed).
( cd "$(dirname "$TARBALL")" && sha256sum "$(basename "$TARBALL")" > "$(basename "$TARBALL").sha256" )
cat "$TARBALL.sha256"
echo ""
echo "Done: $TARBALL ($(du -h "$TARBALL" | cut -f1))"
echo "On the target:  tar xzf $(basename "$TARBALL") && cd satom-installer && sudo bash install-satom.sh"
