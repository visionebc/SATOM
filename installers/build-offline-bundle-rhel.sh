#!/usr/bin/env bash
# ============================================================================
# build-offline-bundle-rhel.sh — Builds the SATOM OFFLINE installer
# for the RHEL family (RHEL / Rocky / AlmaLinux 9, x86_64).
#
# Run it ON a RHEL-9 machine or container WITH internet access, e.g.:
#
#   docker run --rm -v /path/to/repo:/src -w /src rockylinux:9 \
#       bash installers/build-offline-bundle-rhel.sh
#
# It produces:
#     dist/satom-offline-<version>-rhel9-x86_64.tar.gz
#       └── satom-installer/
#           ├── install-satom.sh   (same installer; it detects bundle/rpms)
#           ├── INSTALL.md
#           └── bundle/
#               ├── rpms/    FULL .rpm dependency closure
#               ├── wheels/  Python packages for python3.11 (pip download)
#               └── app.tar.gz  application code
#
# The application code comes from `git archive` when the repo is present, or
# from the tarball named in APP_TARBALL= (useful inside a container with no .git).
# ============================================================================
set -euo pipefail

REF="${1:-main}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(cat "$REPO_DIR/VERSION" 2>/dev/null || echo 0.0)"
OUT="${BUNDLE_OUT:-$REPO_DIR/dist}"
STAGE="$OUT/satom-installer"
# Must match the installer's REQUIRED_PKGS (dnf) + best-effort SELinux tooling.
# python3.11: the system python3 on EL9 is 3.9 and the pins require >= 3.10.
# sudo/openssh: see the note in build-offline-bundle.sh — required OFFLINE.
# [SATOM-ABI-OFFLINE] The system libraries the interpreter is built against
# are listed EXPLICITLY. Until now they reached the bundle only because
# resolving against an empty root pulled them in as dependencies of
# python3.11 — that is, by luck. Without them, a base image with an old
# libexpat cannot finish an offline install: the interpreter fails to import
# pyexpat with 'undefined symbol' and there is no network to repair it.
# install-satom.sh installs them from here when it detects the mismatch;
# this list guarantees they are present.
PKGS=(python3.11 python3.11-pip postgresql-server postgresql nginx rsync
      openssl curl ca-certificates policycoreutils-python-utils
      sudo openssh-clients openssh-server git
      expat openssl-libs sqlite-libs zlib)

echo "==> SATOM offline bundle v${VERSION} — RHEL family (el9, x86_64)"
command -v dnf >/dev/null || { echo "Requires the RHEL family/dnf (use rockylinux:9)"; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "Run as root (dnf needs it)"; exit 1; }

echo "==> 0/4 Build tools (dnf-plugins-core, python3.11, tar)"
dnf -y -q install dnf-plugins-core createrepo_c python3.11 python3.11-pip git-core tar gzip findutils >/dev/null

rm -rf "$STAGE"; mkdir -p "$STAGE/bundle/rpms" "$STAGE/bundle/wheels" "$OUT" "$STAGE/bundle/lego" "$STAGE/bundle/victoria-metrics"

echo "==> 1/4 Downloading .rpms (full dependency closure)"
dnf download -q --resolve --alldeps --destdir "$STAGE/bundle/rpms" "${PKGS[@]}"
N=$(ls "$STAGE/bundle/rpms"/*.rpm | wc -l)
echo "    $N .rpm packages"
[ "$N" -gt 40 ] || { echo "ERROR: too few rpms — something went wrong"; exit 1; }
# Repo metadata: on the target, dnf uses bundle/rpms as a local repo
# (--repofrompath) and resolves ONLY what is needed without fighting @System.
createrepo_c -q "$STAGE/bundle/rpms"

echo "==> 2/4 Downloading Python 3.11 wheels (requirements.txt)"
python3.11 -m pip -q download -r "$REPO_DIR/requirements.txt" -d "$STAGE/bundle/wheels"
python3.11 -m pip -q download pip setuptools wheel -d "$STAGE/bundle/wheels"
echo "    $(ls "$STAGE/bundle/wheels" | wc -l) wheels/sdists"

echo "==> 3/4 Packaging the application code"
if [ -n "${APP_TARBALL:-}" ]; then
    cp "$APP_TARBALL" "$STAGE/bundle/app.tar.gz"
    echo "    code from APP_TARBALL=$APP_TARBALL"
else
    git -C "$REPO_DIR" archive --format=tar.gz -o "$STAGE/bundle/app.tar.gz" "$REF"

    echo "    code from git archive ${REF}"
fi

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

TARBALL="$OUT/satom-offline-${VERSION}-rhel9-x86_64.tar.gz"
tar -C "$OUT" -czf "$TARBALL" satom-installer
( cd "$OUT" && sha256sum "$(basename "$TARBALL")" > "$(basename "$TARBALL").sha256" )
rm -rf "$STAGE"
echo "==> DONE: $TARBALL"
echo "    $(cat "$TARBALL.sha256")"
