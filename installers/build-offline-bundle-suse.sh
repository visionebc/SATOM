#!/usr/bin/env bash
# ============================================================================
# build-offline-bundle-suse.sh — Builds the SATOM OFFLINE installer
# for the SUSE family (openSUSE Leap 15.6 / SLES 15, x86_64).
#
# Run it ON an openSUSE machine or container WITH internet access, e.g.:
#
#   docker run --rm -v /path/to/repo:/src -v /path/app.tar.gz:/app.tar.gz:ro \
#       -e APP_TARBALL=/app.tar.gz -w /src opensuse/leap:15.6 \
#       bash installers/build-offline-bundle-suse.sh
#
# It produces:
#     dist/satom-offline-<version>-suse15-x86_64.tar.gz
#       └── satom-installer/
#           ├── install-satom.sh   (same installer; it detects bundle/rpms-suse)
#           ├── INSTALL.md
#           └── bundle/
#               ├── rpms-suse/  FULL .rpm dependency closure + repodata
#               ├── wheels/     Python packages for python3.11
#               ├── lego/       static ACME client
#               └── app.tar.gz  application code
#
# WHY A DIRECTORY OF ITS OWN AND NOT 'rpms/'
# ------------------------------------------
# Both bundles are .rpm and they are NOT interchangeable: package names differ
# (python311 vs python3.11), base library versions differ, and zypper and dnf
# do not read repositories the same way. A separate directory turns "wrong
# bundle" into an explicit installer error instead of a dependency resolution
# that fails halfway through the install.
#
# WHY IT DOWNLOADS AGAINST AN EMPTY ROOT
# --------------------------------------
# zypper only downloads what THIS machine is missing. The build container
# already has half a distribution installed, so a plain `--download-only`
# produces a bundle that only works on a target identical to the build host.
# With `--root <empty dir>` zypper believes nothing is installed and fetches
# the FULL closure — the equivalent of `dnf download --resolve --alldeps` on RHEL.
# ============================================================================
set -euo pipefail

REF="${1:-main}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(cat "$REPO_DIR/VERSION" 2>/dev/null || echo 0.0)"
OUT="${BUNDLE_OUT:-$REPO_DIR/dist}"
STAGE="$OUT/satom-installer"
FAKEROOT="${FAKEROOT:-/tmp/satom-node}"

# Must match the installer's REQUIRED_PKGS (zypper) + SSH_PKGS (cluster).
# [SATOM-ABI-OFFLINE] The system libraries the interpreter is built against
# are listed EXPLICITLY. Until now they reached the bundle only because
# resolving against an empty root pulled them in as dependencies of
# python3.11 — that is, by luck. Without them, a base image with an old
# libexpat cannot finish an offline install: the interpreter fails to import
# pyexpat with 'undefined symbol' and there is no network to repair it.
# install-satom.sh installs them from here when it detects the mismatch;
# this list guarantees they are present.
PKGS=(python311 python311-pip postgresql-server postgresql nginx rsync
      openssl curl ca-certificates sudo openssh git
      libexpat1 libopenssl3 libsqlite3-0 libz1)

echo "==> SATOM offline bundle v${VERSION} — SUSE family (leap 15, x86_64)"
command -v zypper >/dev/null || { echo "Requires the SUSE family/zypper (use opensuse/leap:15.6)"; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "Run as root (zypper needs it)"; exit 1; }

echo "==> 0/4 Build tools (createrepo_c, python311, tar)"
zypper --non-interactive --gpg-auto-import-keys refresh >/dev/null
zypper --non-interactive install -y createrepo_c python311 python311-pip tar gzip \
       findutils curl awk >/dev/null 2>&1 || \
zypper --non-interactive install -y createrepo_c python311 python311-pip tar gzip \
       findutils curl >/dev/null

rm -rf "$STAGE" "$FAKEROOT"
mkdir -p "$STAGE/bundle/rpms-suse" "$STAGE/bundle/wheels" "$STAGE/bundle/lego" "$STAGE/bundle/victoria-metrics" "$OUT" "$FAKEROOT"

echo "==> 1/4 Downloading .rpms (full closure against an empty root)"
# The repos are COPIED, not parsed: `zypper lr` is human-oriented output and its
# format changes between versions. zypper --root reads the .repo files from <root>/etc/zypp.
mkdir -p "$FAKEROOT/etc/zypp/repos.d"
cp /etc/zypp/repos.d/*.repo "$FAKEROOT/etc/zypp/repos.d/"
# os-release MUST come along: the .repo files use $releasever and zypper derives
# it from the ROOT's os-release. Without it the URLs are malformed, the refresh
# appears to work and every package is reported as "not found in package names"
# — a failure that reads like "this distro has no python311".
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
echo "    $N .rpm packages"
[ "$N" -gt 60 ] || { echo "ERROR: too few rpms ($N) — the empty root did not resolve the closure"; exit 1; }
# Metadata: on the target, zypper uses bundle/rpms-suse as a local repo via
# --reposd-dir, without touching the system repos and without network.
createrepo_c -q "$STAGE/bundle/rpms-suse"

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

TARBALL="$OUT/satom-offline-${VERSION}-suse15-x86_64.tar.gz"
tar -C "$OUT" -czf "$TARBALL" satom-installer
( cd "$OUT" && sha256sum "$(basename "$TARBALL")" > "$(basename "$TARBALL").sha256" )
rm -rf "$STAGE" "$FAKEROOT"
echo "==> DONE: $TARBALL"
echo "    $(cat "$TARBALL.sha256")"
