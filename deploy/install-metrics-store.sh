#!/usr/bin/env bash
# Install (or re-assert) the node-local metrics store — VictoriaMetrics.
#
# Idempotent. Run as root. Called from three places so the node cannot drift:
#   * installers/install-satom.sh          (fresh install)
#   * deploy/self_update_runner.py         (after every code update, EVERY node)
#   * satom execute reinstall metrics-store (manual)
#
# [SATOM-METRICS-NODE-LOCAL]
# WHY THIS SCRIPT EXISTS AT ALL. The store binary and its data directory live
# OUTSIDE the app tree on purpose: satom-ha-datasync replicates data/ with
# rsync --delete, and a TSDB cannot be rsynced under a live process. The cost
# of that correct decision is that NOTHING carries the store between nodes —
# not git, not the datasync, not a pg_dump. It was installed by the installer
# and never again, so a node that joined later, or was rebuilt, simply had no
# store while every other signal said the pair was healthy. Its analytics
# panels returned a query error, which reads as a UI bug rather than a missing
# subsystem.
#
# That is the SAME failure class the operator CLI and the /usr/local/sbin
# helpers already have a re-assert for -- see the comment at the call site in
# self_update_runner.py, which records satom-ha-datasync.sh sitting eleven days
# and two bug-fixes behind git while reporting SUCCESS. The fix is the same:
# every node re-asserts its own node-local artifacts on every code update.
#
# NEVER fatal. A code update must not fail because a binary could not be
# fetched; on an air-gapped management network that would make the product
# un-updatable. Absence is reported by 'satom diagnose install' instead, which
# is the surface that survives the update being long over.
set -uo pipefail

APP_DIR="${FM_APP_DIR:-/opt/satom}"
VM_BIN="/usr/local/bin/victoria-metrics"
VM_DATA="/var/lib/satom-metrics"
UNIT="satom-metrics.service"
UNIT_SRC="${APP_DIR}/deploy/${UNIT}"
ENV_FILE="${APP_DIR}/deploy/metrics-store.env"

if [ "$(id -u)" -ne 0 ]; then
  echo "install-metrics-store.sh: must run as root (it writes ${VM_BIN})." >&2
  exit 3
fi

# The artifact identity has ONE home. Refuse rather than guess: a wrong digest
# silently installs nothing, and "nothing installed" is what we came to fix.
if [ ! -f "$ENV_FILE" ]; then
  echo "install-metrics-store.sh: missing ${ENV_FILE}" >&2
  exit 1
fi
# shellcheck disable=SC1090
. "$ENV_FILE"
if [ -z "${VM_VERSION:-}" ] || [ -z "${VM_SHA256:-}" ]; then
  echo "install-metrics-store.sh: ${ENV_FILE} does not define VM_VERSION/VM_SHA256" >&2
  exit 1
fi

# The service account owns the data dir. Derived from the tree, never a
# hardcoded name: installs adopt an existing account (a1/a2 adopted 'fortinet'
# before the rename) and a literal here reintroduced exactly that bug in the
# datasync script once already.
APP_USER="$(stat -c %U "$APP_DIR" 2>/dev/null || echo root)"

sha_ok() { [ -f "$1" ] && [ "$(sha256sum "$1" | awk '{print $1}')" = "$VM_SHA256" ]; }

INSTALLED_NOW=0
BUNDLE_BIN=""
for _c in "${APP_DIR}/bundle/victoria-metrics/victoria-metrics" \
          "${BUNDLE_DIR:-/nonexistent}/victoria-metrics/victoria-metrics"; do
  [ -f "$_c" ] && { BUNDLE_BIN="$_c"; break; }
done

if sha_ok "$VM_BIN"; then
  echo "victoria-metrics ${VM_VERSION} already present (sha256 verified)"
elif [ -n "$BUNDLE_BIN" ] && sha_ok "$BUNDLE_BIN"; then
  install -m 0755 "$BUNDLE_BIN" "$VM_BIN" \
    && { INSTALLED_NOW=1; echo "victoria-metrics ${VM_VERSION} installed from the offline bundle (sha256 verified)"; }
else
  # Bundle absent or wrong. Try the network -- bounded, so an update on an
  # isolated network fails fast instead of stalling the runner.
  # NOTE the artifact name: the same upstream tag also publishes -cluster and
  # -enterprise builds, and the enterprise one is NOT Apache-2.0. The name is
  # fixed and the digest is anchored: anything else is not installed.
  _vt="$(mktemp -d)"
  if curl -fsSL --max-time 120 -o "$_vt/vm.tgz" \
      "https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/v${VM_VERSION}/victoria-metrics-linux-amd64-v${VM_VERSION}.tar.gz" \
     && tar xzf "$_vt/vm.tgz" -C "$_vt" victoria-metrics-prod 2>/dev/null \
     && sha_ok "$_vt/victoria-metrics-prod"; then
    install -m 0755 "$_vt/victoria-metrics-prod" "$VM_BIN" \
      && { INSTALLED_NOW=1; echo "victoria-metrics ${VM_VERSION} installed (sha256 verified)"; }
  else
    echo "WARN victoria-metrics ${VM_VERSION} not installed (no bundle, and the download failed or did not match the anchored sha256)." >&2
  fi
  rm -rf "$_vt"
fi

if [ ! -x "$VM_BIN" ]; then
  echo "WARN metrics store absent on this node; 'satom diagnose install' will report it." >&2
  exit 4
fi

install -d -m 0750 -o "$APP_USER" -g "$APP_USER" "$VM_DATA"

UNIT_WAS_MISSING=0
[ -f "/etc/systemd/system/${UNIT}" ] || UNIT_WAS_MISSING=1
if [ -f "$UNIT_SRC" ]; then
  install -m 0644 "$UNIT_SRC" "/etc/systemd/system/${UNIT}"
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

# ARM IT ONLY WHEN THE CAPABILITY DID NOT EXIST A MOMENT AGO.
#
# If the binary and the unit were already here, the enable/start state belongs
# to the OPERATOR -- Settings -> General now has Stop/Start buttons for exactly
# this unit, and a re-assert that re-enabled it on every code update would
# silently undo a deliberate stop. Conversely a node that never had the store
# must not stay inert just because nobody noticed: that is the drift this
# script exists to end.
if [ "$INSTALLED_NOW" -eq 1 ] || [ "$UNIT_WAS_MISSING" -eq 1 ]; then
  if systemctl enable --now "$UNIT" >/dev/null 2>&1; then
    echo "${UNIT} enabled and started"
  else
    echo "WARN ${UNIT} installed but did not start; check 'journalctl -u ${UNIT}'." >&2
  fi
else
  echo "${UNIT} left as the operator set it ($(systemctl is-enabled "$UNIT" 2>/dev/null || echo unknown)/$(systemctl is-active "$UNIT" 2>/dev/null || echo unknown))"
fi
exit 0
