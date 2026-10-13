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
# [SATOM-RELEASE-TRUST] Where the unit template and metrics-store.env (which is
# SOURCED, as root, below) are read from. Unset = the app tree's deploy/
# (historical behaviour); the update runner and the root CLI point it at a
# root-only staged copy of the newest SIGNED release when an anchor is installed.
DEPLOY_SRC="${SATOM_DEPLOY_SRC:-${APP_DIR}/deploy}"
UNIT_SRC="${DEPLOY_SRC}/${UNIT}"
ENV_FILE="${DEPLOY_SRC}/metrics-store.env"

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

# [SATOM-METRICS-AUTHKEYS] authKeys for the store's admin endpoints.
# Loopback-only and SSRF-guarded already, so this is defense in depth against
# any OTHER local account (and a future SSRF) reaching delete_series & co.
# The unit reads them with EnvironmentFile= (systemd reads it as root before
# dropping to the service account) and -envflag.enable -envflag.prefix=VM_,
# so they appear neither in the unit nor on the world-readable command line.
# Generated once, kept across runs (per key: a key added to the list later is
# generated without rotating the others).
# The snapshot key is the one the APPLICATION uses (Settings -> metrics store
# snapshots), so it also lives in a root:<account> 0640 file the app reads.
# LIMIT: the store itself runs as the service account, which can read its own
# process environment -- these keys keep out every account EXCEPT that one.
AUTH_DIR="/etc/satom"
AUTH_ENV="${AUTH_DIR}/metrics-auth.env"
SNAP_KEY="${AUTH_DIR}/metrics-snapshot.key"
AUTH_FLAGS="deleteAuthKey forceMergeAuthKey forceFlushAuthKey reloadAuthKey
            search_resetCacheAuthKey configAuthKey flagsAuthKey pprofAuthKey
            logNewSeriesAuthKey metricNamesStatsResetAuthKey"
AUTH_CHANGED=0
gen_key() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
key_ok() { printf '%s' "$1" | grep -Eq '^[0-9a-f]{64}$'; }
(
  umask 077
  install -d -m 0755 -o root -g root "$AUTH_DIR"
  _snap="$(cat "$SNAP_KEY" 2>/dev/null | tr -d '[:space:]')"
  if ! key_ok "$_snap"; then
    _snap="$(gen_key)"
    printf '%s\n' "$_snap" > "${SNAP_KEY}.tmp" && mv -f "${SNAP_KEY}.tmp" "$SNAP_KEY"
  fi
  chown root:"$APP_USER" "$SNAP_KEY" && chmod 0640 "$SNAP_KEY"
  _tmp="$(mktemp "${AUTH_DIR}/.metrics-auth.XXXXXX")" || exit 1
  {
    echo "# Generated by install-metrics-store.sh. ROOT ONLY (0600). VictoriaMetrics"
    echo "# admin-endpoint authKeys, read by satom-metrics.service via EnvironmentFile=."
    for _k in $AUTH_FLAGS; do
      _v="$(sed -n "s/^VM_${_k}=//p" "$AUTH_ENV" 2>/dev/null | tail -n 1)"
      key_ok "$_v" || _v="$(gen_key)"
      echo "VM_${_k}=${_v}"
    done
    echo "VM_snapshotAuthKey=${_snap}"
  } > "$_tmp"
  if ! cmp -s "$_tmp" "$AUTH_ENV"; then
    chmod 0600 "$_tmp" && chown root:root "$_tmp" && mv -f "$_tmp" "$AUTH_ENV" && exit 10
  fi
  rm -f "$_tmp"
  exit 0
)
case $? in
  0)  echo "metrics store authKeys present (${AUTH_ENV}, root-only)" ;;
  10) AUTH_CHANGED=1; echo "metrics store authKeys written (${AUTH_ENV}, root-only)" ;;
  *)  echo "WARN could not write the metrics store authKeys; the admin endpoints stay unkeyed." >&2 ;;
esac
chown root:root "$AUTH_ENV" 2>/dev/null && chmod 0600 "$AUTH_ENV" 2>/dev/null

UNIT_WAS_MISSING=0
STARTED_NOW=0
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
    STARTED_NOW=1
    echo "${UNIT} enabled and started"
  else
    echo "WARN ${UNIT} installed but did not start; check 'journalctl -u ${UNIT}'." >&2
  fi
else
  echo "${UNIT} left as the operator set it ($(systemctl is-enabled "$UNIT" 2>/dev/null || echo unknown)/$(systemctl is-active "$UNIT" 2>/dev/null || echo unknown))"
fi

# [SATOM-METRICS-AUTHKEYS] Keys only take effect when the store (re)starts.
# A RUNNING store that predates them (no -envflag.enable on its command line)
# or whose keys just changed is restarted -- try-restart, so a store the
# operator stopped stays stopped. A few seconds of ingest gap; the scrape
# records it as an error and the next run fills on.
_pid="$(systemctl show -p MainPID --value "$UNIT" 2>/dev/null || echo 0)"
if [ "$STARTED_NOW" -eq 0 ] && [ "${_pid:-0}" != "0" ] && [ -r "/proc/${_pid}/cmdline" ]; then
  if [ "$AUTH_CHANGED" -eq 1 ] \
     || ! tr '\0' '\n' < "/proc/${_pid}/cmdline" | grep -qx -- '-envflag.enable'; then
    if systemctl try-restart "$UNIT" >/dev/null 2>&1; then
      echo "${UNIT} restarted to load its authKeys"
    else
      echo "WARN ${UNIT} did not restart cleanly; check 'journalctl -u ${UNIT}'." >&2
    fi
  fi
fi
exit 0
