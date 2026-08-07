#!/usr/bin/env bash
# Install (or refresh) the ROOT-OWNED copy of the privileged update runner.
#
# [SATOM-RUNNER-ROOT-COPY]
#
# WHY THIS EXISTS. satom-updater.service runs as root and its shipped unit says
#
#     ExecStart=/opt/satom/venv/bin/python /opt/satom/deploy/self_update_runner.py
#
# Both of those paths are inside the application tree, which is owned by the
# SERVICE ACCOUNT after the de-privilege. So the unprivileged web worker could
# rewrite the script root is about to execute, then enqueue a request — which
# it is designed to be able to do — and the next trigger runs its code as root.
# That is a complete escalation across the boundary docs/privilege-model.md
# exists to defend, and it makes signature checking meaningless: a verifier the
# attacker can edit verifies nothing.
#
# The fix is the same one already used for the operator CLI: a real, root-owned
# copy outside the tree, plus a system interpreter that the service account
# cannot replace. A drop-in (not an edit to the unit) because self_update_runner
# re-copies deploy/<unit> on every update — an edited unit never survives.
#
# It also installs the root-owned copies of the /usr/local/sbin helper scripts
# ([SATOM-SBIN-ROOT-COPY] below) — same problem, same three call sites, and
# until 2026-08-07 they had no distribution path whatsoever.
#
# Idempotent. Run as root. Called from four places so the copy cannot drift:
#   * installers/install-satom.sh          (fresh install)
#   * deploy/migrate-deprivilege.sh        (existing nodes)
#   * deploy/self_update_runner.py         (after every code update)
#   * satom execute reinstall runner       (manual)
set -euo pipefail

APP_DIR="${FM_APP_DIR:-/opt/satom}"
LIB_DIR="/usr/local/lib/satom-runner"
UNIT="satom-updater.service"
DROPIN_DIR="/etc/systemd/system/${UNIT}.d"
TRUST_DIR="/etc/satom/update-keys"

# Every file root executes or reads as a trust input. update_package.py is here
# for the same reason as the runner: it IS the signature verifier.
FILES="self_update_runner.py update_package.py"

# [SATOM-SBIN-ROOT-COPY]
# Helper scripts that the units execute from /usr/local/sbin rather than from
# the app tree. They had NO distribution path at all: the installer copied them
# once at install time and deploy/migrate-deprivilege.sh once at migration, and
# nothing ever refreshed them, so the RUNNING copy drifted from git and stayed
# drifted. /usr/local/sbin/satom-ha-datasync.sh was 5297 bytes dated Jul 26
# while deploy/satom-ha-datasync.sh was 5943 bytes dated Aug 4, missing both of
# its fixes: the venv interpreter (openSUSE has no /usr/bin/python3) and a peer
# probe that exits non-zero when it cannot be evaluated instead of pretending
# "no peer configured". The replicator was reporting SUCCESS while replicating
# nothing -- the same overlay bug, applied to the sync mechanism itself.
#
# Kept in sync with the loop in installers/install-satom.sh that seeds them;
# tests/test_unit_distribution.py reads that loop and fails if the two diverge.
SBIN_DIR="/usr/local/sbin"
SBIN_FILES="satom-ha-datasync.sh satom-promote.sh satom-ha-rsync-shell"

if [ "$(id -u)" -ne 0 ]; then
  echo "install-runner.sh: must run as root (it writes ${LIB_DIR})." >&2
  exit 3
fi
for f in $FILES; do
  [ -f "${APP_DIR}/deploy/${f}" ] || {
    echo "install-runner.sh: missing ${APP_DIR}/deploy/${f}" >&2; exit 1; }
done

# Same interpreter policy as install-cli.sh: a SYSTEM python >= 3.10, never the
# venv (the runner must work when the venv is broken — that is when an offline
# package is applied) and never anything inside the app tree.
pick_runner_python() {
  local c v
  for c in /usr/bin/python3 /usr/bin/python3.13 /usr/bin/python3.12 \
           /usr/bin/python3.11 /usr/bin/python3.10 \
           /usr/local/bin/python3.13 /usr/local/bin/python3.12 \
           /usr/local/bin/python3.11 /usr/local/bin/python3.10; do
    [ -x "$c" ] || continue
    case "$c" in "${APP_DIR}"/*) continue ;; esac
    v="$("$c" -c 'import sys;print("%d.%d" % sys.version_info[:2])' 2>/dev/null)" || continue
    case "$v" in
      3.1[0-9]|3.[2-9][0-9]) echo "$c"; return 0 ;;
    esac
  done
  return 1
}

RUN_PY="$(pick_runner_python)" || {
  echo "install-runner.sh: no system Python >= 3.10 found for the update runner." >&2
  echo "  Install python3.11 (or newer) and re-run:" >&2
  echo "    bash ${APP_DIR}/deploy/install-runner.sh" >&2
  exit 1
}

# Build beside, then swap: a half-copied runner is a runner that cannot roll back.
STAGE="${LIB_DIR}.new.$$"
rm -rf "$STAGE"
mkdir -p "$STAGE"
for f in $FILES; do
  cp -a "${APP_DIR}/deploy/${f}" "${STAGE}/${f}"
done
chown -R root:root "$STAGE"
chmod 0755 "$STAGE"
find "$STAGE" -type f -exec chmod 0644 {} +

# The verifier must import before it is trusted with an update.
"$RUN_PY" -c "
import importlib.util, sys
spec = importlib.util.spec_from_file_location('up', '${STAGE}/update_package.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
seed = bytes(range(32))
pub = m.ed25519_public_from_seed(seed)
assert m.ed25519_verify(pub, b'satom', m.ed25519_sign(seed, b'satom'))
assert not m.ed25519_verify(pub, b'satom', m.ed25519_sign(seed, b'other'))
" || {
  echo "install-runner.sh: the signature verifier failed its self-test — refusing to install." >&2
  rm -rf "$STAGE"; exit 1
}

rm -rf "${LIB_DIR}.old"
[ -d "$LIB_DIR" ] && mv "$LIB_DIR" "${LIB_DIR}.old"
mv "$STAGE" "$LIB_DIR"
rm -rf "${LIB_DIR}.old"

# ---- point the unit at the root-owned copy -------------------------------
mkdir -p "$DROPIN_DIR"
cat > "${DROPIN_DIR}/10-root-copy.conf" <<EOF
# Generated by SATOM (install-runner.sh). DO NOT EDIT.
#
# [SATOM-RUNNER-ROOT-COPY] The shipped unit points at the app tree, which the
# service account owns. Running that as root is a privilege escalation, so the
# ExecStart is redirected to a root-owned copy with a system interpreter.
# A drop-in and not an edit: self_update_runner re-copies deploy/<unit> on
# every update, so an edited unit would silently revert.
[Service]
ExecStart=
ExecStart=${RUN_PY} ${LIB_DIR}/self_update_runner.py
Environment=FM_APP_DIR=${APP_DIR}
Environment=SATOM_TRUST_DIR=${TRUST_DIR}
EOF
chmod 0644 "${DROPIN_DIR}/10-root-copy.conf"

# ---- trust store ---------------------------------------------------------
# Created here rather than by the installer alone so an upgraded node gets one
# too. Empty is a valid state: it means this node accepts no package yet.
mkdir -p "$TRUST_DIR"
chown root:root /etc/satom "$TRUST_DIR"
chmod 0755 /etc/satom "$TRUST_DIR"

# ---- root-owned copies of the /usr/local/sbin helpers --------------------
# [SATOM-SBIN-ROOT-COPY] root:root 0755 for the same reason as ${LIB_DIR}: a
# script the service account can rewrite is a script the service account can
# make root (or the peer's app account) run. Missing sources are skipped rather
# than fatal -- satom-ha-rsync-shell only ships on some branches -- but a
# source that IS present and fails to install is a hard failure below.
for f in $SBIN_FILES; do
  src="${APP_DIR}/deploy/${f}"
  if [ -f "$src" ]; then
    install -o root -g root -m 0755 "$src" "${SBIN_DIR}/${f}"
  fi
done

systemctl daemon-reload 2>/dev/null || true

# ---- verify rather than assume ------------------------------------------
fail=0
for p in "$LIB_DIR" "$TRUST_DIR"; do
  owner="$(stat -c %U "$p")"; mode="$(stat -c %a "$p")"
  case "$owner:$mode" in
    root:755|root:0755) ;;
    *) echo "install-runner.sh: ${p} is ${owner} mode ${mode} — expected root 755" >&2; fail=1 ;;
  esac
done
for f in $FILES; do
  owner="$(stat -c %U "${LIB_DIR}/${f}")"
  [ "$owner" = root ] || { echo "install-runner.sh: ${LIB_DIR}/${f} is ${owner}" >&2; fail=1; }
done
for f in $SBIN_FILES; do
  src="${APP_DIR}/deploy/${f}"; dst="${SBIN_DIR}/${f}"
  [ -f "$src" ] || continue
  owner="$(stat -c %U "$dst" 2>/dev/null || echo MISSING)"
  mode="$(stat -c %a "$dst" 2>/dev/null || echo -)"
  case "$owner:$mode" in
    root:755|root:0755) ;;
    *) echo "install-runner.sh: ${dst} is ${owner} mode ${mode} — expected root 755" >&2; fail=1 ;;
  esac
  # Byte-identical, not merely present: "installed once, years ago" is exactly
  # the state this section exists to end.
  cmp -s "$src" "$dst" || { echo "install-runner.sh: ${dst} differs from ${src}" >&2; fail=1; }
done
ACTUAL="$(systemctl show -p ExecStart --value "$UNIT" 2>/dev/null || true)"
case "$ACTUAL" in
  *"${LIB_DIR}/self_update_runner.py"*) ;;
  *) echo "install-runner.sh: ${UNIT} still starts: ${ACTUAL}" >&2; fail=1 ;;
esac
[ "$fail" -eq 0 ] || exit 1

echo "SATOM update runner hardened:"
echo "  code       : ${LIB_DIR} (root:root, system python ${RUN_PY})"
echo "  trust store: ${TRUST_DIR} ($(ls -1 "$TRUST_DIR"/*.pub 2>/dev/null | wc -l) key(s))"
echo "  sbin       : ${SBIN_DIR} ($(for f in $SBIN_FILES; do [ -f "${APP_DIR}/deploy/${f}" ] && printf '%s ' "$f"; done))"
echo "  verify     : satom diagnose privilege"
