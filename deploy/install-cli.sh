#!/usr/bin/env bash
# Install (or refresh) the root-owned copy of the SATOM operator CLI.
#
# Idempotent. Run as root. Called from three places so the copy cannot drift:
#   * installers/install-satom.sh          (fresh install)
#   * deploy/self_update_runner.py         (after every code update)
#   * satom execute reinstall cli          (manual)
#
# WHY A COPY AND NOT A SYMLINK: the app tree is owned by the service account.
# A launcher that exec'd code from there would let a compromised web worker
# rewrite what an operator runs under sudo. The sudo target must be a fixed,
# real, root-owned path. 'satom diagnose privilege' asserts exactly that.
set -euo pipefail

APP_DIR="${FM_APP_DIR:-/opt/satom}"
LIB_DIR="/usr/local/lib/satom-cli"
BIN="/usr/local/sbin/satom"
SRC="${APP_DIR}/deploy/satom_cli"
LAUNCHER="${APP_DIR}/deploy/satom-cli-launcher"

if [ "$(id -u)" -ne 0 ]; then
  echo "install-cli.sh: must run as root (it writes ${BIN})." >&2
  exit 3
fi
[ -d "$SRC" ] || { echo "install-cli.sh: missing ${SRC}" >&2; exit 1; }
[ -f "$LAUNCHER" ] || { echo "install-cli.sh: missing ${LAUNCHER}" >&2; exit 1; }

# Replace atomically-ish: build beside, then swap. A half-copied package would
# make the recovery tool itself unimportable.
STAGE="${LIB_DIR}.new.$$"
rm -rf "$STAGE"
mkdir -p "${STAGE}/satom_cli"
cp -a "${SRC}/." "${STAGE}/satom_cli/"
rm -rf "${STAGE}/satom_cli/__pycache__"

chown -R root:root "$STAGE"
find "$STAGE" -type d -exec chmod 0755 {} +
find "$STAGE" -type f -exec chmod 0644 {} +

rm -rf "${LIB_DIR}.old"
[ -d "$LIB_DIR" ] && mv "$LIB_DIR" "${LIB_DIR}.old"
mv "$STAGE" "$LIB_DIR"
rm -rf "${LIB_DIR}.old"

install -o root -g root -m 0755 "$LAUNCHER" "$BIN"

# Verify rather than assume: a wrong owner or mode here is the whole threat.
fail=0
for p in "$BIN" "$LIB_DIR"; do
  owner="$(stat -c %U "$p")"
  mode="$(stat -c %a "$p")"
  case "$owner:$mode" in
    root:755|root:0755) ;;
    *) echo "install-cli.sh: ${p} is ${owner} mode ${mode} — expected root 755" >&2; fail=1 ;;
  esac
done
if [ -L "$BIN" ]; then
  echo "install-cli.sh: ${BIN} is a symlink — the sudo target must be a real path" >&2
  fail=1
fi
[ "$fail" -eq 0 ] || exit 1

"$BIN" show version >/dev/null 2>&1 || {
  echo "install-cli.sh: installed, but '${BIN} show version' failed. Run it by hand." >&2
  exit 1
}

echo "satom CLI installed:"
echo "  binary : ${BIN} (root:root 0755)"
echo "  library: ${LIB_DIR} (root:root)"
echo "  verify : satom diagnose privilege"
echo "  grant  : satom show sudoers <operator-account>"
