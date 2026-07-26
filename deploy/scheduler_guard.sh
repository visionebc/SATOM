#!/usr/bin/env bash
# The scheduled-action firer must run on the Postgres PRIMARY ONLY. On a
# standby it idle-waits and re-checks, so promoting the DB auto-starts the
# scheduler here with NO external coordination — and two nodes never both fire
# (which for a firmware-upgrade action would mean a double flash).
#
# The role probe lives in satom-node-role.sh because the obvious idiom
# (`runuser -u postgres -- psql`) requires root, and since v1.2 this unit runs
# as the service account. With the old probe the role came back EMPTY, this
# loop took the standby branch forever, and systemd still showed the unit as
# "active (running)" — no scheduled action fired and nothing alerted.
set -u
APP=/opt/satom
ROLE_PROBE="$APP/deploy/satom-node-role.sh"

[ -x "$ROLE_PROBE" ] || { echo "scheduler_guard: falta $ROLE_PROBE" >&2; exit 1; }

while :; do
  case "$("$ROLE_PROBE" 2>/dev/null)" in
    f) exec "$APP/venv/bin/python" -m app.scheduler_runtime ;;  # primary
    *) sleep 30 ;;   # standby ('t') or DB not ready ('') → wait, re-check, promote auto-starts us
  esac
done
