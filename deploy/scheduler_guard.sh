#!/usr/bin/env bash
# The scheduled-action firer must run on the Postgres PRIMARY ONLY. On a
# standby it idle-waits and re-checks, so promoting the DB auto-starts the
# scheduler here with NO external coordination — and two nodes never both fire
# (which for a firmware-upgrade action would mean a double flash).
set -u
role() { runuser -u postgres -- psql -tAc "select pg_is_in_recovery()" 2>/dev/null; }
while :; do
  case "$(role)" in
    f) exec /opt/fortinet-manager/venv/bin/python -m app.scheduler_runtime ;;  # primary
    *) sleep 30 ;;   # standby ('t') or DB not ready ('') → wait, re-check, promote auto-starts us
  esac
done
