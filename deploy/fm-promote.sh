#!/usr/bin/env bash
# fm-promote.sh — guarded MANUAL failover for the Fortinet Manager HA pair.
#
# Promotes THIS node's Postgres standby to a read-write primary and brings the
# web app up. Invoked ONLY by the privileged updater runner
# (deploy/self_update_runner.py, running as root) after the admin typed the
# node's hostname to confirm in the Software Update → High Availability panel.
#
# It is NEVER auto-invoked. With two standalone Postgres hosts and no quorum,
# automatic promotion would invite split-brain (two primaries). Promotion is
# always an explicit operator decision, taken only when the old primary is known
# to be down. Re-attaching the old node afterwards is a pg_rewind/basebackup job
# (see the runbook), not this script.
set -uo pipefail

PGVER="${FM_PGVER:-15}"
SERVICE="${FM_SERVICE:-fortinet-manager.service}"
SCHED="${FM_SCHED:-fortinet-manager-scheduler.service}"
HEALTH="${FM_HEALTH_URL:-http://127.0.0.1:8000/healthz}"

log() { echo "[fm-promote] $*"; }

# 0. Refuse unless we really are a standby (idempotent / anti-footgun).
inrec="$(runuser -u postgres -- psql -tAc 'SELECT pg_is_in_recovery()' 2>/dev/null | tr -d '[:space:]')"
if [ "$inrec" != "t" ]; then
  log "local Postgres is NOT in recovery (pg_is_in_recovery=${inrec:-?}) — already primary? refusing."
  exit 2
fi

# 1. Promote the standby.
log "promoting Postgres cluster ${PGVER}/main to primary…"
if command -v pg_ctlcluster >/dev/null 2>&1; then
  pg_ctlcluster "$PGVER" main promote || true
else
  runuser -u postgres -- psql -tAc 'SELECT pg_promote()' || true
fi

# 2. Wait until it leaves recovery (becomes read-write).
for _ in $(seq 1 30); do
  inrec="$(runuser -u postgres -- psql -tAc 'SELECT pg_is_in_recovery()' 2>/dev/null | tr -d '[:space:]')"
  [ "$inrec" = "f" ] && break
  sleep 1
done
if [ "$inrec" != "f" ]; then
  log "Postgres did not leave recovery within 30s — aborting."
  exit 3
fi
log "Postgres is now read-write (primary)."

# 3. Bring the app up (it may have been stopped/idle as a standby) and restart
#    the scheduler (its pg_is_in_recovery guard now sees a primary and fires).
systemctl enable --now "$SERVICE" 2>/dev/null || systemctl restart "$SERVICE"
systemctl restart "$SCHED" 2>/dev/null || true

# 4. Health check.
for _ in $(seq 1 30); do
  code="$(curl -sf -o /dev/null -w '%{http_code}' "$HEALTH" 2>/dev/null || true)"
  [ "$code" = "200" ] && { log "health check 200 — promotion complete."; exit 0; }
  sleep 1
done
log "health check did not reach 200 after promotion."
exit 1
