#!/bin/bash
# Evaluate the proactive health checks and dispatch new alerts (email + in-app
# bell). Runs on every node (cert / device-reachability / git-lag are node-local
# truths). Invoked by satom-alerts.timer.
set -euo pipefail
set -a; . /opt/satom/.env; set +a
cd /opt/satom

# ---------------------------------------------------------------------------
# Last resort: say what is wrong when the alert engine itself cannot.
#
# Every finding this engine raises is recorded and dispatched THROUGH the
# database, so the one condition it can never report is the one that takes the
# database down with it. Measured, on 2026-08-22: this node filled its disk at
# 05:00, PostgreSQL entered a crash -> recovery -> PANIC loop because it could
# not write a checkpoint, and this unit failed every fifteen minutes for an
# hour with `OperationalError: connection failed`. Disk thresholds existed
# (warn 80 %, crit 92 %) and were useless, because evaluating them needs the
# thing that was already broken. The sentence "the filesystem is 100 % full"
# was never written anywhere -- while /healthz kept answering 200.
#
# So on failure we do not exit quietly on a stack trace: we print the machine's
# own numbers to stdout, which systemd puts in the journal, which is where
# someone reading a failed unit is already looking. No database, no network,
# no dependency that can be down at the same time.
# ---------------------------------------------------------------------------
# `rc=$?` after an `if` reads the exit status of the IF, which is 0 -- the
# failure would be reported as rc=0 and the unit would exit successfully.
rc=0
env FLASK_APP=wsgi:app venv/bin/flask alerts-run || rc=$?
[ "$rc" = 0 ] && exit 0

state=$(df -P -h /opt/satom 2>/dev/null | awk 'NR==2 {printf "filesystem %s used, %s free", $5, $4}')
mem=$(free -m 2>/dev/null | awk '/^Mem:/ {printf "memory %s/%s MB used", $3, $2}')
load=$(cut -d" " -f1-3 /proc/loadavg 2>/dev/null)
echo "alerts-run FAILED (rc=$rc) and could not raise a finding about it." \
     "Machine state read WITHOUT the database: ${state:-df unavailable};" \
     "${mem:-free unavailable}; load ${load:-unavailable}." \
     "A full filesystem here means PostgreSQL cannot checkpoint, every unit" \
     "that needs it fails, and /healthz still answers 200 -- see" \
     "docs/sizing.md section 5." >&2
command -v logger >/dev/null 2>&1 && \
    logger -p daemon.crit -t satom-alerts \
    "alerts-run failed (rc=$rc): ${state:-df unavailable}; ${mem:-free unavailable}; load ${load:-unavailable}"
exit "$rc"
