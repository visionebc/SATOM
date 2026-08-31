#!/bin/sh
# Container replacement for the two systemd timers on a host install:
#
#   satom-alerts.timer      every 15 min   -> flask alerts-run
#   satom-responder.timer   every  1 min   -> python -m app.cli_sentinel responder-tick
#
# One loop rather than two containers, because these two jobs are the ONLY
# periodic work in the product and a second container to run a one-line command
# every minute is a second thing to notice has stopped.
#
# Deliberately NOT cron/anacron: a cron daemon in a container swallows stdout
# into a mail spool nobody reads, and the whole point of running under a
# container engine is that `docker compose logs` is the log.
#
# The tick is 60 s and alerts fire every 15th tick. A drifting scheduler is
# fine here: both jobs are idempotent evaluations, not state transitions.
set -u

TICK="${SATOM_CRON_TICK_SECONDS:-60}"
ALERTS_EVERY="${SATOM_CRON_ALERTS_TICKS:-15}"
ROLE_PROBE=/opt/satom/deploy/docker/node-role.sh

log() { echo "[cron] $(date -u +%Y-%m-%dT%H:%M:%SZ) $*"; }

log "starting: tick=${TICK}s alerts every ${ALERTS_EVERY} ticks"

n=0
while :; do
    n=$((n + 1))

    # Both jobs WRITE (findings, dispatch records, response state), so both are
    # primary-only. On a standby the database is read-only and every tick would
    # log an exception -- an error stream that means "working as designed",
    # which is how a real error stops being visible.
    role="$("$ROLE_PROBE" 2>/dev/null || true)"
    if [ "$role" != "f" ]; then
        [ $((n % 15)) -eq 1 ] && log "standby or db not ready (role='${role}') — idle"
        sleep "$TICK"
        continue
    fi

    # A failing job must never kill the loop: the responder failing at 03:00
    # would otherwise also stop alerts, and the alert engine is what tells the
    # operator the responder is failing.
    # rc captured on its own line. Inside `if ! cmd; then log "$?"`, $?
    # holds the status of the TEST, not of the command -- which printed
    # "responder-tick FAILED (rc=0)" for a genuine failure.
    python -m app.cli_sentinel responder-tick || log "responder-tick FAILED (rc=$?)"

    if [ $((n % ALERTS_EVERY)) -eq 0 ]; then
        if ! FLASK_APP=wsgi:app flask alerts-run; then
            # Mirror of deploy/satom-alerts.sh: when the alert engine cannot
            # raise a finding about itself, say the machine state WITHOUT the
            # database. On 2026-08-22 a full filesystem put Postgres into a
            # crash loop and the sentence "the filesystem is 100 % full" was
            # never written anywhere, while /healthz kept answering 200.
            state=$(df -P -h /opt/satom 2>/dev/null | awk 'NR==2 {printf "filesystem %s used, %s free", $5, $4}')
            log "alerts-run FAILED and could not raise a finding about it. ${state:-df unavailable}"
        fi
    fi

    sleep "$TICK"
done
