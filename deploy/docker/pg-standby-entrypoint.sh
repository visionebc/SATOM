#!/usr/bin/env bash
# Bring up PostgreSQL as a streaming standby of the SATOM primary.
#
# Wraps the stock postgres entrypoint rather than replacing it, so every
# behaviour of the base image that is not about replication -- signal handling,
# uid switching, the `postgres` argv convention -- stays exactly as upstream
# ships it. Anything reimplemented here is a divergence to maintain forever.
#
# Flow:
#   PGDATA already a standby  -> start, follow the primary
#   PGDATA already a PRIMARY  -> REFUSE (see below)
#   PGDATA empty              -> pg_basebackup from the primary, then start
set -euo pipefail

PGDATA="${PGDATA:-/var/lib/postgresql/data}"
: "${SATOM_PRIMARY_HOST:?SATOM_PRIMARY_HOST is required}"
PRIMARY_PORT="${SATOM_PRIMARY_PORT:-5432}"
: "${SATOM_REPL_USER:?SATOM_REPL_USER is required}"
: "${SATOM_REPL_PASSWORD:?SATOM_REPL_PASSWORD is required}"

log() { echo "[pg-standby] $*" >&2; }

if [ -s "$PGDATA/PG_VERSION" ]; then
    if [ -f "$PGDATA/standby.signal" ]; then
        log "PGDATA is already a standby of ${SATOM_PRIMARY_HOST} — starting"
    else
        # The one refusal in this script, and the reason it exists.
        #
        # A promoted standby has no standby.signal: it IS a primary, and it is
        # holding every write accepted since the failover. Re-basebackup'ing it
        # from the old primary would silently discard exactly that data --
        # quietly, successfully, and with a healthy container afterwards.
        #
        # Recovering from a failover is an operator decision (re-point the
        # cluster, or rebuild this node on purpose by removing the volume).
        # It is not something a container restart is allowed to make.
        log "REFUSING to start."
        log "PGDATA holds a PRIMARY (no standby.signal), not a standby."
        log "This node was probably promoted. Rebuilding it from"
        log "${SATOM_PRIMARY_HOST} would discard every write accepted since."
        log "Decide explicitly: re-point the cluster, or destroy this volume"
        log "  docker compose down && docker volume rm satom_satom-pgdata"
        exit 1
    fi
else
    log "PGDATA is empty — taking a base backup from ${SATOM_PRIMARY_HOST}:${PRIMARY_PORT}"

    # Wait for the primary. A standby brought up in the same window as its
    # primary (a whole-node reboot, a rebuild) would otherwise fail here and
    # sit in a restart loop that reads like a credential problem.
    deadline=$(( $(date +%s) + ${SATOM_BASEBACKUP_WAIT_SECONDS:-300} ))
    until PGPASSWORD="$SATOM_REPL_PASSWORD" \
          pg_isready -h "$SATOM_PRIMARY_HOST" -p "$PRIMARY_PORT" -q; do
        if [ "$(date +%s)" -ge "$deadline" ]; then
            log "primary ${SATOM_PRIMARY_HOST}:${PRIMARY_PORT} never became ready"
            exit 1
        fi
        sleep 5
    done

    rm -rf "${PGDATA:?}"/* "${PGDATA:?}"/.[!.]* 2>/dev/null || true

    # -R writes postgresql.auto.conf + standby.signal for us, so the primary
    #    connection string has ONE author.
    # -X stream keeps a WAL receiver open for the whole backup: without it a
    #    long basebackup can outlive the primary's retained WAL and produce a
    #    standby that can never catch up -- which looks like success here and
    #    fails minutes later with "requested WAL segment has already been
    #    removed".
    # -C -S creates a physical replication SLOT, so the primary keeps WAL this
    #    standby has not consumed even while the standby is down. That is what
    #    makes a reboot of this node survivable instead of a rebuild.
    PGPASSWORD="$SATOM_REPL_PASSWORD" pg_basebackup \
        --host="$SATOM_PRIMARY_HOST" \
        --port="$PRIMARY_PORT" \
        --username="$SATOM_REPL_USER" \
        --pgdata="$PGDATA" \
        --wal-method=stream \
        --create-slot --slot="${SATOM_REPL_SLOT:-satom_standby}" \
        --write-recovery-conf \
        --checkpoint=fast \
        --progress --verbose

    chmod 0700 "$PGDATA"
    log "base backup complete — starting as a streaming standby"
fi

# Hand over to the stock entrypoint with the argv compose passed us
# (compose.prod.yaml's `command:`, so the standby runs the primary's settings).
exec docker-entrypoint.sh "$@"
