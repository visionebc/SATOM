#!/bin/sh
# SATOM container entrypoint. One image, several roles.
#
# The role is chosen by $SATOM_ROLE so the web worker, the scheduler and the
# periodic jobs are the SAME build. On the host installs those are three
# systemd units reading one /opt/satom checkout; splitting them into three
# images would let the scheduler run code the web worker does not have, and
# that difference is invisible until a scheduled action behaves differently
# from the same action fired by hand.
#
# Roles:
#   web        gunicorn, the only role that listens (8000)
#   scheduler  fires scheduled actions        (host: satom-scheduler.service)
#   cron       alerts + sentinel responder    (host: the two systemd timers)
#   shell      exec into a configured runtime for maintenance
#
# NOT reproduced here, by design (see app/runtime.py):
#   satom-updater / satom-integrations  .path watchers  -> root on the host
#   satom-reconciler                    git-driven host reconciliation
#   satom-cert-renew                    writes node PKI + reloads host nginx
set -eu

log() { echo "[entrypoint] $*" >&2; }

# ---------------------------------------------------------------------------
# Wait for PostgreSQL.
#
# Not optional and not a nicety: the Flask app factory calls db.create_all() at
# import time, so a web worker that starts before Postgres accepts connections
# does not retry -- it raises inside the factory and gunicorn boot-loops. The
# compose healthcheck already orders startup; this covers the restart-storm
# case where Postgres is up as a process but still replaying WAL.
# ---------------------------------------------------------------------------
wait_for_db() {
    uri="${SQLALCHEMY_DATABASE_URI:-}"
    [ -n "$uri" ] || { log "SQLALCHEMY_DATABASE_URI is not set"; exit 64; }

    # postgresql+psycopg://user:pw@host:port/db  ->  host, port
    hostport=$(printf '%s' "$uri" | sed -E 's|^[^@]*@||; s|/.*$||')
    host=$(printf '%s' "$hostport" | cut -d: -f1)
    port=$(printf '%s' "$hostport" | cut -s -d: -f2)
    port="${port:-5432}"

    deadline=$(( $(date +%s) + ${SATOM_DB_WAIT_SECONDS:-120} ))
    while :; do
        if pg_isready -h "$host" -p "$port" -q; then
            log "postgres ${host}:${port} is ready"
            return 0
        fi
        if [ "$(date +%s)" -ge "$deadline" ]; then
            # Say which endpoint and for how long. "database unavailable" sends
            # the operator to the wrong container.
            log "postgres ${host}:${port} did not accept connections in ${SATOM_DB_WAIT_SECONDS:-120}s"
            exit 69
        fi
        sleep 2
    done
}

# ---------------------------------------------------------------------------
# Refuse to run with placeholder secrets.
#
# env.example ships obvious placeholders so the stack is copy-paste runnable.
# The failure mode that guard exists for is the operator who copies it, brings
# up production, and never notices -- at which point every session cookie is
# forgeable and every appliance password in fortinet.db is decryptable by
# anyone holding the published example file.
#
# FERNET_KEY especially: it CANNOT be rotated once appliance passwords are
# encrypted with it, so a placeholder that reaches production is not a config
# mistake to fix later, it is a re-keying migration.
# ---------------------------------------------------------------------------
reject_placeholder_secrets() {
    for var in SECRET_KEY FERNET_KEY; do
        eval "val=\${$var:-}"
        case "$val" in
            ""|*CHANGE_ME*|*changeme*|*REPLACE*|*example*)
                log "$var is unset or still the placeholder from env.example."
                log "Generate real values: deploy/docker/satom-docker.sh gen-secrets"
                exit 78
                ;;
        esac
    done
}

role="${SATOM_ROLE:-web}"
log "role=${role} runtime=${SATOM_RUNTIME:-host} version=$(cat /opt/satom/VERSION 2>/dev/null || echo '?')"

case "$role" in
    web)
        reject_placeholder_secrets
        wait_for_db
        # --timeout must stay ABOVE the advisor provider timeout
        # (app/services/advisor_providers.py DEFAULT_TIMEOUT), exactly as in
        # deploy/satom.service: below it a slow model has its worker killed
        # first and the operator gets a dropped connection instead of the
        # provider's own "request timed out".
        exec gunicorn \
            --workers "${SATOM_WEB_WORKERS:-4}" \
            --bind "0.0.0.0:8000" \
            --timeout "${SATOM_WEB_TIMEOUT:-600}" \
            --access-logfile - \
            --error-logfile - \
            wsgi:app
        ;;
    scheduler)
        reject_placeholder_secrets
        wait_for_db
        # Primary-only, and the guard is a LOOP, not a one-shot check: on a
        # standby it idle-waits and re-probes, so promoting the database
        # auto-starts the firer with no external coordination -- and the two
        # nodes of a cluster never both fire, which for a firmware-upgrade
        # action would mean a double flash. Straight port of
        # deploy/scheduler_guard.sh.
        while :; do
            case "$(/opt/satom/deploy/docker/node-role.sh 2>/dev/null || true)" in
                f) exec python -m app.scheduler_runtime ;;   # primary
                *) sleep 30 ;;   # standby ('t') or db not ready ('')
            esac
        done
        ;;
    cron)
        reject_placeholder_secrets
        wait_for_db
        exec /opt/satom/deploy/docker/cron-runner.sh
        ;;
    shell)
        wait_for_db
        exec /bin/sh
        ;;
    *)
        # An unknown role must not fall through to `web`: two web containers
        # both binding 8000 is a confusing failure, and a silently-missing
        # scheduler is a silent one.
        log "unknown SATOM_ROLE='$role' (expected: web|scheduler|cron|shell)"
        exit 64
        ;;
esac
