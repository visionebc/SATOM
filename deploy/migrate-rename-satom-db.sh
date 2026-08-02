#!/usr/bin/env bash
# migrate-rename-satom-db.sh — retire the last "fortinet" identifiers from an
# existing install: the database, the Postgres role, the Linux service account
# and the Postgres TLS directory.
#
# WHY THIS IS A SEPARATE MIGRATOR
# -------------------------------
# The 2026-07 rename deliberately stopped short of these four: they are LIVE
# state, not files, and getting one of them wrong locks the application out of
# its own database. They are now in scope, so this script does them in an order
# that keeps the HA pair recoverable at every step, with a backup before each
# irreversible move.
#
# WHAT IT DOES NOT TOUCH, ON PURPOSE
#   * the replication slot (fm_standby) — Postgres has no rename for slots;
#     dropping and recreating one under a streaming standby risks a full
#     re-sync for an invisible internal string.
#   * the external backup server (backup-server) — the appliances push to it by
#     name in their own configuration; renaming it here would break the
#     nightly config push silently.
#   * the *vendor* names (FortiWeb / FortiADC / FortiAnalyzer) — the product
#     manages those appliances and has to be able to name them.
#
# ORDER (both nodes, standby first for the local work):
#   1. standby:  --stop
#   2. primary:  --stop --rename-db --local --start
#   3. standby:  --local --start
#   4. either:   --ssl   (one node at a time, verify replication after each)
set -euo pipefail

APP_DIR="${SATOM_APP_DIR:-/opt/satom}"
ENV_FILE="$APP_DIR/.env"
OLD_DB="fortinet_mgr"; NEW_DB="satom"
OLD_ROLE="fortinet";   NEW_ROLE="satom"
OLD_USER="fortinet";   NEW_USER="satom"
OLD_SSL="fmssl";       NEW_SSL="satomssl"
STAMP="$(date +%Y%m%d-%H%M%S)"
UNITS=(satom.service satom-scheduler.service satom-reconciler.service)
TIMERS=(satom-alerts.timer satom-cert-renew.timer satom-git-publish.timer satom-ha-datasync.timer)

log(){ printf '  %s\n' "$*"; }
die(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "must run as root"

PGCONF="$(ls -d /etc/postgresql/*/main 2>/dev/null | head -1)"

is_primary(){
  [ "$(runuser -u postgres -- psql -tAc 'select pg_is_in_recovery()' 2>/dev/null || echo t)" = "f" ]
}

do_stop(){
  log "stopping application units"
  systemctl stop "${TIMERS[@]}" 2>/dev/null || true
  systemctl stop "${UNITS[@]}" 2>/dev/null || true
  pkill -u "$OLD_USER" -f gunicorn 2>/dev/null || true
  sleep 1
}

do_start(){
  log "starting application units"
  systemctl daemon-reload
  systemctl start "${UNITS[@]}"
  systemctl start "${TIMERS[@]}" 2>/dev/null || true
  local i
  for i in $(seq 1 30); do
    if curl -sfo /dev/null http://127.0.0.1:8000/healthz; then log "healthz 200"; return 0; fi
    sleep 1
  done
  systemctl status satom.service --no-pager -l | tail -20
  die "satom.service did not become healthy in 30s"
}

do_rename_db(){
  is_primary || { log "standby: the rename happens on the primary and arrives by WAL — skipping"; return 0; }
  local have_old have_new
  have_old=$(runuser -u postgres -- psql -tAc "select 1 from pg_database where datname='$OLD_DB'")
  have_new=$(runuser -u postgres -- psql -tAc "select 1 from pg_database where datname='$NEW_DB'")
  if [ "${have_new:-}" = "1" ] && [ -z "${have_old:-}" ]; then
    log "database already '$NEW_DB'"
  elif [ "${have_old:-}" = "1" ]; then
    log "backup -> /root/$OLD_DB.pre-dbrename-$STAMP.dump"
    runuser -u postgres -- pg_dump -Fc "$OLD_DB" > "/root/$OLD_DB.pre-dbrename-$STAMP.dump"
    log "terminating remaining sessions"
    runuser -u postgres -- psql -q -c "select pg_terminate_backend(pid) from pg_stat_activity where datname='$OLD_DB' and pid<>pg_backend_pid();" >/dev/null
    log "ALTER DATABASE $OLD_DB RENAME TO $NEW_DB"
    runuser -u postgres -- psql -q -c "alter database \"$OLD_DB\" rename to \"$NEW_DB\";"
  else
    die "neither $OLD_DB nor $NEW_DB exists — refusing to guess"
  fi

  if [ "$(runuser -u postgres -- psql -tAc "select 1 from pg_roles where rolname='$OLD_ROLE'")" = "1" ]; then
    # scram-sha-256 verifiers do not hash the role name, so the password
    # survives the rename. md5 WOULD be cleared, silently — hence the guard.
    [ "$(runuser -u postgres -- psql -tAc 'show password_encryption')" = "scram-sha-256" ] \
      || die "password_encryption is not scram-sha-256; a role rename would clear the password"
    log "ALTER ROLE $OLD_ROLE RENAME TO $NEW_ROLE"
    runuser -u postgres -- psql -q -c "alter role \"$OLD_ROLE\" rename to \"$NEW_ROLE\";"
  else
    log "role already '$NEW_ROLE'"
  fi

  local hba="$PGCONF/pg_hba.conf"
  if grep -qE "[[:space:]]$OLD_DB[[:space:]]|[[:space:]]$OLD_ROLE[[:space:]]" "$hba"; then
    cp -a "$hba" "/root/pg_hba.conf.pre-dbrename-$STAMP"
    sed -i -E "s/([[:space:]])$OLD_DB([[:space:]])/\1$NEW_DB\2/g; s/([[:space:]])$OLD_ROLE([[:space:]])/\1$NEW_ROLE\2/g" "$hba"
    log "pg_hba.conf rewritten (backup /root/pg_hba.conf.pre-dbrename-$STAMP)"
    systemctl reload postgresql
  else
    log "pg_hba.conf already names '$NEW_DB'"
  fi
}

do_local(){
  if grep -q "$OLD_DB" "$ENV_FILE" 2>/dev/null || grep -q "://$OLD_ROLE:" "$ENV_FILE" 2>/dev/null; then
    cp -a "$ENV_FILE" "/root/satom.env.pre-dbrename-$STAMP"
    sed -i -E "s#://$OLD_ROLE:#://$NEW_ROLE:#g; s#/$OLD_DB\b#/$NEW_DB#g" "$ENV_FILE"
    log ".env rewritten (backup /root/satom.env.pre-dbrename-$STAMP)"
  else
    log ".env already points at $NEW_DB"
  fi

  # The uid/gid are preserved, so file ownership across /opt/satom is unchanged
  # and no chown sweep is required. Home is /opt/satom and does not move.
  if getent passwd "$OLD_USER" >/dev/null && ! getent passwd "$NEW_USER" >/dev/null; then
    log "renaming Linux account $OLD_USER -> $NEW_USER (uid preserved)"
    pkill -u "$OLD_USER" 2>/dev/null || true; sleep 1
    if getent group "$OLD_USER" >/dev/null; then groupmod -n "$NEW_USER" "$OLD_USER"; fi
    usermod -l "$NEW_USER" "$OLD_USER"
  else
    log "Linux account already '$NEW_USER' (or both exist — not touching)"
  fi

  local sud=/etc/sudoers.d/satom
  if [ -f "$sud" ] && grep -q "$OLD_USER" "$sud"; then
    cp -a "$sud" "/root/sudoers-satom.pre-dbrename-$STAMP"
    sed -i "s/\b$OLD_USER\b/$NEW_USER/g" "$sud"
    if ! visudo -cf "$sud" >/dev/null; then
      cp -a "/root/sudoers-satom.pre-dbrename-$STAMP" "$sud"; die "sudoers invalid, rolled back"
    fi
    log "sudoers rewritten and validated"
  fi

  # Drop-ins, not unit files: the updater recopies deploy/<unit> on every code
  # update, so a User= edited in the unit never survives.
  local d changed=0
  for d in /etc/systemd/system/satom*.service.d/*.conf; do
    [ -e "$d" ] || continue
    if grep -q "=$OLD_USER\$" "$d"; then sed -i "s/=$OLD_USER\$/=$NEW_USER/" "$d"; changed=1; fi
  done
  if [ "$changed" = 1 ]; then log "systemd drop-ins rewritten"; else log "systemd drop-ins already name '$NEW_USER'"; fi
  systemctl daemon-reload
}

do_ssl(){
  local old="$PGCONF/$OLD_SSL" new="$PGCONF/$NEW_SSL" f i
  if [ -d "$old" ] && [ ! -d "$new" ]; then log "renaming $old -> $new"; mv "$old" "$new"; fi
  for f in /var/lib/postgresql/*/main/postgresql.auto.conf; do
    [ -e "$f" ] || continue
    if grep -q "/$OLD_SSL/" "$f"; then
      cp -a "$f" "/root/postgresql.auto.conf.pre-dbrename-$STAMP"
      sed -i "s#/$OLD_SSL/#/$NEW_SSL/#g" "$f"
      log "postgresql.auto.conf rewritten (backup /root/postgresql.auto.conf.pre-dbrename-$STAMP)"
    fi
  done
  systemctl restart postgresql
  for i in $(seq 1 30); do if runuser -u postgres -- pg_isready -q; then break; fi; sleep 1; done
  runuser -u postgres -- pg_isready || die "postgres did not come back"
  log "postgres back up"
}

usage(){ sed -n '2,28p' "$0"; }

[ $# -gt 0 ] || { usage; exit 2; }
for arg in "$@"; do
  case "$arg" in
    --stop)      do_stop ;;
    --rename-db) do_rename_db ;;
    --local)     do_local ;;
    --ssl)       do_ssl ;;
    --start)     do_start ;;
    -h|--help)   usage; exit 0 ;;
    *) die "unknown option: $arg" ;;
  esac
done
log "done"
