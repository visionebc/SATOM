#!/usr/bin/env bash
#
# SATOM (web) — installer.  Provisions a fresh host OR re-runs safely
# on an existing one.  Works ONLINE (pip from PyPI) or OFFLINE (--offline, pip
# from ./wheelhouse — build it with scripts/build_offline_bundle.sh).
#
# Usage (run as root, from the app root):
#   ./scripts/install.sh                 # online install / upgrade
#   ./scripts/install.sh --offline       # air-gapped (needs ./wheelhouse)
#   ./scripts/install.sh --no-system-deps # skip apt (deps already present)
#
# Idempotent + SAFE:
#   * NEVER regenerates SECRET_KEY / FERNET_KEY when .env already exists
#     (rotating FERNET_KEY makes stored appliance passwords undecryptable).
#   * Creates the Postgres role/DB only if missing.
#   * Always runs `flask db upgrade` (Alembic) so the schema matches the code.
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/satom}"
DB_NAME="${DB_NAME:-satom}"
DB_USER="${DB_USER:-satom}"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
SERVICE="${SERVICE:-satom}"
PORT="${PORT:-8000}"
OFFLINE=0
SYSTEM_DEPS=1

for arg in "$@"; do
  case "$arg" in
    --offline) OFFLINE=1 ;;
    --no-system-deps) SYSTEM_DEPS=0 ;;
    --help|-h) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "run as root"
cd "$APP_DIR" 2>/dev/null || die "app dir $APP_DIR not found (extract/rsync the source there first)"
[ -f wsgi.py ] || die "$APP_DIR doesn't look like the app (no wsgi.py)"

# --------------------------------------------------------------------------- #
# 1) System dependencies
# --------------------------------------------------------------------------- #
if [ "$SYSTEM_DEPS" = "1" ]; then
  log "Installing system packages (PostgreSQL, Python venv, client tools)…"
  export DEBIAN_FRONTEND=noninteractive
  if [ "$OFFLINE" = "1" ]; then
    log "  (offline) skipping apt — assuming postgresql + python3-venv already present"
  else
    apt-get update -qq
    apt-get install -y -qq postgresql postgresql-client python3 python3-venv python3-pip \
                          nginx openssl >/dev/null
  fi
fi
# nginx and openssl are NOT optional extras: step 8 puts the application behind
# TLS, and without them this installer would produce the plain-HTTP node it
# used to produce -- one that answers /healthz 200 and rejects every correct
# password, because FLASK_ENV=production marks the session cookie Secure.
command -v openssl >/dev/null || die "openssl not found — required to issue the node certificate"
command -v nginx   >/dev/null || die "nginx not found — required to terminate TLS (apt-get install nginx)"
command -v psql   >/dev/null || die "psql not found — install postgresql-client"
command -v pg_dump >/dev/null || log "WARN: pg_dump not found — backup/restore page will be unavailable"
systemctl is-active --quiet postgresql || systemctl start postgresql || true

# --------------------------------------------------------------------------- #
# 2) Locale (the cluster must serve UTF-8 or psycopg chokes — learned the hard way)
# --------------------------------------------------------------------------- #
if ! locale -a 2>/dev/null | grep -qi 'en_US.utf8'; then
  log "Generating en_US.UTF-8 locale…"
  sed -i 's/^# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen 2>/dev/null || \
    echo 'en_US.UTF-8 UTF-8' >> /etc/locale.gen
  locale-gen >/dev/null 2>&1 || true
fi

# --------------------------------------------------------------------------- #
# 3) Postgres role + database (idempotent, UTF-8)
# --------------------------------------------------------------------------- #
DB_PASS=""
if [ -f .env ] && grep -q '^SQLALCHEMY_DATABASE_URI=' .env; then
  DB_PASS="$(grep '^SQLALCHEMY_DATABASE_URI=' .env | sed -E 's#.*://[^:]+:([^@]+)@.*#\1#')"
fi
[ -n "$DB_PASS" ] || DB_PASS="$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')"

log "Ensuring Postgres role '$DB_USER' and database '$DB_NAME' (UTF-8)…"
su postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'\"" | grep -q 1 || \
  su postgres -c "psql -c \"CREATE ROLE $DB_USER LOGIN PASSWORD '$DB_PASS';\""
# keep the password in step with whatever .env carries (no-op if unchanged)
su postgres -c "psql -c \"ALTER ROLE $DB_USER PASSWORD '$DB_PASS';\"" >/dev/null
su postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='$DB_NAME'\"" | grep -q 1 || \
  su postgres -c "psql -c \"CREATE DATABASE $DB_NAME OWNER $DB_USER ENCODING 'UTF8' TEMPLATE template0;\""

# --------------------------------------------------------------------------- #
# 4) Python venv + dependencies
# --------------------------------------------------------------------------- #
log "Creating venv + installing dependencies ($([ "$OFFLINE" = 1 ] && echo offline || echo online))…"
[ -d venv ] || python3 -m venv venv
if [ "$OFFLINE" = "1" ]; then
  [ -d wheelhouse ] || die "--offline needs ./wheelhouse (run scripts/build_offline_bundle.sh on a connected box)"
  venv/bin/pip install --no-index --find-links wheelhouse --upgrade pip >/dev/null 2>&1 || true
  venv/bin/pip install --no-index --find-links wheelhouse -r requirements.txt
else
  venv/bin/pip install --upgrade pip >/dev/null
  venv/bin/pip install -r requirements.txt
fi

# --------------------------------------------------------------------------- #
# 5) .env — generate secrets ONLY on a fresh install (never rotate them)
# --------------------------------------------------------------------------- #
if [ ! -f .env ]; then
  log "Writing fresh .env (generating SECRET_KEY + FERNET_KEY)…"
  SECRET_KEY="$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')"
  FERNET_KEY="$(venv/bin/python -c 'from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())')"
  URI="postgresql+psycopg://$DB_USER:$DB_PASS@$DB_HOST:$DB_PORT/$DB_NAME"
  cat > .env <<ENVEOF
# SATOM environment — generated by install.sh on first install.
# FERNET_KEY must NEVER be regenerated while encrypted appliance passwords exist.
FLASK_ENV=production
FLASK_APP=wsgi.py
SECRET_KEY=$SECRET_KEY
FERNET_KEY=$FERNET_KEY
SQLALCHEMY_DATABASE_URI=$URI
ENVEOF
  chmod 600 .env
else
  log ".env exists — keeping existing SECRET_KEY/FERNET_KEY (not rotated)."
fi

# --------------------------------------------------------------------------- #
# 6) Database schema — Alembic migrations (builds/upgrades to current head)
# --------------------------------------------------------------------------- #
log "Applying database migrations (flask db upgrade)…"
set -a; . ./.env; set +a
# SKIP the app's create_all() bootstrap during migration so it can't race
# Alembic (create_all would build the tables first → CREATE collides).
FORTINET_SKIP_DB_BOOTSTRAP=1 venv/bin/flask db upgrade

# --------------------------------------------------------------------------- #
# 7) systemd unit + log dir
# --------------------------------------------------------------------------- #
log "Installing systemd unit '$SERVICE'…"
mkdir -p /var/log/satom
cat > "/etc/systemd/system/$SERVICE.service" <<UNITEOF
[Unit]
Description=SATOM Web App
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR
EnvironmentFile=$APP_DIR/.env
ExecStart=$APP_DIR/venv/bin/gunicorn --workers 4 --bind 127.0.0.1:$PORT --timeout 120 --access-logfile /var/log/satom/access.log --error-logfile /var/log/satom/error.log wsgi:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNITEOF
systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1 || true
systemctl restart "$SERVICE"

# --------------------------------------------------------------------------- #
# 8) TLS — issued by the install, replaced by the operator later
# --------------------------------------------------------------------------- #
# gunicorn now binds loopback only, so this step is what makes the node
# reachable at all. Self-signed by a per-node internal CA: the browser warns,
# which is the intended day-zero state -- a node that is USABLE immediately and
# whose certificate the operator swaps on their own schedule.
log "Provisioning TLS (internal CA + node certificate + nginx)…"
SERVED_NAMES="${SERVED_NAMES:-$(hostname -f 2>/dev/null || hostname)}"
NODE_IP="${NODE_IP:-$(hostname -I 2>/dev/null | awk '{print $1}')}"
APP_DIR="$APP_DIR" SATOM_SERVED_NAMES="$SERVED_NAMES" SATOM_NODE_IP="$NODE_IP" \
  "$APP_DIR/deploy/tls-bootstrap.sh" ensure-pki
write_satom_vhost() {   # $1: "" or --default-server
  APP_DIR="$APP_DIR" SATOM_SERVED_NAMES="$SERVED_NAMES" SATOM_NODE_IP="$NODE_IP" \
    "$APP_DIR/deploy/tls-bootstrap.sh" write-vhost \
      --out /etc/nginx/conf.d/satom.conf --port "${WEB_PORT:-443}" \
      --upstream "127.0.0.1:$PORT" ${1:+"$1"}
}
# [SATOM-NGINX-DEFAULT] The :80 -> :443 redirect only ever runs when nginx picks
# THIS block for an unmatched name, i.e. when it owns default_server. A packaged
# default site that keeps it answers the welcome page over plain HTTP while :443
# works perfectly, so the node looks healthy and the redirect is silently gone.
# Debian's lives in sites-enabled (included before conf.d); the nginx.org and
# RHEL packages drop a conf.d/default.conf, which beats satom.conf on the
# ALPHABETICAL parse order between files.
rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf
# Written WITH default_server. If some other vhost already claims it, nginx says
# so verbatim and only THEN is it rewritten without -- self-correcting, rather
# than guessing at someone else's configuration with a regex. An `nginx -t` that
# fails for any other reason keeps default_server and falls through to the check
# below, which reports the real cause.
write_satom_vhost --default-server
if ! nginx -t >/dev/null 2>&1 && nginx -t 2>&1 | grep -qi "duplicate default server"; then
  log "Another vhost already claims default_server on :${WEB_PORT:-443} — rewriting without it"
  write_satom_vhost
fi
nginx -t || die "nginx rejected the generated vhost — see the output above"
systemctl enable nginx >/dev/null 2>&1 || true
systemctl reload nginx 2>/dev/null || systemctl restart nginx

# --------------------------------------------------------------------------- #
# 9) Health check
# --------------------------------------------------------------------------- #
log "Waiting for the service to come up…"
if timeout 30 bash -c "until curl -skfo /dev/null https://127.0.0.1:${WEB_PORT:-443}/auth/login; do sleep 1; done"; then
  log "✓ SATOM is UP on https://${SERVED_NAMES%% *}:${WEB_PORT:-443}/"
  echo
  echo "  The certificate is SELF-SIGNED by this node's internal CA, so the"
  echo "  browser will warn on first visit. Replace it whenever you like:"
  echo "    $APP_DIR/deploy/tls-bootstrap.sh import-cert --cert F --key F [--chain F]"
  echo "    systemctl reload nginx"
  echo "  An imported certificate is never overwritten by re-running this installer."
  echo
  echo "  Admin login: admin / Sopas123.-  (CHANGE IT after first login)"
  echo "  Service:     systemctl status $SERVICE"
  echo "  Database:    $DB_NAME (Postgres, UTF-8)"
else
  systemctl status "$SERVICE" --no-pager -l | tail -20
  die "service did not come up in 30s — see status above"
fi
