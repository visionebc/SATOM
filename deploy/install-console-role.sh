#!/usr/bin/env bash
# Provision (or re-assert) the database console's read-only Postgres role.
#
# Idempotent. Run as root. Called from:
#   * installers/install-satom.sh          (fresh install)
#   * deploy/self_update_runner.py         (after every code update, EVERY node)
#   * by hand: sudo bash /opt/satom/deploy/install-console-role.sh
#
# [SATOM-CONSOLE-RO-ROLE]
# Settings -> Database (SQL console), the report builder and the plugin
# datasets run SELECTs typed by a person. They used to run under the
# APPLICATION's own role -- owner of every table, member of pg_monitor --
# guarded only by a denylist of functions, and a denylist is never complete
# (query_to_xml('select ... from users') read a credential table by string).
# The app now switches every such query to this role with SET LOCAL ROLE and
# REFUSES to run it when the role is missing: no silent fallback.
#
# What this script does (the parts that need a superuser):
#   * CREATE ROLE satom_console_ro NOLOGIN, with every privilege attribute OFF;
#   * session defaults read-only + statement_timeout (belt and braces: they
#     apply to a LOGIN session only, the app sets both per transaction);
#   * drops any membership the role was given in another role;
#   * GRANT satom_console_ro TO <application role> (needed for SET ROLE).
# Table grants are NOT here: the application owns the tables and syncs them at
# boot from its own credential list (app/services/dbintrospect.py), so a new
# table or a new credential table never needs this script edited.
#
# PRIMARY ONLY. On a standby Postgres is read-only and the role arrives by
# streaming replication; the script says so and exits 0.
#
# NEVER aborts a code update: every skip exits 0, a failed statement exits 1
# (the runner records the step as failed and the update goes on; the console
# then refuses queries with a message naming this script).
set -uo pipefail

APP_DIR="${FM_APP_DIR:-/opt/satom}"
ENV_FILE="${APP_DIR}/.env"
ROLE="satom_console_ro"

if [ "$(id -u)" -ne 0 ]; then
  echo "install-console-role.sh: must run as root (it runs psql as postgres)." >&2
  exit 3
fi
cd /tmp 2>/dev/null || cd /

if ! command -v psql >/dev/null 2>&1 || ! getent passwd postgres >/dev/null 2>&1; then
  echo "console role: no local PostgreSQL on this node; skipped"
  exit 0
fi
if [ ! -r "$ENV_FILE" ]; then
  echo "console role: ${ENV_FILE} not found; skipped" >&2
  exit 0
fi

# The application's database and role, from the one place that holds them.
uri="$(sed -n 's/^SQLALCHEMY_DATABASE_URI=//p' "$ENV_FILE" | tail -n 1 | tr -d "\"'" | tr -d '[:space:]')"
case "$uri" in
  postgresql://*|postgresql+*://*) ;;
  *) echo "console role: the application database is not PostgreSQL; skipped"; exit 0 ;;
esac
rest="${uri#*://}"
userinfo="${rest%@*}"
hostpart="${rest##*@}"
APP_ROLE="${userinfo%%:*}"
DB_HOST="${hostpart%%/*}"
DB_HOST="${DB_HOST%%:*}"
DB_NAME="${hostpart#*/}"
DB_NAME="${DB_NAME%%\?*}"

ident_ok() { printf '%s' "$1" | grep -Eq '^[A-Za-z_][A-Za-z0-9_]{0,62}$'; }
if ! ident_ok "$APP_ROLE" || ! ident_ok "$DB_NAME"; then
  echo "console role: unexpected database/role name in ${ENV_FILE}; skipped" >&2
  exit 0
fi
case "$DB_HOST" in
  127.0.0.1|localhost|"["*|::1|"") ;;
  *)
    echo "console role: the database is EXTERNAL (${DB_HOST}); ask its administrator to run:"
    echo "  CREATE ROLE ${ROLE} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;"
    echo "  GRANT ${ROLE} TO ${APP_ROLE};"
    exit 0 ;;
esac

rec="$(runuser -u postgres -- psql -X -tAc 'SELECT pg_is_in_recovery()' 2>/dev/null | tr -d '[:space:]')"
case "$rec" in
  f) ;;
  t) echo "console role: standby -- the role arrives by replication from the primary; skipped"; exit 0 ;;
  *) echo "WARN console role: local PostgreSQL did not answer; skipped" >&2; exit 0 ;;
esac

if ! runuser -u postgres -- psql -X -qAt -v ON_ERROR_STOP=1 -d "$DB_NAME" \
     -v role="$ROLE" -v app="$APP_ROLE" <<'SQL'
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'role') AS need_create \gset
\if :need_create
CREATE ROLE :"role" NOLOGIN;
\endif
ALTER ROLE :"role" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
                   NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 0;
ALTER ROLE :"role" SET default_transaction_read_only = on;
ALTER ROLE :"role" SET statement_timeout = '8s';
SELECT format('REVOKE %I FROM %I', g.rolname, :'role')
  FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid
 WHERE m.member = (SELECT oid FROM pg_roles WHERE rolname = :'role') \gexec
SELECT NOT pg_has_role(:'app', :'role', 'MEMBER') AS need_grant \gset
\if :need_grant
GRANT :"role" TO :"app";
\endif
SQL
then
  echo "console role: provisioning ${ROLE} FAILED; the database console will refuse queries until it succeeds" >&2
  exit 1
fi

echo "console role ${ROLE} ready (NOLOGIN, read-only defaults, granted to ${APP_ROLE}); table grants are synced by the application at boot"
exit 0
