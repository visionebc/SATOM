#!/usr/bin/env bash
# Prints the node's Postgres role: "f" = primary/standalone, "t" = streaming
# standby, "" (empty, exit 1) = database not reachable yet.
#
# WHY THIS EXISTS
#   Every HA guard in this product needs the same answer, and the obvious way
#   to get it — `runuser -u postgres -- psql` — REQUIRES ROOT. Since v1.2 the
#   units run as the service account, so that idiom returns nothing and the
#   guards silently take the "not primary" branch: the scheduler idle-loops
#   forever and git-publish no-ops, both while systemd reports success.
#
#   So the probe uses the application's OWN credentials from .env over TCP.
#   That works at any privilege level, and it derives the database name instead
#   of hardcoding a database name (installs migrated before 2026-08 are
#   predate the rename).
set -u
APP=/opt/satom

exec "$APP/venv/bin/python" - <<'PYEOF'
import re, sys

env = {}
try:
    for line in open('/opt/satom/.env'):
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            env[k.strip()] = v.strip().strip('"').strip("'")
except Exception:
    sys.exit(1)

m = re.match(r'postgresql\+\w+://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?/(\S+)',
             env.get('SQLALCHEMY_DATABASE_URI', ''))
if not m:
    sys.exit(1)
user, pw, host, port, db = m.groups()

try:
    import psycopg
    conn = psycopg.connect(host=host, port=int(port or 5432), user=user,
                           password=pw, dbname=db, connect_timeout=10)
except Exception:
    sys.exit(1)

with conn:
    with conn.cursor() as cur:
        cur.execute("SELECT pg_is_in_recovery()")
        print('t' if cur.fetchone()[0] else 'f')
PYEOF
