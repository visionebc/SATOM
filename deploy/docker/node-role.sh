#!/bin/sh
# Prints this stack's Postgres role: "f" = primary/standalone, "t" = streaming
# standby, "" (exit 1) = database not reachable yet.
#
# Container twin of deploy/satom-node-role.sh. Same contract, same three
# answers, deliberately the same three characters -- the callers are ports of
# the host guards and a different vocabulary here would be a silent behaviour
# change at the exact place HA decisions are made.
#
# The ONE difference: the host probe parses /opt/satom/.env, which does not
# exist in the image (compose injects the environment). It reads
# SQLALCHEMY_DATABASE_URI from the process environment instead.
#
# Why this matters at all: the scheduled-action firer must run on the PRIMARY
# ONLY. Two nodes both firing a firmware-upgrade action means a double flash.
set -u

exec python - <<'PYEOF'
import os, re, sys

m = re.match(r'postgresql\+\w+://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?/(\S+)',
             os.environ.get('SQLALCHEMY_DATABASE_URI', ''))
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
