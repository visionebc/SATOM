#!/bin/bash
# Create the replication role and let it in. Runs ONCE, during the primary's
# first initdb (the postgres image only executes this directory when PGDATA is
# empty).
#
# Two things have to be true for a standby to attach, and only one of them is a
# role: PostgreSQL treats replication connections as a SEPARATE database in
# pg_hba, so `host all all ...` -- which the image writes by default -- does
# NOT admit them. A cluster built without the second line fails at
# pg_basebackup with "no pg_hba.conf entry for replication connection", on the
# standby, at build time. Cheap to fix there; the reason it is worth a comment
# is that the same omission after a primary rebuild fails identically months
# later, when the operator is rebuilding a node under pressure.
set -euo pipefail

: "${SATOM_REPL_USER:?}"
: "${SATOM_REPL_PASSWORD:?}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-SQL
	CREATE ROLE "${SATOM_REPL_USER}" WITH REPLICATION LOGIN PASSWORD '${SATOM_REPL_PASSWORD}';
SQL

# Scoped to the replication database and to that one role. Not `all`: this
# entry is reachable from the DMZ (the primary publishes 5432 so the peer can
# attach), so it is the one line in the stack that admits a connection from
# outside the compose network. The replication role can stream WAL and read
# nothing else.
#
# The source range stays wide because the standby's address is not known at
# initdb time and narrowing it wrongly produces a cluster that cannot be
# rebuilt; the enforcement that matters is scram-sha-256 plus the DMZ firewall.
echo "host replication ${SATOM_REPL_USER} 0.0.0.0/0 scram-sha-256" >> "$PGDATA/pg_hba.conf"
echo "host replication ${SATOM_REPL_USER} ::/0        scram-sha-256" >> "$PGDATA/pg_hba.conf"

echo "[initdb] replication role '${SATOM_REPL_USER}' created and admitted"
