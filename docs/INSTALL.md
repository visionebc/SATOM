# Fortinet Manager (web) — Install & Migrate

The app is **PostgreSQL-backed** (the local source of truth) with **Alembic**
migrations. `scripts/install.sh` provisions a fresh host or safely re-runs on an
existing one; it works **online** (pip from PyPI) or **offline** (air-gapped).

## Online install (fresh host)

```bash
# put the source at /opt/fortinet-manager (git clone / scp / extract a tarball)
cd /opt/fortinet-manager
sudo ./scripts/install.sh
```

It installs PostgreSQL + Python deps, creates the UTF-8 DB + role, generates
`SECRET_KEY`/`FERNET_KEY` into `.env`, runs `flask db upgrade`, installs the
`fortinet-manager` systemd unit, starts it on :8000, and health-checks it.

Login: `admin` / `Sopas123.-` — **change it after first login**.

## Offline install (air-gapped)

On a connected box with the **same OS / arch / Python** as the target:

```bash
cd /opt/fortinet-manager
./scripts/build_offline_bundle.sh           # → dist/fortinet-manager-offline-<date>.tar.gz
```

Copy the tarball to the air-gapped host, then:

```bash
tar xzf fortinet-manager-offline-<date>.tar.gz -C /opt
cd /opt/fortinet-manager
sudo ./scripts/install.sh --offline          # pip from the bundled ./wheelhouse
```

`--offline` skips `apt` (PostgreSQL + `python3-venv` must already be present on
the air-gapped box) and installs every wheel from `./wheelhouse`.

## Re-running / upgrading in place

`install.sh` is **idempotent and safe**:

- It **never regenerates** `SECRET_KEY` / `FERNET_KEY` when `.env` exists —
  rotating `FERNET_KEY` would make stored appliance passwords undecryptable.
- The Postgres role/DB are created only if missing.
- `flask db upgrade` always runs, so a code pull that adds a migration just
  needs `git pull && sudo ./scripts/install.sh` to bring the schema to head.

Useful flags / overrides (env vars): `APP_DIR`, `DB_NAME`, `DB_USER`, `DB_HOST`,
`DB_PORT`, `PORT`, `SERVICE`, and `--no-system-deps` (skip apt when the OS
packages are already installed).

## Backup & restore

The **Database → System backup** page (and the `system_backup` Automation
action) bundle a `pg_dump -Fc` of the DB + the `reports/` JSON tree into one
`.tar.gz`. Restore takes a pre-restore **safety dump** first, then
`pg_restore --clean`. The full round-trip (dump → restore into a fresh DB →
row-count parity) is verified.

## What lives where

- **PostgreSQL** `fortinet_mgr` — management data (users, appliances, templates,
  audit) **and** the device source-of-truth cache (`device_objects`,
  `device_snapshots`, the typed projections).
- **`reports/<device>/_config.json`** — per-device human-readable JSON backup
  (git-shareable, opt-in).
- **OS keyring is not used** by the web app; appliance passwords are
  Fernet-encrypted in the DB (`FERNET_KEY` in `.env`). Keep `.env` (mode 600,
  gitignored) safe — it is the one secret that cannot be regenerated.
