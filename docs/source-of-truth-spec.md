# Source of Truth — Local Persistence Layer for OFortMAuT
> **STATUS (2026-07-05): IMPLEMENTED.** The DB-first read layer shipped in full
> (2026-07-04): `services/read_layer.py`, per-device cache layers (config /
> deep / inventory), DB-first Configuration sections, Server-Policy & WPP
> detail, fleet map, freshness badges, and the standing refresh schedule
> (`device_sync` 60 min · `deep_capture` 03:30 · `cert_scan` 04:15 via the
> scheduler sidecar). This document is kept as the **design record**; the
> living operational reference is the internal project knowledge base. Do not implement from here
> without cross-checking the current code.


> Spec + phased implementation plan. Target: `ofortmaut-web` on LXC 248
> (`/opt/ofortmaut`, Flask + SQLAlchemy, gunicorn 4 workers on 192.0.2.34:8000).
> Status: design approved over chat (2026-06-29). Decisions locked in §2.

---

## 1. Goal & non-goals

**Goal.** Make this instance a **local source of truth** for FortiWeb (and later
FortiADC) configuration. The app reads from a **local database by default**;
the appliance is touched only when a user explicitly refreshes a section. Local
data is the backup/analysis substrate; git is the versioned off-box backup.

**Non-goals (this round).**
- Not a live mirror with TTL/cache-first auto-refresh (rejected — see §2.1).
- Not FortiADC ingestion yet (storage is type-agnostic; the FortiADC *reader*
  is a separate, later phase — §11).
- Not a restore-to-box engine (use the existing Clone engine + manual cutover).

---

## 2. Decisions locked

| # | Decision | Source |
|---|---|---|
| 1 | **DB-first reads, explicit per-section refresh.** No cache-first/TTL. The DB is the truth; ⟳ on a section goes live, repaints, and writes that section back to the DB. | user |
| 2 | **Pre-apply approval.** Before any write the user sees a dry-run diff of exactly what will change and must accept it. | user |
| 3 | **Multi-user + pessimistic locking.** Editing a server policy (or any object) **locks** it so a second user cannot edit concurrently. Must be horizontally scalable. | user |
| 4 | **Everything in PostgreSQL.** Install Postgres on this LXC; migrate the existing management data (users, appliances, templates, …) into it too — one database, not SQLite + Postgres + git as three stores. Git stays as the off-box backup/export (file-based, not a running service). | user |
| 5 | **Scheduled sync defined by the user in Automation → Actions.** Two new catalog actions: `device_sync` (light, lists) and `device_inspect` (deep, per-policy). | user |
| 6 | FortiADC: separate, later phase. | user |

### 2.1 Why DB-first beats cache-first (the 2000-policy problem)
A live read of 2000 server policies on every page load is exactly today's pain.
DB-first removes freshness-guessing logic entirely: the DB is authoritative,
the box is touched only on ⟳. Reads paginate with `LIMIT/OFFSET` (or keyset)
off Postgres. Writes are **diff-by-content-hash** — only changed objects are
rewritten, so refresh is cheap and the git diff stays clean.

### 2.2 Changes I recommend on top of your decisions
These improve scalability/portability without altering your four choices:

- **Adopt Alembic (Flask-Migrate) now.** Today schema is built by
  `db.create_all()`, which never `ALTER`s. A Postgres move + a growing schema +
  an offline/online installer all need **repeatable, versioned migrations**.
  This is a prerequisite, not a nice-to-have.
- **JSONB-first storage, drop the EAV field table.** The desktop app used an
  `device_object_field` EAV table because SQLite indexes scalars poorly. Postgres
  `JSONB` + **GIN indexes** query nested fields directly, so we store one
  `payload JSONB` per object and skip the tens-of-millions-of-rows EAV table.
  Fewer rows, faster fleet-wide search, simpler ingest.
- **Lease-based locks, not held DB row locks.** HTTP is stateless; you cannot
  hold a `SELECT … FOR UPDATE` across a user's edit session. Use a
  `resource_lock` table with an **owner + TTL/lease + heartbeat**; the lock
  auto-expires if a tab is abandoned. This is the scalable multi-user answer
  (§6).
- **Hot-type typed projections.** Keep generic `device_object` (JSONB) as the
  universal store, and denormalize only *hot* types (server_policy, server_pool,
  web_protection_profile) into typed, indexed tables for fast list/table views —
  rebuilt on each ingest. (Mirrors the desktop `_TYPED_PROJECTIONS` idea.)

---

## 3. Architecture

```
┌──────────────── gunicorn workers (Flask) ────────────────┐
│  views/*  ──read──►  read_layer (DB-first, paginated)     │
│     │                      ▲                              │
│     │ ⟳ refresh(section)   │ ingest (diff-hash)           │
│     ▼                      │                              │
│  fortiweb_ops (dry-run→approve→apply)                     │
│     │ write-through (refresh that section after a write)  │
└─────┼────────────────────────────────────────────────────┘
      ▼
   PostgreSQL (one DB: management + device cache + locks + sync state)
      │  device_snapshot / device_object(JSONB) / typed projections
      │  resource_lock / sync_run
      ▼
   git  reports/<device>/_config.json … (off-box versioned backup/export)
```

- **One Postgres** holds everything (decision 4). Connection is the single
  `SQLALCHEMY_DATABASE_URI` already in `app/config.py`.
- **Scheduler is the serialized writer** for fleet syncs (decision 5), but
  Postgres handles concurrent worker writes fine, so per-request write-through
  is also safe (unlike the SQLite single-writer constraint).
- **git** = the canonical off-box backup; the DB can be rebuilt from `reports/`
  via a backfill (so a fresh clone/install is not empty without touching a box).

---

## 4. Data model (new tables — all Postgres)

```sql
-- one row per (device, layer) snapshot
device_snapshot(
  id            bigserial pk,
  appliance_id  int  fk appliances(id) on delete cascade,
  layer         text,            -- 'config' | 'inventory' | 'report'
  section       text,            -- 'server_policy' | 'web_protection' | ... | '_all'
  source        text,            -- 'live' | 'git' | 'import'
  generated_at  timestamptz,
  blob_hash     text             -- content hash of the whole section payload
)

-- every object AND sub-object at any depth (self-FK), payload as JSONB
device_object(
  id            bigserial pk,
  appliance_id  int  fk,
  snapshot_id   bigint fk device_snapshot(id) on delete cascade,
  parent_id     bigint fk device_object(id)   on delete cascade,  -- nullable
  layer         text,
  section       text,
  logical_name  text,            -- registry logical name (firmware-agnostic)
  urn           text,
  mkey          text,            -- object name / row id
  payload       jsonb,           -- the object's own fields (no children)
  content_hash  text,            -- hash(payload) for diff writes
  depth         int,
  idx           int              -- order within parent
)
-- indexes: (appliance_id, section), (appliance_id, logical_name, mkey),
--          GIN(payload), (content_hash)

-- hot-type typed projections (denormalized, rebuilt each ingest)
device_server_policy(object_id fk device_object, appliance_id, name,
  deployment_mode, vserver, server_pool, web_protection_profile,
  http_service, https_service, monitor_mode, status)
device_server_pool(object_id, appliance_id, name, type, protocol)
device_web_protection_profile(object_id, appliance_id, name, kind, signature_rule, …)

-- pessimistic lease locks (§6)
resource_lock(
  id            bigserial pk,
  appliance_id  int,
  resource_key  text,            -- e.g. 'server_policy:pol-demo-ecom'
  owner_user_id int  fk users(id),
  owner_label   text,            -- username for display
  acquired_at   timestamptz,
  heartbeat_at  timestamptz,
  expires_at    timestamptz,     -- lease; auto-expired when now() > expires_at
  unique(appliance_id, resource_key)
)

-- sync history (Automation → Actions runs, ⟳, write-through)
sync_run(
  id            bigserial pk,
  appliance_id  int,
  section       text,
  trigger       text,            -- 'manual' | 'scheduled' | 'write_through'
  user_label    text,
  started_at    timestamptz,
  finished_at   timestamptz,
  status        text,            -- 'ok' | 'error' | 'skipped'
  changed       int,             -- objects rewritten (diff-hash)
  detail        text
)
```

Existing management tables (`users`, `appliances`, `templates`, `audit_logs`,
`app_settings`, …) are unchanged in shape — only their **backend moves to
Postgres** (§9).

---

## 5. Read path (DB-first, per-section, paginated)

A single helper centralizes reads so views stop calling the box directly.

```python
# app/services/read_layer.py
def read_section(appliance, section, *, page=1, per_page=100, q=None):
    """DB-first. Returns (rows, meta{generated_at, source, total, stale})."""
    # SELECT from device_object / typed projection, paginated, optional filter.

def refresh_section(appliance, section, *, user) -> SyncRun:
    """⟳ : go live for THIS section only, ingest with diff-hash, write a
    sync_run row, publish to git if changed. Returns counts."""
```

- Views (`workspace`, `server_objects`, `web_protection`, `section_config`,
  `objedit`, `search`, `architecture`, `fleet_objects`) switch their list reads
  to `read_section`. **Piloted first on `workspace` (Server Policy) and
  `server_objects`**, validated, then rolled out.
- Each list shows a **freshness badge**: `DB · hace 3 h · ⟳`. ⟳ refreshes only
  that section (not the whole device).
- Detail/edit still loads the single object live-or-DB, but editing requires a
  **lock** (§6) and writes go through **approval** (§7).

---

## 6. Concurrency — lease-based pessimistic locks

**Acquire** when a user opens an object for edit:
`POST /api/lock {appliance_id, resource_key}` → insert into `resource_lock`
(unique constraint). If a row exists and `now() < expires_at`, return **423
Locked** with the owner's name + remaining lease. If it exists but expired,
**steal** it (atomic `UPDATE … WHERE expires_at < now()`).

**Hold/heartbeat.** Lease = 2 min. The edit page heartbeats every 30 s
(`POST /api/lock/heartbeat`) to extend `expires_at`. Abandoned tab → lease
lapses → object becomes editable again automatically. No stuck locks.

**Release** on save/cancel/navigation (`DELETE /api/lock`).

**Atomicity** uses Postgres: the unique `(appliance_id, resource_key)` index +
`INSERT … ON CONFLICT DO NOTHING` / conditional `UPDATE` make acquire/steal
race-free across all gunicorn workers. (This is why held `FOR UPDATE` row locks
don't work — they can't span a stateless user session; the lease can.)

UI: a locked object shows a banner *"En edición por <user> — vence en 1:45"* and
its inputs are disabled until the lease lapses or the owner releases.

---

## 7. Write path — dry-run → approval → apply → write-through

`fortiweb_ops.py` already defaults to `dry_run=True` and records before/after.
We make the approval explicit and DB-aware:

1. User edits a locked object, clicks **Save**.
2. App computes a **dry-run diff**: desired payload vs the **DB snapshot**
   (cheap, no box) → a field-level before/after view.
3. **Approval modal** renders the diff; user must click **Accept & apply**.
4. On accept: live `FortiWebOps.<op>(dry_run=False)` (snapshot + audit + change
   history), then **write-through** `refresh_section` for that object's section
   so the DB reflects the new state immediately, then **release the lock**.
5. On reject/cancel: nothing is written, lock released.

This satisfies decision 2 (see-and-accept before apply) and keeps the DB
consistent right after a write without a full device sync.

---

## 8. Sync orchestration

```python
# app/services/device_sync.py
def sync_device(appliance, *, deep=False, sections=None, user, publish=True):
    """Read sections live (read-only REST via rediscovery), decompose to
    device_object (JSONB) with diff-hash, rebuild typed projections, write
    reports/<device>/ + git_publish if changed, write a sync_run row."""

def sync_fleet(appliances, *, deep=False, user): ...
def backfill_from_git(*, force=False):
    """Seed the DB from the existing reports/ tree (fresh clone/install is not
    empty without touching a box)."""
```

**Three triggers** (all converge on `sync_device`/`refresh_section`):
1. **Manual** — ⟳ per section + "Sync now" on Settings → Devices.
2. **Scheduled** — `device_sync` (light) + `device_inspect` (deep) catalog
   entries in `scheduled_actions.py`; the user sets cadence/targets in
   **Automation → Actions** (decision 5). The existing `scheduler_runtime.py`
   QTimer-equivalent serializes runs.
3. **Write-through** — after an approved write (§7), refresh that section.

Decomposer (`device_store.py`) ports the desktop `nodes_from_snapshot` /
`nodes_from_report` pure functions (object + sub-objects → flat node tree),
adapted to emit JSONB payloads.

---

## 9. SQLite → PostgreSQL consolidation (decision 4)

1. **Install Postgres** on LXC 248; create role + db
   (`fortinet` / `fortinet_mgr`). Store the URL in `.env`
   (`SQLALCHEMY_DATABASE_URI=postgresql+psycopg://…`). Add `psycopg[binary]` to
   `requirements.txt`.
2. **Adopt Flask-Migrate/Alembic.** Generate the baseline migration from the
   current models, then a migration per new table set (§4). Replace the
   `db.create_all()` bootstrap with `flask db upgrade` at deploy.
3. **One-shot data migration** SQLite→Postgres: a script that opens the old
   `fortinet.db`, reads every management table, and bulk-inserts into Postgres
   (order respects FKs). Verify row counts per table. Keep `fortinet.db` as the
   rollback until the user signs off (per fleet migration policy).
4. **Verify**: app boots against Postgres, login works, appliances/templates/
   audit all present, JWKS/SSO unaffected (local users here, no SSO).

> One database, not three. Git remains an **export/backup** (files in a repo),
> which is not a running service — so the "3 services" concern is satisfied:
> exactly one DB engine (Postgres) + the app + git files.

---

## 10. Installer (online / offline, migratable)

The "everything in Postgres" choice makes the box self-contained and portable:
- **Online installer**: provision LXC → `apt install postgresql` → create
  role/db → `pip install -r requirements.txt` → `flask db upgrade` → seed admin.
- **Offline installer**: bundle the Postgres package + a wheelhouse + the repo;
  same `flask db upgrade` path (Alembic makes the schema reproducible — this is
  why §2.2 makes Alembic a prerequisite).
- Migratable: `pg_dump`/`pg_restore` moves the whole source-of-truth between
  hosts; git carries the `reports/` backup independently.

(Installer is its own later deliverable; called out here so Phase 0 doesn't
paint us into a non-reproducible-schema corner.)

---

## 11. FortiADC (later)

Storage (`device_object` JSONB, type-agnostic) already supports it. Only a
FortiADC-specific `rediscovery` (which endpoints to walk, via
`clients/fortiadc.py`) is missing. Separate phase after FortiWeb proves out.

---

## 12. Phase roadmap (the plan)

Each phase produces working, testable software on its own. We expand each phase
into a detailed TDD task list **when we reach it** (the later phases depend on
earlier output, so detailing them now would be guesswork).

- **Phase 0 — Postgres + Alembic foundation.** Install Postgres, add psycopg,
  adopt Flask-Migrate, baseline migration, data-migration script, cut over,
  verify. *(No behavior change; pure substrate.)* — **detailed below.**
- **Phase 1 — Device cache schema + decomposer.** New tables (§4) as models +
  Alembic migration; port `device_store` decomposer (pure, TDD with fakes);
  `ingest_snapshot` with diff-hash; typed-projection rebuild.
- **Phase 2 — Sync orchestration + git backup.** `device_sync.sync_device`
  (read-only REST via existing `rediscovery`), `reports/<device>/` write +
  `git_publish`, `backfill_from_git`, `sync_run` rows.
- **Phase 3 — DB-first read layer + badges.** `read_layer.read_section`
  (paginated) + `refresh_section`; pilot on `workspace` + `server_objects`;
  freshness badge component.
- **Phase 4 — Locking.** `resource_lock` model + `/api/lock` endpoints
  (acquire/heartbeat/steal/release) + edit-page integration + banner.
- **Phase 5 — Approval write path.** Dry-run diff vs DB, approval modal,
  apply + write-through + lock release in `fortiweb_ops`/`objedit`.
- **Phase 6 — Automation actions.** `device_sync` + `device_inspect` catalog
  entries in `scheduled_actions.py`; user sets cadence in Automation → Actions.
- **Phase 7 — Roll read layer to remaining views** (`web_protection`,
  `section_config`, `objedit`, `search`, `architecture`, `fleet_objects`).
- **Phase 8 — Installer (online/offline) + migratability.**
- **Phase 9 — FortiADC reader.**

---

## 13. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Postgres cutover breaks management data | One-shot migration verifies row counts; keep `fortinet.db` as rollback until sign-off (fleet migration policy). |
| Lease lock confuses users | Clear banner with owner + countdown; short 2-min lease + 30-s heartbeat; explicit steal-on-expiry. |
| DB drifts stale vs box | Freshness badge per section + ⟳ + write-through after every approved write + scheduled sync. |
| JSONB queries slow at fleet scale | GIN index on `payload` + typed projections for hot list views. |
| Schema not reproducible on fresh install | Alembic from Phase 0; installer runs `flask db upgrade`. |

---

## Phase 0 — detailed TDD tasks (executable now)

> Implement on LXC 248 `/opt/ofortmaut`. Run app commands inside the
> container: `ssh -i /opt/proxmox-power-panel/keys/id_ed25519 root@192.0.2.34
> "pct exec 248 -- bash -c 'cd /opt/ofortmaut && …'"`.
> Restart after deploy: `systemctl restart ofortmaut.service`.

### Task 0.1 — Install PostgreSQL + role/db
- [ ] `apt-get install -y postgresql postgresql-contrib`
- [ ] `sudo -u postgres psql -c "CREATE ROLE fortinet LOGIN PASSWORD '<gen>';"`
- [ ] `sudo -u postgres psql -c "CREATE DATABASE fortinet_mgr OWNER fortinet;"`
- [ ] Verify: `psql "postgresql://fortinet:<pw>@127.0.0.1/fortinet_mgr" -c '\l'`

### Task 0.2 — Add driver + Flask-Migrate to deps
- [ ] Add `psycopg[binary]==3.2.*` and `Flask-Migrate==4.*` to `requirements.txt`
- [ ] `pip install -r requirements.txt`
- [ ] Verify: `python -c "import psycopg, flask_migrate; print('ok')"`

### Task 0.3 — Wire Flask-Migrate (failing test first)
- [ ] **Test** `tests/test_migrations.py::test_alembic_upgrade_head_builds_schema`:
      spin a temp Postgres schema, run `flask db upgrade`, assert `users`,
      `appliances`, `templates` tables exist.
- [ ] Run → FAIL (no migrations dir).
- [ ] Init `flask db init`; `flask db migrate -m "baseline"` from current models.
- [ ] Replace `db.create_all()` in `app/__init__.py` with an `upgrade()` call
      (or document `flask db upgrade` as the deploy step).
- [ ] Run → PASS.
- [ ] Commit.

### Task 0.4 — Point config at Postgres
- [ ] Set `SQLALCHEMY_DATABASE_URI=postgresql+psycopg://fortinet:<pw>@127.0.0.1/fortinet_mgr`
      in `/opt/ofortmaut/.env`.
- [ ] `flask db upgrade` → schema created in Postgres.
- [ ] Verify app boots: `systemctl restart ofortmaut.service` + curl `/`.

### Task 0.5 — Data migration SQLite → Postgres
- [ ] **Test** `tests/test_pg_migrate.py`: seed a temp SQLite with N users/
      appliances, run `migrate_sqlite_to_pg()`, assert equal counts in Postgres.
- [ ] Run → FAIL.
- [ ] Write `scripts/migrate_sqlite_to_pg.py` (read each management table, bulk
      insert FK-ordered: profiles→users→appliances→templates→audit_logs→
      app_settings→user_settings→…).
- [ ] Run → PASS.
- [ ] Execute against the live `fortinet.db`; verify row counts per table; login.
- [ ] Commit. Keep `fortinet.db` as rollback.

---

## Addendum (2026-06-29) — extra deliverables requested

Folded into the roadmap as Phases 8–9 (UI) on top of the substrate:

- **Phase 8 — Database page (new top-level page, NOT under Settings).** Keep
  Settings light: a dedicated `/database` page (admin-only, `USER_MANAGE`) with
  three tabs: (1) **Relational model** — entity/relationship view of the
  Postgres schema (tables, columns, types, PK/FK edges, rendered from
  `information_schema`/SQLAlchemy metadata); (2) **Tables** — browse any table's
  rows, paginated; (3) **SQL console** — run direct queries. Console is
  **read-only by default** (only `SELECT`/`WITH`/`EXPLAIN` allowed; a writable
  mode is an explicit, separately-gated toggle with confirm) so a stray
  `DROP`/`UPDATE` can't nuke the source of truth. Results paginated + CSV export.

- **Per-device JSON backup + optional git.** Every device's full config is
  exported as `reports/<device>/_config.json` (already the Phase-2 artifact);
  the Backups section exposes a **"push to git" toggle** so the user chooses
  whether the JSON (and the DB dump) are committed to the repo. So the source of
  truth exists in three forms: **Postgres** (live queryable), **JSON files**
  (per-device, human-readable), and **git** (versioned off-box, opt-in).

- **Phase 9 — System + DB backup & restore.** A section to back up and restore
  the whole instance: **`pg_dump`** of the Postgres DB (custom format) + the
  `reports/` JSON tree + the `.env`-referenced config, bundled and downloadable;
  **restore** from a chosen bundle (`pg_restore`), with a pre-restore safety
  dump. Optional git push of the backup bundle. Scheduled backups reuse
  Automation → Actions (a `system_backup` catalog action).

These do not change decisions 1–6; they are additive UI/ops on the Postgres
substrate Phase 0 establishes.

---

## COMPLETION LOG (2026-06-29) — Phases 4–9 implemented & verified

All work below was implemented on LXC 248, tested after each phase, service
restarted and confirmed UP. Test suite: **234 passed / 2 pre-existing failures**
(`test_logs_routes::test_status_idle` state-leak + `test_wpp_exceptions::
test_type_fields_route` — both failing BEFORE this work, untouched/out of scope).

- **Phase 4 — Locking.** `services/lock_service.py` (lease TTL 120s + heartbeat,
  race-safe via the `uq_resource_lock_dev_key` unique constraint), `views/locks.py`
  (`/api/locks/acquire|heartbeat|release|steal|status`), `static/js/lock.js`
  (acquire → 30s heartbeat → banner + "Take over" + save-guard → release on
  unload), wired into the objedit editor. 12 tests.
- **Phase 5 — Approval write-path + write-through.** `services/write_through.py`
  (`diff_object` before/after vs cache for the approval preview; `local_update`/
  `local_delete` keep the cache consistent after an approved write WITHOUT a full
  re-sweep — the 2000-object-safe path; releases the lease). Wired into objedit
  save/delete; the editor preview now shows a "Changes vs local source of truth"
  table. 5 tests.
- **Phase 6 — Automation actions.** `device_sync` (cache refresh) + `device_inspect`
  (refresh + git publish) catalog entries in `services/scheduled_actions.py`;
  user sets cadence in Automation → Actions. 3 tests.
- **Phase 7 — DB-first roll-out (partial).** Web Protection + Server Objects now
  read DB-first via `read_layer` with a freshness badge + ⟳ Refresh (matching
  Server Policy from Phase 3). Detail/editor views (section_config, objedit) and
  the fleet views (search, architecture, fleet_objects) still read live — not the
  2000-row list problem; candidates for a later pass.
- **Phase 8 — Database page.** Top-level `/database` (admin-only, NOT under
  Settings). `services/dbintrospect.run_query` (read-only: SELECT/WITH/EXPLAIN
  only, rolled-back + time-limited txn) + `table_page` pagination. Three tabs:
  relational model (tables + PK/FK edges), table browser, SQL console + CSV
  export. Verified live against Postgres (real `device_server_policies` rows;
  writes blocked). 6 tests.
- **Phase 9 — System backup & restore.** `services/system_backup.py` (`pg_dump
  -Fc` + `reports/` JSON → one `.tar.gz`; `pg_restore --clean` with a SAFETY dump
  first; password via `PGPASSWORD`, never on the cmdline). Top-level
  `/system-backup` page (create / download / restore-with-confirm / "publish
  device JSON to git" toggle) + a `system_backup` scheduled action. Bundles
  gitignored. Verified live (423 KB bundle = 262 KB pg_dump + reports). 5 tests.

**Source of truth now exists in three forms:** PostgreSQL (live, queryable, the
DB-first reads) · per-device `reports/<device>/_config.json` (human-readable) ·
git (opt-in, versioned, off-box).

**Still pending / not done:** FortiADC reader (deferred by decision), the rest of
the Phase-7 read-layer roll-out, an installer (online/offline) for migratability,
and a real round-trip of `restore_backup` (the create path is live-verified; a
full destructive restore was NOT run on the live instance — exercise it on a
throwaway DB first).

---

## COMPLETION LOG (2026-06-29, cont.) — Diagram, restore proof, installer, fleet DB-first

Continued from the Phase 4–9 log above. Service restarted + confirmed UP after
each change; full suite **234 passed / 2 pre-existing failures** (unchanged),
plus new tests below.

- **Relational DIAGRAM (user's explicit ask — "diagrama, no cuadros").** The
  Database page "Relational model" tab is now a real interactive **ER diagram**
  (`static/js/er_diagram.js`, zero-dependency SVG so it works offline): tables as
  nodes, FK relationships as connecting lines with arrowheads, a force-directed
  auto-layout, drag-nodes / pan / wheel-zoom / Fit / Re-layout, hover-highlight of
  a table's relationships, and a ↺ badge for self-references. The old row-table is
  kept as a collapsible "Show as list" fallback. Verified live: **24 tables, 16 FK
  edges** (incl. the `device_objects → device_objects` self-ref). +1 regression
  test (`test_database_page_renders_er_diagram`).
- **Phase 9 restore — now DESTRUCTIVELY VERIFIED.** Ran the full round-trip into a
  THROWAWAY DB (`fortinet_restore_test`): `create_backup` → `restore_backup`
  (conn override) → row-count parity across users/appliances/device_objects/
  device_server_policies/device_snapshots/audit_logs — **all match**. (Also
  confirmed the manual `pg_dump -Fc` (262 KB) + `pg_restore --clean` path.) The
  throwaway DB + test bundles were dropped; production untouched + healthy.
- **Installer (migratability goal).** `scripts/install.sh` (online + `--offline`)
  + `scripts/build_offline_bundle.sh` + `docs/INSTALL.md`. Idempotent and SAFE:
  NEVER regenerates SECRET_KEY/FERNET_KEY when `.env` exists, creates the UTF-8
  Postgres role/DB only if missing, and always runs `flask db upgrade` (with
  `FORTINET_SKIP_DB_BOOTSTRAP=1` so `create_all` can't race Alembic — a real bug
  the fresh-install test caught). **VERIFIED on a real fresh install** into a temp
  dir + temp DB + temp service on :8099 (24 tables built by Alembic from zero,
  admin seeded, login 200), then fully torn down.
- **Phase 7 — fleet DB-first (completed the big read-path roll-out).** The
  fleet-wide object browser (`services/fleet_objects.py`, the
  Settings → "Fleet objects" / `/fleet-objects` page) NO LONGER aggregates live
  across every appliance on each request — `_fetch_objects` now reads **DB-first**
  from the Postgres cache (`device_objects` via `read_layer`), mapping each type to
  its cached logical name(s) (WPP = inline+offline, kind-tagged). Verified live:
  server_policy 20 rows, server_pool CSV with real cached rows, wpp merges
  inline+offline — all with zero appliance hits. +3 tests
  (`tests/test_fleet_objects.py`).

**Now genuinely remaining (and why):** the FortiADC reader (deferred by the
user's own decision — "fortiadc separately and later" [translated from Spanish]); and the `search` page +
`architecture` map still read their existing sources (git Policy-Inspector
reports / topology snapshots) which are already file/DB-backed, not the
live-2000-row problem. The core source-of-truth architecture (Postgres + JSON +
git, DB-first reads, locking, approval write-through, automation, backup/restore,
the relational diagram, and the installer) is complete and verified.
