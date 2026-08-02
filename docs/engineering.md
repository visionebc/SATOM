# SATOM — Engineering Manual

> **Audience:** developers extending the codebase and platform engineers
> operating a deployment. Companion documents: field-level object references
> ([server_policy.md](server_policy.md),
> [web_protection_profile.md](web_protection_profile.md),
> [wpp_exceptions.md](wpp_exceptions.md)), the device-cache contract
> ([source-of-truth-spec.md](source-of-truth-spec.md)), the install runbook
> ([INSTALL.md](INSTALL.md)) and the API reference ([api_v1.md](api_v1.md)).

---

## Table of contents

1. [System architecture](#1-system-architecture)
2. [Runtime & deployment](#2-runtime--deployment)
3. [Products (ADOMs) and request scoping](#3-products-adoms-and-request-scoping)
4. [Data layer](#4-data-layer)
5. [The endpoint registry](#5-the-endpoint-registry)
6. [Device clients](#6-device-clients)
7. [Service layer map](#7-service-layer-map)
8. [Security engineering](#8-security-engineering)
9. [Frontend architecture](#9-frontend-architecture)
10. [Testing](#10-testing)
11. [Background jobs framework](#11-background-jobs-framework)
12. [Extending the app](#12-extending-the-app)
13. [Conventions & hard-won gotchas](#13-conventions--hard-won-gotchas)

---

## 1. System architecture

```
app/__init__.py      create_app(): config, extensions, _ensure_columns()
                     migrations-on-boot, registry seed, report seed,
                     jobs orphan sweep, blueprint registry + product gate,
                     legacy-URL WSGI shim
app/views/*.py       ~60 blueprints — thin HTTP handlers (params → service
                     call → template/JSON). No business logic here.
app/services/*.py    ~80 modules — ALL business logic. No Flask request
                     context assumed (workers import these too).
app/clients/         REST clients (fortiweb.py, fortiadc.py, base.py) +
                     client_for(appliance) platform factory.
app/registry/        endpoint catalog: loader.py (DB-first + YAML fallback),
                     data specs (WAF kinds, help overlays).
app/models*.py       SQLAlchemy models. Postgres in production.
app/api_v1/          the public token API (separate auth path, JSON-only).
app/templates|static Jinja + Turbo Drive + CSP-safe vanilla JS.
```

**Dependency direction:** `views → services → {clients, registry, models}`.
Keep it acyclic; services must stay importable without a request context —
the background-job workers and the scheduler sidecar run them headless.

**Design pillars:**

- **DB-first reads** (`services/read_layer.py`): pages render from the local
  device cache; live device I/O is explicit (refresh buttons, saves).
- **Dry-run-first writes** (`services/fortiweb_ops.py`): every device
  mutation previews a computed diff, then applies with snapshot + audit +
  change-history.
- **Registry-resolved URLs:** nothing hardcodes a REST path; callers resolve
  logical names per product/API version (§5).
- **Fail-closed on partial knowledge:** e.g. certificate removal refuses when
  bindings can't be verified; sync aborts rather than overwrite the cache
  with an empty snapshot.

## 2. Runtime & deployment

- **Process model:** gunicorn `4 workers × 8 gthread threads` binding
  `0.0.0.0:8000`, fronted by an edge nginx (TLS, gzip, `/static/` proxy
  cache). No app-side HTTP cache.
- **Systemd:** the main unit runs as the unprivileged `satom` user with
  `NoNewPrivileges`, `ProtectSystem=strict` (+ explicit `ReadWritePaths`),
  `PrivateTmp`. A **scheduler sidecar** unit fires due scheduled actions.
- **PostgreSQL** is the source of truth (`SQLALCHEMY_DATABASE_URI` in `.env`);
  `pool_pre_ping` + `pool_recycle=1800`. Nightly `pg_dump` via cron; the
  in-app System Backup bundles dump + reports tree with a verified restore.
- **Redis** (local) backs Flask-Limiter (`RATELIMIT_STORAGE_URI`) and the
  shared JSON cache (`services/cache.py`, key prefix `fmcache:*`, in-process
  fallback with backoff). Note: Flask-Limiter 3.x ignores the legacy
  `RATELIMIT_STORAGE_URL` name — use `..._URI`.
- **Secrets:** `.env` (mode 640, gitignored) holds `SECRET_KEY`, `FERNET_KEY`
  and the DB URL. `FERNET_KEY` encrypts appliance passwords at rest and is
  the **one non-regenerable secret** — losing/rotating it orphans every
  stored device credential. `install.sh` never regenerates an existing one.
- **Install / upgrade:** `scripts/install.sh` (idempotent; online or
  `--offline` from a wheelhouse built by `build_offline_bundle.sh`);
  `flask db upgrade` runs on every install. Boot-time `_ensure_columns()`
  additionally backfills additive columns so hot deploys don't need a manual
  migration for simple `ADD COLUMN` cases.
- **Restart after code/template changes:** gunicorn caches Jinja; static JS
  does not need a restart (`asset()` appends `?v=<mtime>`).
- **Concurrency protection for devices:** a per-`host:port` semaphore in
  `clients/base.py` caps concurrent requests per appliance (default 4,
  `FORTINET_HOST_CONCURRENCY`) so 4×8 gunicorn + sidecar can't flood a
  management plane. Connect timeout is capped at 10s.

## 3. Products (ADOMs) and request scoping

Three products share one app: `global` (`/`), `fortiweb` (`/web/…`),
`fortiadc` (`/adc/…`).

- **Blueprint registry:** FortiWeb-scoped blueprints are registered under the
  `/web` prefix; a WSGI shim rewrites legacy paths (`/workspace/…` →
  `/web/workspace/…`) without redirects so old links and tests keep working.
- **Effective product per request** (`g.product`, resolved in the gate):
  URL scope > `X-ADOM` header > `_adom` form field (urlencoded POSTs only) >
  session cookie. The session is only the default for new tabs; navigation
  never mutates it — only explicit switches do. Client side, each tab stores
  its ADOM in `sessionStorage` and stamps the header on every Turbo visit and
  fetch.
- **Data scoping** (`services/product_scope.py`): `stamp()` writes the
  product onto rows (jobs meta, audit, notifications, templates, baselines,
  scheduled actions); `scope_query()` / `visible_product()` filter reads.
  Rule: a fortiadc session sees only `fortiadc`; fortiweb sees everything
  except `fortiadc` (legacy unscoped rows are FortiWeb-era); global and
  headless workers see all.
- **Anti-drift guard:** `tests/test_product_separation.py` enforces import
  direction (ADC modules only import platform code; nothing outside a
  whitelist imports ADC modules) so a future physical split stays mechanical.

## 4. Data layer

**Management data** (SQLAlchemy models): users (scrypt hashes, lockout
columns, TOTP), appliances (Fernet-encrypted password property),
`AppSetting` key/value store (global keys by default; product-specific keys
carry a product prefix), templates/baselines, audit logs + change history,
config-backup vault (`ConfigBackup`), managed certificates + device
certificate inventory, API tokens (hashed), scheduled actions + runs, change
requests + events, bug reports, capacity limits, DB reports.

**Device cache** (the source-of-truth projection, see
[source-of-truth-spec.md](source-of-truth-spec.md)):

- `device_objects` — every object and sub-object of every device, flattened
  pre-order with parent self-FK, `layer ∈ {config, inventory, deep}`, plus an
  indexed scalar-field table for fleet-wide search.
- **Typed projections** — hot types denormalized into real tables
  (`device_server_policies`, `device_web_protection_profiles`,
  `device_server_pools`…) rebuilt on every ingest; they power typed queries
  and the ER diagram while everything else stays generic.
- `services/read_layer.py` — the read API: `read_objects`,
  `policy_full_cached` (reconstructs a policy's whole graph from the deep
  layer), `wpp_cached`, freshness metadata for the `DB · X ago` badges.
- **Ingest paths:** `device_sync.py` (config sweep; aborts after 8
  consecutive device-level errors; **zero objects ⇒ error, cache kept**),
  `deep_capture.py` / `analysis_deep.py` (per-policy graphs), plus
  `reports/<device>/_config.json` as the human-readable, git-shareable twin.

## 5. The endpoint registry

The registry decouples the app from firmware-specific REST paths.

- **Storage:** Postgres table `registry_endpoints (product, api_version,
  name, urn, enabled, updated_by, updated_at)` — unique per
  (product, api_version, name). Three catalogs: 507 FortiWeb rows (`v2.0`),
  255 FortiADC rows (`v1`) and 64 FortiAnalyzer rows (`jsonrpc`), seeded
  **insert-only** from `endpoints.yaml` / `endpoints_fortiadc.yaml` /
  `endpoints_fortianalyzer.yaml` at boot: an operator's edit or disable is
  never clobbered by a deploy. YAML remains the fallback when the DB is
  unavailable (scripts without app context).
- **Loader:** `app/registry/loader.py` — DB-first with a 60s per-process TTL
  cache; `resolve(name)` / `resolve_adc(name)` / `resolve_faz(name)` by
  logical name. After an edit the serving worker invalidates immediately;
  others converge ≤60s.
- **Editor:** the standalone Registry page was FUSED into the API console
  (2026-07-05); `/web/registry` and its section links redirect there. The
  write path (`registry.save` / `registry.toggle`, permission
  `registry_edit`) still lives on the registry blueprint and is reused by the
  console — one write path, no duplicate. Create/edit by modal,
  **soft-delete** (disable) with a restore panel; hard delete would just
  resurrect the row from the YAML seed on next boot. Fully audited.
- **One console per product:** `/web/api-explorer/` (FortiWeb, REST v2.0)
  · `/adc/api/` (FortiADC, REST, no version segment) · `/faz/api/`
  (FortiAnalyzer, JSON-RPC verbs over a single `POST /jsonrpc`). Each fuses
  its own catalog + a live console; `registry.execute_write` gates every
  mutating verb. Operator-facing reference: `docs/device-api.md`.
- **Drift guard:** a test fails the build if any URN in the dependency tree
  stops resolving against the registry.
- **WAF spec catalog:** `app/registry/data/waf_specs.json` (166 kinds —
  enums, refs, field order, `show_when` gating, value labels) plus
  `waf_help.json` (per-section help harvested from the vendor admin guide).
  These are **generated from the desktop project — never hand-edit**.

## 6. Device clients

`app/clients/base.py` — shared httpx transport: explicit TLS verify modes,
retries on transient failures, `httpx.Timeout(30, connect=10)`, per-host
semaphore.

**FortiWeb (`fortiweb.py`):**

- Auth: base64-encoded JSON credentials in the `Authorization` header on
  every request (stateless; the documented cookie session cannot write).
- Envelope: cmdb GET returns `{"results": [...]}` (single `?mkey=` →
  `{"results": {...}}`). Parse `j.get('results', j.get('data', []))`.
- **`list_with_error(path) -> (rows, error)`** is the important reader: it
  surfaces device-level rejections (HTTP ≥ 400, top-level or nested
  `errcode`, transport exceptions) instead of silently returning `[]`.
  Benign errcodes `-20001` (endpoint absent on this firmware) and `-3` (not
  found) still read as empty — the registry is a cross-firmware superset.
- Common errcodes: `-651` invalid value · `-56` empty required value ·
  `-7637` port in use · `-20010` **license lock** (whole API 423s) ·
  `errcode 10` CMDB save collision (auto-assigned ids carried into a POST —
  strip all hyphenated `*-id` and `index`).
- **Sub-table read scoping quirk:** read by-parent sub-tables via the logical
  endpoint with `?mkey=<parent>` — the path-style read *leaks the entire
  parent collection* when the sub-table is empty.

**FortiADC (`fortiadc.py`):**

- Login `POST /api/user/login` → Bearer token (+ login cookies). Envelope
  `{"payload": ...}` (array for collections; negative number = error).
- CRUD: `POST` bare / `GET` / `PUT ?mkey=` / `DELETE ?mkey=`; child tables
  `/api/<parent>_child_<table>?pkey=<parent>&mkey=<row>`. Paths are the CLI
  tree flattened with underscores (`load_balance_pool`).
- Status endpoint is `/api/platform/version` (there is no
  `/api/system/status`). No REST transport exists for config-restore or
  firmware — those remain SSH/manual by design.
- Cert upload: multipart to `/api/upload/certificate_local` with **file
  parts** `cert`/`key` (`type=CertKey`); the text mode fails.

`client_for(appliance)` dispatches by `appliance.kind` — use it instead of
importing a concrete client in views.

## 7. Service layer map

Grouped tour of `app/services/` (~80 modules):

- **Device I/O & cache:** `device_sync`, `deep_capture`, `analysis_deep`,
  `read_layer`, `device_store`, `rediscovery`, `inventory_metrics`,
  `device_context`, `hardware`, `ha`, `cluster`.
- **Policy & objects:** `policy_ops` (clone/migrate/enable/disable +
  preflight), `policy_form`, `policy_graph`, `policy_links`, `objform` (the
  form engine), `fortiweb_field_schema` (create-field seeds), `clone`,
  `clone_rules` (admin dummy-IP policy), `capacity`, `naming`, `baselines`,
  `templates`, `bulk` (background fleet applies).
- **WAF:** `waf_specs` (catalog registration), `signature_catalog`,
  `wpp_exceptions` (rules 1–4 enforcement), `exception_inject`,
  `exception_detect`, `regex_lab`, `section_taxonomy`, `wp_menu`.
- **Certificates:** `cert_manager` (scan/issue/lifecycle/dispatch-by-kind),
  `cert_adc`, `cert_ssh`, `cert_probe`.
- **Ops & automation:** `jobs` (framework), `deep_jobs`, `scheduled_actions`
  (catalog + executor), `scheduler` (pure next-run math), `change_requests`,
  `backup` (REST + SSH fallback vault), `logcollect`, `inspector`,
  `flash_report`, `release_notes`, `git_service`, `system backup` (via
  views/system_backup).
- **Platform:** `product_scope`, `access`/`auth_store`/`directory_auth`
  (RBAC + LDAP/RADIUS), `audit`, `notifications`, `email_service`,
  `encryption`, `lock_service`, `db_reports`/`report_builder`,
  `dbintrospect`, `dns_tool`, `fleet_objects`, `datasheets`, `bug_reports`.
- **FortiADC:** `adc_menu`, `adc_objform`, `adc_ops` (presets, discovery
  plan, VS inspector, health battery) — ADC-specific logic lives *only*
  here, enforced by the separation test.
- **Developer tools:** `lua_studio`, `py_console`, `plugin_sandbox`,
  `*_examples` (gated developer consoles with sandboxing).

## 8. Security engineering

- **AuthN:** local accounts (scrypt), optional TOTP 2FA, LDAP/RADIUS
  directory auth. Per-account lockout (10 fails → 15 min). Login rate-limit
  5/min/IP. Session cookies are Secure; the app is intended to live behind a
  TLS edge.
- **AuthZ:** role → permission gates (`config_write`, `user_manage`,
  `registry_edit`, `backup`, …) checked in views; Settings and Database are
  admin-only; API tokens are owner-capped (a token can never out-privilege
  its owner, and dies with them).
- **CSP (locked down):** `script-src-elem 'self' 'nonce-…'` (no
  unsafe-inline), **`script-src-attr 'none'`** (zero inline handlers —
  everything is `addEventListener` in nonced blocks), nonced style elements;
  only `style-src-attr` remains permissive. Turbo Drive requires re-stamping
  the live nonce onto body `<style>`/`<script>` before render
  (`turbo-boot.js`) — see §13.
- **CSRF:** Flask-WTF everywhere; the global fetch wrapper injects
  `X-CSRFToken` on same-origin fetches.
- **Secrets at rest:** appliance passwords Fernet-encrypted
  (`FERNET_KEY`); API tokens stored hashed, shown once; masked columns in
  the DB introspection tools; CA/ACME EAB secrets encrypted in settings.
- **Write safety:** dry-run default on every device write; snapshot + audit
  + change history on apply; command templates for external CAs are
  shlex-parsed *before* token substitution (no argv injection); SSH layer
  exposes read-only presets and validates `show`/`get`/`diagnose` scopes;
  destructive automation (firmware flash) requires an approved Change
  Request window; proxy API routes enforce appliance-kind guards.
- **Rate limiting:** Redis-backed Flask-Limiter; `TRUSTED_PROXIES` respected
  for client IPs.
- **Hardened unit:** non-root user, `ProtectSystem=strict`, `PrivateTmp`,
  `NoNewPrivileges`; container-level nftables restrict :8000 to the edge.

## 9. Frontend architecture

- **No SPA framework.** Server-rendered Jinja + **Hotwire Turbo Drive** for
  snappy navigation, vanilla JS modules under `app/static/js/`.
- **CSP-safe patterns:** all behavior binds via `addEventListener` inside
  nonced `<script>` blocks or external files; dynamic fragments re-stamp the
  document's live nonce; JSON islands
  (`<script type="application/json">`) pass data to JS.
- **`asset()`** helper cache-busts static files by mtime — JS/CSS changes
  need no service restart.
- **Reusable widgets:** the jobs dock (`jobs.js`, reconnects to any active
  job across navigation and auto-refreshes target pages on completion), the
  slide-over object-editor panels (`objedit_drawer.js`, stackable, promote
  create→edit, write back to the opening dropdown), the fleet map renderer
  (`fleet_map.js`, pure SVG), the ER diagram (`er_diagram.js`), the report
  builder wizard (`report_builder.js`).
- **Per-tab ADOM:** `sessionStorage.fmAdom` + `X-ADOM` header stamping in
  `turbo-boot.js` / the global fetch wrapper (§3).

## 10. Testing

- **Run:** `TMPDIR=$PWD/data/tmp venv/bin/python -m pytest -q` (create the
  tmp dir first). 700+ tests / 100+ files; no device, network, or display
  needed — clients are duck-typed fakes.
- **Coverage style:** service-level unit tests + Flask test-client
  integration tests (blueprints, permissions, CSRF exemptions in TESTING
  mode) + anti-drift guards (registry backing, product separation, typed
  projection schema, section catalogs, template locks).
- **Judging a run under `pct exec`/CI:** trust the **exit code** — the final
  pytest summary line does not always reach the log buffer.
- **Local pitfalls:** stale root-owned `/tmp/pytest-of-root` dirs break runs
  executed as the service user (hence the TMPDIR convention); smoke tests
  through HTTP must use the HTTPS edge URL (Secure cookies) and carry the
  CSRF token from a rendered page's `meta[name=csrf-token]`.
- **In-process smoke pattern:** `create_app()` + test client with
  `session['product']` and `_user_id` set (product gate redirects otherwise).

## 11. Background jobs framework

`services/jobs.py` — file-backed jobs (`data/jobs/*.json`), multi-worker
safe:

- `create_job(type, meta)` → id (timestamp + uuid suffix); workers run in
  threads via `run_async`; `update_job` for flat fields, **`mutate_job`** for
  atomic read-modify-write of nested meta.
- **Cooperative control:** `checkpoint()` in worker loops honors stop
  (raises) and pause (parks in place); jobs marked `cancelable=False`
  (firmware flash) refuse both. States: pending / running / pausing / paused
  / cancelling / success / error.
- **Orphan sweep at boot:** any non-terminal job whose recorded PID no longer
  exists is marked error ("the service restarted").
- Jobs carry `by` (owner), `host`/`pid`, product stamp, and an optional
  `result.reload_path` that tells the jobs dock which page to auto-refresh.
- **Rule: never call `url_for` inside a worker** — resolve URLs in the
  request handler and pass strings in (workers have no request context).
- The generic error handler must not overwrite a worker-recorded error
  (guarded via the active-jobs set).

## 12. Extending the app

- **New REST endpoint:** add a row from the product's API console (or the
  YAML seed for new installs). Code resolves it by logical name — no path constants.
- **New blueprint:** create `app/views/x.py`, register it in
  `app/__init__.py` (choose global vs `/web`-scoped vs `adc_bps` gate set),
  add the nav entry in `templates/base.html`, gate with a permission
  decorator.
- **New scheduled action:** add an `ActionSpec` to
  `services/scheduled_actions.py` wrapping an existing service function;
  it appears in the admin catalog automatically.
- **New WAF object kind:** regenerate `waf_specs.json` in the desktop
  project and sync it — do not hand-edit (a `.gitignore` gotcha once
  silently dropped `app/registry/data/`; it is anchored to `/data/` now).
- **New typed projection:** add the spec + a `CREATE TABLE` migration
  (append-only); a schema-parity test guards spec↔table drift.
- **New report:** prefer a built-in seeded in `services/report_builder.py`
  (auto-validated at boot) or let users build one with the wizard.
- **Versioning:** repo-root `VERSION` + tags; keep additive DB changes in
  `_ensure_columns()` *and* a real Alembic migration for fresh installs.

## 13. Conventions & hard-won gotchas

The internal project knowledge base carries the full, dated history. The ones you will hit first:

1. **License-locked devices 423 the whole REST API** (`-20010`) with no
   `results` key — always read through `list_with_error`, never assume
   empty-list means empty.
2. **By-parent sub-tables leak the parent collection** on path-style reads —
   use `?mkey=` scoped reads.
3. **Strip auto-assigned ids before re-POSTing** a GET payload (all
   hyphenated `*-id` + `index`) or the CMDB rejects with errcode 10.
4. **FortiWeb silently ignores inline sub-object arrays** on parent POSTs —
   split them into by-parent row creates.
5. **NTP servers:** add = path-style POST (no `?mkey=`); there is no per-row
   delete — removal is a replace-set. Modeled in `objedit` as a singleton
   sub-table.
6. **Turbo + CSP:** any dynamically (re)inserted `<script>`/`<style>` must
   carry the *document's* live nonce — Turbo copies the fetched response's
   nonce otherwise and the browser silently drops the element.
7. **`_adom` form scoping** is read for urlencoded POSTs only — parsing
   multipart in `before_request` would consume upload streams.
8. **Two files share the basename `cert_manager.py`** (service and view) —
   when staging copies over SSH/`pct push`, use unique staging names or they
   overwrite each other. Same for any multi-source `scp` (two sources into
   one target path create a directory).
9. **`python3` everywhere** (no `python` binary on the hosts); use the venv
   interpreter for anything importing the app, with `.env` loaded.
10. **Restart discipline:** Python/template changes need a service restart;
    static JS/CSS do not (`asset()` mtime busting).
11. **Backups on unlicensed boxes:** device-side REST backup returns
    `-20010`/`-901`; the SSH `show full-configuration` fallback is the
    reliable path (and the vault note records why).
12. **The registry is a cross-firmware superset:** an endpoint absent on a
    given firmware answers `-20001` and must degrade to "empty", not error.
