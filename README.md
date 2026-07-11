# Fortinet Manager — Web Edition

A multi-user **Flask web platform for managing fleets of Fortinet appliances**
(FortiWeb WAFs and FortiADC load balancers) over their REST APIs and SSH/CLI —
with a local, queryable copy of every device's configuration so the UI stays
fast even when the appliances are slow, unreachable, or license-locked.

- **Version:** 1.0 · **Status:** production (single-site deployment) · **License:** private (not yet published under an OSS license)
- **~60 Flask blueprints · ~80 service modules · 700+ unit/integration tests · 500 tracked files**

---

## What it does

| Area | Highlights |
|---|---|
| **Server Policy management** | FortiWeb-style policy table + editable detail form, minimal-diff saves, guided **clone / migrate** across devices (pre-flight checklist, dummy-VIP rules, WPP handling), safe cascade delete |
| **Web Protection (WAF)** | Full mirror of the FortiWeb 7.6 GUI menu — Signatures editor (category / details / per-signature exceptions), 166 curated object kinds ported from the desktop app, guided WAF exceptions with template locks and lifecycle tracking |
| **Generic object editor** | Any of ~500 registry endpoints editable through one spec-driven form engine (`objedit`) — stacked slide-over panels, create-references-in-place, sub-tables, dry-run previews on every write |
| **Device operations** | Discovery / rediscovery, deep capture, config backups (REST with SSH fallback), restore vault, firmware upgrade runbooks, boot-partition management, SSH console with read-only presets |
| **Fleet visibility** | Architecture network diagram (SVG, DB-first), fleet-wide object search, FortiView analysis + packet capture, DNS & LB lookup tool, metrics dashboard, certificate inventory |
| **Certificates** | Central Certificate Manager — issuance via **ADCS or ACME** (switchable), lifecycle policy (revoke-on-supersede, expiry sweeps), SNI policies, key upload over SSH, REST deploy to FortiADC |
| **Automation** | Scheduled actions (cron-style catalog: backups, syncs, cert scans, upgrades), **Change Requests** (maintenance-window approval gates for risky work), background jobs with pause / resume / stop |
| **Multi-product (ADOMs)** | Three workspaces — **Global** `/`, **FortiWeb** `/web/`, **FortiADC** `/adc/` — with per-browser-tab product context and strict data scoping between products |
| **Integration API** | Versioned `/api/v1` with scoped bearer tokens (`read ⊂ write ⊂ admin`, owner-capped, product-bound) — deliberately narrow and read-biased |
| **Reporting** | Report Builder (no-SQL wizard + 7 built-in reports), live ER diagram of the schema, system backup/restore bundles |

## Architecture at a glance

```
Browser (Turbo Drive, nonce-based CSP, per-tab ADOM header)
   │ HTTPS
Edge reverse proxy (nginx: TLS, gzip, static cache)
   │
Gunicorn (4 workers × 8 threads) ── Flask app factory (app/)
   │            │                        │
PostgreSQL      Redis                 Scheduler sidecar (systemd)
(source of      (rate-limit +
 truth + device  shared cache)
 config cache)
   │
   ├── httpx REST clients ───► FortiWeb / FortiADC appliances
   └── paramiko SSH ─────────► CLI-only tasks (backups, captures, cert upload)
```

The defining design choice is **DB-first reads**: pages render from a
normalized local cache of each device's whole configuration
(`device_objects`, populated by rediscovery / deep capture) with an explicit
*refresh-live* escape hatch — instead of hammering the appliance management
plane on every page load. See [docs/engineering.md](docs/engineering.md).

## Quick start

Requires a Debian-family host with Python 3.11+ and PostgreSQL.

```bash
# put the source at /opt/fortinet-manager (git clone / tarball)
cd /opt/fortinet-manager
sudo ./scripts/install.sh          # online install
# or, air-gapped:
./scripts/build_offline_bundle.sh  # on a connected twin host
sudo ./scripts/install.sh --offline
```

The installer provisions PostgreSQL, generates `SECRET_KEY` / `FERNET_KEY`
into `.env`, runs Alembic migrations, installs the systemd unit and starts the
app on `:8000`. First login: `admin` / `Sopas123.-` — **change it immediately**
(the app also supports per-account lockout, TOTP 2FA, and LDAP/RADIUS
directory auth).

Full install/upgrade/backup notes: [docs/INSTALL.md](docs/INSTALL.md).

## Documentation

Three levels, written for three audiences:

| Manual | Audience | Contents |
|---|---|---|
| [**User Guide**](docs/user-guide.md) | Operators & engineers using the UI | Every screen and workflow: devices, policies, WAF, exceptions, certificates, automation, troubleshooting |
| [**Engineering Manual**](docs/engineering.md) | Developers & platform admins | Architecture, data layer, registry, clients, jobs framework, security engineering, testing, deployment, conventions & gotchas |
| [**Management Overview**](docs/management-overview.md) | Non-technical stakeholders | What it is, business value, risk posture, costs, roadmap — no jargon |

Reference documents (deep dives):

- [docs/overview.md](docs/overview.md) — project overview & operational rules
- [docs/api_v1.md](docs/api_v1.md) — API v1 integration manual (tokens, endpoints, examples)
- [docs/server_policy.md](docs/server_policy.md) — Server Policy object model, field-level
- [docs/web_protection_profile.md](docs/web_protection_profile.md) — WPP / WAF dependency graph
- [docs/wpp_exceptions.md](docs/wpp_exceptions.md) — WAF exceptions workflow & data model
- [docs/source-of-truth-spec.md](docs/source-of-truth-spec.md) — device cache / source-of-truth spec
- [docs/fortiadc.md](docs/fortiadc.md) — FortiADC REST conventions
- [docs/release_notes.md](docs/release_notes.md) — release-notes harvester & upgrade planning
- [docs/INSTALL.md](docs/INSTALL.md) — install & migrate

## Tech stack

Python 3.11+ · Flask 3 · SQLAlchemy 3 / Alembic · PostgreSQL · Redis ·
gunicorn · httpx · paramiko · cryptography (Fernet) · Flask-Login /
Flask-WTF / Flask-Limiter · ldap3, pyotp, pyrad (directory auth + 2FA) ·
Hotwire Turbo (no SPA framework, CSP-safe vanilla JS) · reportlab / pdfplumber
(reports).

## Testing

```bash
cd /opt/fortinet-manager
TMPDIR=$PWD/data/tmp venv/bin/python -m pytest -q
```

700+ tests across 100+ files run without a device, a display, or network —
clients are duck-typed and faked. See the testing chapter of the
[Engineering Manual](docs/engineering.md#10-testing).

## Security model (summary)

- RBAC (readonly / operator / admin profiles) + per-permission gates on every write
- Every device write goes through a **dry-run-first** pipeline with snapshot,
  audit log and change history; destructive actions sit behind approval
  workflows (Change Requests)
- Strict CSP (`script-src-attr 'none'`, nonce-based scripts/styles), CSRF
  everywhere, per-account lockout, Redis-backed rate limiting
- Appliance credentials Fernet-encrypted at rest; `.env` holds the only
  non-regenerable secret (`FERNET_KEY`)
- Hardened systemd unit (non-root user, `ProtectSystem=strict`, `PrivateTmp`)

Details: [Engineering Manual §8](docs/engineering.md#8-security-engineering).

## Repository layout

```
app/
  __init__.py        app factory, blueprint registry, product (ADOM) gate
  models*.py         SQLAlchemy models (users, appliances, cache, certs, jobs…)
  clients/           REST clients (FortiWeb, FortiADC) + platform factory
  registry/          versioned endpoint catalog (DB-backed, YAML seed)
  services/          ~80 business-logic modules (no Flask views inside)
  views/             ~60 blueprints (thin HTTP layer over services)
  api_v1/            the public token API
  templates/ static/ Jinja templates + CSP-safe JS
docs/                the manuals you are reading
migrations/          Alembic
scripts/             install.sh, offline bundle builder, operational scripts
tests/               700+ pytest tests (no device needed)
deploy/              systemd units and deployment artifacts
```
