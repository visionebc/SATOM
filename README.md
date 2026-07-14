# OFortMAuT — Web Edition

A multi-user **Flask web platform for managing fleets of Fortinet appliances**
— **FortiWeb** (WAF), **FortiADC** (ADC/load balancer), and **FortiAnalyzer**
(logs & analytics), with **FortiAuthenticator** planned — over their REST/JSON-RPC
APIs and SSH/CLI, with a local, queryable copy of every device's configuration so
the UI stays fast even when the appliances are slow, unreachable, or license-locked.

> **Not a firewall manager.** OFortMAuT manages application-delivery and
> analytics appliances. It is **not** a FortiManager or FortiGate/NGFW tool.

- **Version:** see [`VERSION`](VERSION) · **Status:** production · **License:** [Elastic License 2.0](LICENSE) · [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Release pipeline](docs/release-pipeline.md)
- **~60 Flask blueprints · ~80 service modules · 700+ unit/integration tests · 500 tracked files**

> ⚠️ **Trademark:** OFortMAuT is an independent source-available project, **not
> affiliated with or endorsed by Fortinet, Inc.** "Fortinet", "FortiWeb",
> "FortiADC", "FortiAnalyzer" and related marks belong to Fortinet, Inc. and are
> used here only nominatively to describe interoperability. See [NOTICE](NOTICE).
>
> Provided **AS IS, without warranty** (Elastic License 2.0, *No Liability*). You
> are responsible for how you deploy and operate it. See [SECURITY.md](SECURITY.md).

> 📜 **Licensing:** SATOM is **source-available** under the
> [Elastic License 2.0](LICENSE), not an OSI open-source license. You may use,
> modify and run it inside your own organisation — including in production and
> for commercial purposes — at no cost. You may **not** provide it to third
> parties as a hosted or managed service. For a commercial license covering
> that, contact **licensing@visionebc.com**.

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

## Feature catalog

The complete list, grouped by area. Everything below ships in this repository today.

### Policy & WAF management (FortiWeb)
- Server Policy table mirroring the FortiWeb GUI, with an editable detail form and **minimal-diff saves** (only changed fields are written to the device).
- Guided **policy clone / migrate across devices**: pre-flight checklist, dummy-VIP rules, Web Protection Profile handling, reference resolution.
- Safe **cascade delete** with dependency preview before anything is removed.
- Full **Signatures editor** — category view, per-signature details, and per-signature exception management.
- **Guided WAF exceptions** with template locks and lifecycle tracking (detect → inject → review).
- Web Protection area mirroring the FortiWeb 7.6 GUI menu, with 166 curated object kinds ported from the original desktop app.

### Generic object management
- **Spec-driven form engine (`objedit`)** that makes ~500 registry endpoints editable through one engine: stacked slide-over panels, create-references-in-place, sub-tables, and a **dry-run preview on every write**.
- **Endpoint registry in the database** (per product and API version) — when a firmware upgrade moves a REST URI, the operator fixes it from the UI instead of waiting for a code release.
- **Live API consoles** for each product (FortiWeb, FortiADC, FortiAnalyzer) with audited, permission-gated writes.
- Fleet-wide **object search** across every device's cached configuration.
- Naming-convention rules, section catalog / taxonomy, field catalogs, and datasheets.

### Multi-product workspaces (ADOMs)
- Three scoped workspaces — **Global** `/`, **FortiWeb** `/web/`, **FortiADC** `/adc/` — with per-browser-tab product context and strict data scoping.
- **FortiADC**: load-balancer objects, virtual servers, real-server pools, LB lookup, certificate deploy over REST.
- **FortiAnalyzer**: full JSON-RPC integration speaking **both API dialects** (legacy envelope and `apiver: 3`), live menu bound to the endpoint registry, Device Manager (dvmdb) views.

### Device operations
- Discovery / rediscovery and **deep capture** of whole device configurations into a normalized local cache (DB-first reads, refresh-live escape hatch).
- Config **backups over REST with automatic SSH/CLI fallback**, and a restore **vault** (device-level restore is dry-run gated).
- **Firmware upgrade runbooks** and boot-partition management.
- Built-in **SSH console** with read-only command presets.
- Provisioning workflows, hardware inventory, and capacity views.

### Source of truth & backups
- **Git source of truth**: every appliance's config is harvested into versioned JSON (`reports/<device>/_config.json`) — product-aware for FortiWeb, FortiADC, and FortiAnalyzer — refreshed hourly and auto-published to git.
- **System Backup & Restore page**: database bundles (pg_dump), device vault, application-code versions with **one-click code rollback**, and an embedded recovery runbook.
- **Backup coverage matrix**: every backup stream (code, live DB, DB bundles, device SoT, vault, appliance-pushed configs, firmware) with format, destinations, cadence, and a **live state badge**, plus a per-device SoT freshness strip.
- **External backup server integration** (SFTP): inventory of configs the appliances push on their own schedule, with per-device **browse / compare / search / download** modals — including a parser for FortiWeb's multi-file backup container format.
- **Firmware source of truth**: manifest in git, binaries on the backup server, sha256-verified **pull into the console** for restore/upgrade.
- Git drift view for the SoT tree, reports commit history with an **A→B diff viewer**.
- Peer backup inventory over an unauthenticated health probe, so each node renders the other's inventory without SSH.

### High availability
- **Two-node HA**: primary + standby with **PostgreSQL streaming replication** and a role-guarded 5-minute data sync (vault, bundles, runtime data).
- Replication is **TLS-enforced with mutual certificate verification** against an internal CA; plain or cert-less connections are refused.
- Git-driven **reconciler** keeps deployments converged with the repository (manual mode supported).
- Cluster status page and node-to-node **HTTPS probes authenticated with a shared identity key**.

### Security
- Local user management with **two-factor authentication**, directory/LDAP auth, and granular RBAC permissions.
- **Audit log** on every write path; change history preserved.
- **Change Requests**: maintenance-window approval gates for risky operations.
- **Scoped API tokens** for the versioned `/api/v1` (`read ⊂ write ⊂ admin`, owner-capped, product-bound, deliberately read-biased).
- Secrets encrypted at rest (Fernet); nonce-based CSP; rate limiting; object locks.
- **Node TLS manager** in Settings: import a certificate or issue one from the built-in **internal CA**, with automatic nightly renewal and `nginx -t` + auto-rollback on bad imports.
- **PostgreSQL TLS policy** (min protocol / ciphers) tunable from the UI.
- **Encryption-in-transit monitoring**: per-channel cards (app↔app, app↔DB, replication, git) where every badge is backed by a **live probe** — protocol, cipher, enforced, authenticated.

### Automation & self-management
- **Scheduled actions** catalog (cron-style): config syncs, backups, certificate scans, deep captures, nightly device inspections — per-product targeting.
- Background **jobs with pause / resume / stop**.
- **Self-update from the UI**: the web tier only enqueues; a privileged systemd runner performs the update with a per-step log (expandable in the UI) and health verification.
- **Library manager**: PyPI update checks (cached, off the render path) plus per-package **pip upgrade / rollback buttons** — curated allowlist only, import-smoke test, health check, and automatic rollback on failure; `requirements.txt` is bumped and pushed automatically on success.

### Certificates
- Central **Certificate Manager** with issuance via **ADCS or ACME** (switchable).
- Lifecycle policy: revoke-on-supersede, expiry sweeps, SNI policies.
- Private-key upload over SSH and **REST deploy to FortiADC**; certificate inventory and live probes across the fleet.

### Observability & analysis
- Monitoring dashboard, metrics, infrastructure health, and system health/info pages.
- **FortiView traffic analysis** and packet capture.
- **DNS & LB lookup tool**, log collection, flash reports, capacity planning.
- Notifications with e-mail delivery; release-notes tracker; in-app documentation viewer.

### Reporting
- **Report Builder**: no-SQL wizard plus 7 built-in reports.
- Live **ER diagram** of the schema and database introspection views.

### Developer & power tools
- **Lua Studio** and **Regex Lab** with curated example libraries.
- **Plugin system** with a sandboxed runtime and examples.
- API explorer, import-from-backup, structure / segments / classification tooling, baselines, and built-in bug reporting.

### Deployment
- **Interactive Linux installer** — online (any major distro family), or fully **air-gapped offline bundles** per family: Debian 12 (.deb closure) and RHEL/Rocky/Alma 9 (local dnf repository), each with the Python wheels included.
- Installs **standalone or as a 2-node cluster**: the primary generates a join key; the secondary pastes it and replication, shared keys, and its own locally-minted certificate are set up automatically.
- systemd units, nginx TLS front, gunicorn app server, PKI bootstrap — plus a sysadmin manual (`docs/INSTALL.md`) covering requirements, sudo/sudoers, hardening, and uninstall.
- 700+ unit/integration tests.

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
# put the source at /opt/ofortmaut (git clone / tarball)
cd /opt/ofortmaut
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
cd /opt/ofortmaut
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

## Credits

Developed and maintained by **Vision EBC**. Portions of this project were
built with AI-assisted development tooling; all changes are reviewed, tested
(700+ automated tests) and validated on real appliances before release.
