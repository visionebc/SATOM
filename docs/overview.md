# OFortMAuT — Project Overview & Operational Rules

> The web platform for managing **FortiWeb** appliances over their REST API and
> SSH/CLI. This is the authoritative in-app overview: what the app is, where it
> runs, how it's deployed, its security posture, and the rules the team follows
> when operating it.

---

## 1. What it is

A Flask application that administers a fleet of FortiWeb appliances:

- **Server Policy** editor (the listener → pool → WAF binding), **Server
  Objects**, and a full **Web Protection Profile** (WAF) editor mirroring the
  FortiWeb 7.6 GUI.
- **Exceptions & signature carve-outs** authored as desired-state and injected to
  the box on demand.
- **Fleet Map** (network-design diagram), **Architecture**, **Analysis**
  (FortiView + packet capture), **Backups**, **Log Collection**, **Rediscovery**,
  **Policy Inspector**, **Firmware upgrade** runbooks, **Change Requests**, and
  **Scheduled Actions**.
- **Registry**: a versioned catalog of REST endpoints (Postgres-backed) that
  decouples the app from firmware-specific URLs.

It is **DB-first**: pages read a local cache of each device's configuration
(populated by rediscovery / deep capture) so the UI stays fast and usable even
when appliances are slow, unreachable, or license-locked. Live device reads are
the explicit "refresh" escape hatch.

## 2. Architecture

```
Browser ──▶ edge nginx (LXC 241 @ 192.0.2.40)
             └─▶ gunicorn (4 workers × 8 gthread) on 0.0.0.0:8000 inside LXC 248
                  ├─ Flask app (app/) ── PostgreSQL (config, registry, jobs index)
                  ├─ Redis (rate-limit + cache, 127.0.0.1)
                  ├─ httpx  ─▶ FortiWeb REST  (/api/v2.0/…)
                  └─ paramiko ─▶ FortiWeb SSH/CLI (reads + cert key upload)
```

- **Layers:** `views/` (blueprints) → `services/` (business logic) →
  `clients/` (REST/SSH) + `registry/` + `models`. Keep the dependency direction
  acyclic.
- **Background jobs** (`services/jobs.py`): fleet-wide/long operations (backups,
  deep capture, bulk applies, firmware) run as jobs with pause/resume/stop,
  visible in **Global → Jobs**. A boot-time sweep terminates orphaned jobs left
  by a restart.
- **Registry** is the reason the app survives firmware changes: adapting to a new
  firmware is a **data** edit (a registry row), not code.

## 3. Deployment

- **Host:** hypervisor06 (192.0.2.34), **LXC 248**, `/opt/ofortmaut`. Container IP
  `192.0.2.248`. Reach: `ssh root@192.0.2.34 "pct exec 248 -- <cmd>"`.
- **Service:** `systemctl restart ofortmaut.service` after any code or
  template change. A scheduler sidecar (`ofortmaut-scheduler.service`)
  fires scheduled actions.
- **Runs as** the unprivileged `fortinet` user; hardened systemd unit
  (`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`).
- **Config/secrets:** `EnvironmentFile=/opt/ofortmaut/.env` holds
  `SECRET_KEY`, `FERNET_KEY`, the DB URL, `RATELIMIT_STORAGE_URI`,
  `TRUSTED_PROXIES`. `.env` is git-ignored and `root:fortinet 640`.
- **Backups:** nightly `pg_dump` → `/var/backups/fortinet-db` (14-day retention).
- **CI:** `pytest -q` + an offscreen smoke run on push/PR.

## 4. Security posture

- **Auth:** local accounts (scrypt-hashed) via Flask-Login, optional TOTP 2FA and
  LDAP/RADIUS directory auth. Per-account lockout: 10 failed logins → 15-min lock.
- **RBAC:** role/permission model; the whole **Settings** area is admin-only
  (`user_manage`). Write actions require `CONFIG_WRITE` + unlock.
- **CSRF:** Flask-WTF on all forms; the global fetch wrapper injects the token for
  XHR. Self-healing on a stale token.
- **CSP:** nonce-based; `script-src-attr 'none'` (no inline handlers). New inline
  `<script>`/`<style>` **must** carry `nonce="{{ csp_nonce }}"`.
- **Network:** nftables inside the LXC — `:8000` only from the edge (192.0.2.40),
  `:22` from LAN. TLS to appliances is explicit per device (`verify_ssl`).
- **Secrets never touch git or disk in the clear.** Appliance passwords are
  Fernet-encrypted in the DB; the key lives only in `.env` (`FERNET_KEY`). If
  `FERNET_KEY` is unset the app refuses to start rather than silently generating a
  throwaway key that would make every stored credential undecryptable.
- **Production checklist:** rotate the seeded `admin` password on first login;
  keep `FERNET_KEY` backed up (losing it loses every stored device credential).

## 5. Operational rules (the team's conventions)

1. **English-only** user-facing text, comments, and logs.
2. **No secrets on disk or in git** — only the `.env`/keyring holds passwords and
   tokens; the DB stores encrypted credentials, never plaintext.
3. **REST-first; SSH only where the API can't reach** (troubleshooting reads, and
   uploading certificate *key material*, which REST can't carry).
4. **DB-first reads, live is opt-in.** Day-to-day browsing uses the local cache so
   the appliances aren't hammered; "refresh/live" is the explicit escape hatch.
5. **Fleet writes are never blind.** Anything touching many devices goes through a
   preview (dry-run) → canary → apply pipeline as a background job; each write
   snapshots + audits.
6. **Appliances show the hostname only** in lists/combos; host/port/classification
   go to the tooltip.
7. **Every write is audited** — snapshot before, audit row, and before/after
   change history. The device stays the source of truth.
8. **Restart only when required.** A restart is needed for Python/template/env
   changes; data-only or static-asset changes don't need one.
9. **CSP discipline** — no `on*=` inline handlers; nonce every inline
   `<script>`/`<style>`; JS-generated markup emits no handler attributes.

## 6. Where things live (map)

| Concern | Location |
|---|---|
| App factory, security headers, gates | `app/__init__.py` |
| Blueprints (one per feature area) | `app/views/*.py`, `app/api/` |
| Business logic | `app/services/*.py` |
| REST / SSH clients | `app/clients/` |
| Endpoint registry (DB + YAML seed) | `app/registry/`, `endpoints.yaml` |
| Templates / styles | `app/templates/`, `app/static/css/fortiweb.css` |
| Background jobs | `app/services/jobs.py`, Global → Jobs |
| This documentation | `docs/*.md` → the **Documentation** sidebar link |

## 7. Reference docs

The **Documentation** section also carries the deep field-level references:
Server Policy, Web Protection Profile, WPP Exceptions & Signatures, Release Notes,
the Source-of-Truth spec, and the Installation guide. Keep them current in the
same change that alters the behaviour they describe.
