# Technical requirements

> Also in the Documentation Center as `technical-requirements`. Links of the form `[text](slug)` point at Documentation Center articles; `:::` blocks are Documentation Center callouts. When this changes, both copies change in the same round.

This page is the one-stop reference for a new engineer or an evaluating
customer: what SATOM is for, what it does, and what a node needs to run it.
It summarises and links; the linked articles hold the detail. Everything here
describes release **4.12.0**.

---

## Purpose and scope

SATOM (System Automation & Task Orchestration Manager) is a web console that
administers a fleet of Fortinet appliances over their own management
interfaces — REST first, SSH/CLI only where the API cannot reach. It is
built as a Flask application with PostgreSQL behind it.

**SATOM is:**

- a central place to read, change, back up and upgrade appliances, with a
  preview before every write and an audit row after it;
- **DB-first**: pages read a local cache of each device's configuration, so the
  console stays usable when an appliance is slow, unreachable or
  licence-locked. Going live to the device is an explicit action;
- an automation layer (jobs, scheduled actions, change requests, processes)
  and a monitoring layer (metrics, probes, alerting) over the same inventory.

**SATOM is not:**

- a replacement for the appliances: they keep working without it, and the
  device stays the source of truth for its configuration;
- a vendor-site crawler: release notes, upgrade paths and API knowledge for
  builds you do not run arrive as signed packs ([API library](api-library));
- a generic configuration-write API: its own integration API is deliberately
  narrow ([API](api)).

For the architecture behind this, read [Architecture](architecture) and
[System overview](system-overview).

---

## Core capabilities

The permission keys are the granular keys of a profile; see
[Users and profiles](users-and-profiles) and [Permissions](permissions).

| Functional area | Capability | Main permission key(s) | Article |
|---|---|---|---|
| Devices and lifecycle | Inventory, rediscovery, health, configuration backups and restore, firmware upgrade runbooks, provisioning | {{perm:appliances.view}}, {{perm:appliances.edit}}, {{perm:appliances.apply}}, {{perm:backups.view}}, {{perm:backups.create}}, {{perm:backups.restore}}, {{perm:operations.apply}} | [appliances](appliances), [rediscovery](rediscovery), [backups](backups), [firmware-upgrade](firmware-upgrade), [provisioning](provisioning) |
| FortiWeb policies | Server policies, server objects, web protection profiles, exceptions and signatures, templates and fleet objects | {{perm:protection.view}}, {{perm:protection.edit}}, {{perm:protection.apply}}, {{perm:network.view}}, {{perm:network.edit}}, {{perm:network.apply}}, {{perm:operations.template_save}}, {{perm:operations.template_apply}}, {{perm:operations.template_approve}} | [server-policy](server-policy), [server-objects](server-objects), [web-protection](web-protection), [exceptions](exceptions), [template-library](template-library) |
| Other products | FortiADC, FortiAnalyzer, FortiAuthenticator and FortiGate workspaces; the Web Server Manager of the Linux ADOM | {{perm:network.view}}, {{perm:network.edit}}, {{perm:registry.view}}, {{perm:registry.execute_write}}, {{perm:webserver.view}} | [fortiadc](fortiadc), [fortianalyzer](fortianalyzer), [fortiauthenticator](fortiauthenticator), [fortigate](fortigate), [web-server-manager](web-server-manager) |
| Monitoring | Fleet dashboards, metrics collection and the metrics store, probes, alerting, search, reports | {{perm:monitoring.view}} | [monitoring-overview](monitoring-overview), [metrics](metrics), [probes](probes), [alerting](alerting) |
| Automation and change control | Background jobs, scheduled actions, change requests, processes, locks | {{perm:operations.view}}, {{perm:operations.apply}}, {{perm:operations.scripts_run}} | [jobs](jobs), [scheduled-actions](scheduled-actions), [change-requests](change-requests), [process](process), [locks](locks) |
| Tools, Scout, Plugin Studio | Troubleshooting tools, Scout (AI assistant), Plugin Studio apps, Script Library, Python Console, Lua Studio | {{perm:advisor.use}}, {{perm:monitoring.probe_free}}, {{perm:studio.plugin_studio}}, {{perm:studio.script_library}}, {{perm:studio.python_console}}, {{perm:studio.lua_studio}} | [tools-menu](tools-menu), [scout](scout), [plugin-studio-start](plugin-studio-start), [script-library](script-library) |
| Administration | Users and profiles, settings, audit log, node certificates, system backup, software update, high availability | {{perm:users.manage}}, {{perm:profiles.manage}}, {{perm:audit.view}} | [users-and-profiles](users-and-profiles), [settings](settings), [audit-log](audit-log), [system-backup](system-backup), [software-update](software-update), [high-availability](high-availability) |
| API | Token-authenticated integration API at `/api/v1`; the Fortinet endpoint registry and API explorer | {{perm:users.manage}} (tokens), {{perm:registry.view}}, {{perm:registry.edit}}, {{perm:registry.execute_write}} | [api](api), [api-tokens](api-tokens), [api-registry](api-registry) |

Three system profiles ship: **readonly** (every read key), **operator**
(reads plus the day-to-day write keys) and **admin** (every key). Keys marked
admin-only in `app/permissions.py`, such as {{perm:users.manage}} and
{{perm:operations.template_approve}}, are not in the operator profile.

---

## Supported products and firmware

| Product | ADOM | Channel |
|---|---|---|
| FortiWeb | `/web/` | REST, plus SSH/CLI for troubleshooting reads and certificate key upload |
| FortiADC | `/adc/` | REST |
| FortiAuthenticator | `/fac/` | REST (API key); SSH with its own credential when needed |
| FortiAnalyzer | `/faz/` | JSON-RPC |
| FortiGate | `/fgt/` | REST, read live; edits limited to `cmdb` objects, dry run first |

Support is decided **per exact build**, never per API version or firmware line
([Build compatibility](build-compatibility)). Before a template, profile,
baseline or carve-out is written, SATOM checks every field against the target
build and skips, warns or blocks per appliance.

The signed API pack shipped with 4.12.0 carries measured endpoint baselines for
these builds:

| Product | Builds with a measured baseline |
|---|---|
| FortiWeb | 7.6.8, 8.0.5, 8.0.6 |
| FortiADC | 7.6.7, 8.0.3, 8.0.4 |
| FortiAnalyzer | 7.6.7 |
| FortiAuthenticator | 8.0.3 |
| FortiGate | 8.0.1, 8.0.2 |

For a build outside this list, fields with no evidence read **unknown** and are
reported as "cannot be guaranteed", never as ok. A template apply to a build
with no evidence at all is blocked by the template's firmware check. Newer
knowledge packs and rediscovery of a real appliance fill the gaps.

---

## Platform requirements

### Operating system and install shapes

| Shape | Supported targets | Notes |
|---|---|---|
| Native, online | Debian 12 (reference), RHEL/Rocky/Alma 9, openSUSE Leap 15 / SLES 15, Arch | `install-satom.sh`; needs HTTPS egress to the distribution mirrors, PyPI and the code repository |
| Native, offline bundle | Debian 12, RHEL/Rocky/Alma 9, openSUSE Leap 15 / SLES 15 | One bundle per distribution family; no Internet egress. Arch has no offline bundle |
| Guided | Debian 12/13, Ubuntu 22.04/24.04, RHEL/Rocky/Alma 9, openSUSE Leap/SLES 15 | `satom-setup.sh` checks the machine, then runs the native or Docker install |
| Docker | A container host | One stack: application, PostgreSQL, Redis, metrics store and an nginx proxy |

Every native install needs **systemd as PID 1** (Alpine/musl is not supported),
amd64/x86_64, and an account with `sudo` scoped to the installer for the
install window. Run `sudo bash install-satom.sh --preflight` to check a machine
without changing it. Full procedure: [Installation](installation).

### Runtime stack

| Component | Native install | Docker stack |
|---|---|---|
| Python | ≥ 3.10 in its own venv (`python3.11` on EL9 and SUSE) | 3.11 |
| Flask / Werkzeug | Flask 3.1.3, Werkzeug 3.1.9 (pinned in `requirements.txt`) | same image |
| SQLAlchemy / psycopg | SQLAlchemy 2.1.5, psycopg 3.3.6 | same image |
| Application server | gunicorn 26.2.0: 4 workers × 8 threads, bound to `127.0.0.1:8000` | same |
| Database | the distribution's PostgreSQL package | PostgreSQL 15 (or an existing external server) |
| Metrics store | VictoriaMetrics 1.148.0 (single node, sha256-verified), `127.0.0.1:8428`, 396-day retention | VictoriaMetrics 1.148.0 |
| Reverse proxy / TLS | the distribution's nginx | nginx 1.27 |
| Rate-limit storage | in-process (`memory://`) unless `RATELIMIT_STORAGE_URI` points at Redis | Redis 7 |
| Sandbox | `bubblewrap` — the code tools refuse to run without it | in the image |

The installer also installs `rsync`, `openssl`, `ca-certificates`, `curl`,
`sudo` and `git` (online), and `openssh` in cluster mode only. It compiles
nothing and uses only the distribution's official repositories.

### Browser

The console needs a current browser and **no Internet access from it**: every
script, stylesheet and font (Bootstrap, Bootstrap Icons, Chart.js) is vendored
and served by the node, and the Content-Security-Policy names no other origin.

---

## Sizing

The installer's floor is **2 vCPU, 2 GB RAM, 15 GB disk**. That is what the
installer needs to finish, not a recommendation. Size for the fleet:

| Tier | Devices | Policies per device | vCPU | RAM | Disk |
|---|---|---|---|---|---|
| Lab / PoC | ≤ 10 | ≤ 100 | 2 | 4 GB | 20 GB |
| Small | ≤ 25 | ≤ 250 | 4 | 4 GB | 30 GB |
| Medium | ≤ 60 | ≤ 250 | 4 | 8 GB | 40 GB |
| Large | ≤ 110 | ≤ 750 | 8 | 8 GB | 120 GB |

- The binding constraint is device I/O inside the 3-minute collection window.
  Past about 110 devices, split the fleet across independent installations
  instead of growing the node.
- Disk grows with devices × policies, not with device count alone.
- Keep `max(15 % of the volume, 3 GB)` free. PostgreSQL stops when it cannot
  write a checkpoint, and `/healthz` keeps answering 200 while it does. Watch
  free space from outside the node.

Details and the formulas: [Installation — Sizing](installation#sizing).

---

## Network requirements

| Port | Direction | Purpose | Required |
|---|---|---|---|
| Console port (default 443/tcp) | browser → node | HTTPS web console and `/api/v1` | always |
| 80/tcp | browser (and a public ACME CA) → node | redirect to HTTPS; `/.well-known/acme-challenge/` | always (fixed port) |
| Appliance port (default 443/tcp, per device) | node → appliance | management REST / JSON-RPC | always |
| Appliance SSH (default 22/tcp, per device) | node → appliance | CLI reads, certificate key upload, CLI writer | where used |
| 8443/tcp | node ↔ node | health and status probes: TLS plus HMAC-signed requests | cluster only (fixed port) |
| 5432/tcp | standby → primary | PostgreSQL streaming replication, TLS with `verify-ca` | cluster only |
| 22/tcp | standby → primary | rsync of `data/` over SSH, read-only, restricted key | cluster only |
| HTTPS egress | node → Internet | install (mirrors, PyPI, repository), update feed, knowledge feed, PyPI for library updates | online mode only |

gunicorn (`127.0.0.1:8000`) and the metrics store (`127.0.0.1:8428`) listen on
loopback only. Optional outbound connections follow your settings: directory
servers ([Authentication](settings-authentication)), the mail server for
alerts and external AI providers for Scout.

:::note Isolated networks
A node with no Internet egress installs from an offline bundle and updates
from a signed offline update package uploaded through Software Update. Knowledge
packs are uploaded the same way. See [Offline updates](offline-updates).
:::

Both cluster nodes must be NTP-synchronised. A peer request whose signature
timestamp is more than 120 seconds off is refused.

---

## Security requirements

| Area | Requirement as shipped |
|---|---|
| Transport | nginx terminates TLS 1.2/1.3; plain HTTP answers `301` to HTTPS. The install issues a certificate from a per-node internal CA; replace it with your own or use ACME ([Node TLS](node-tls)) |
| Appliance TLS | Verified by default against the trust store; turned off only per device, explicitly ([Trust store](trust-store)) |
| Authentication | Local accounts (scrypt), optional TOTP 2FA, LDAP/AD/RADIUS. 10 consecutive failures lock an account for 15 minutes. Passwords are 12–1024 characters |
| Authorisation | RBAC on the route, not only in the template: a missing key returns 403 |
| Session | Cookie `Secure`, `HttpOnly`, `SameSite=Lax`; idle session lock (default 60 minutes) |
| Browser headers | Nonce-based CSP with `script-src-attr 'none'` (no inline handlers), HSTS, `X-Frame-Options: DENY` (same-origin frames only where SATOM embeds itself), `nosniff`, CSRF tokens on every form |
| Secrets | Appliance credentials Fernet-encrypted in the database; `SECRET_KEY`, `FERNET_KEY` and the DB password only in the environment file (`root:satom 0640`). Losing `FERNET_KEY` loses every stored credential: back it up |
| Privilege | The application runs as an unprivileged, shell-less service account. Its `sudo` allowlist is `nginx -t` and `systemctl reload nginx`. Privileged work goes through one root runner (`satom-updater.service`) that validates its input |
| Code tools | Operator-supplied Python (Script Library runs, integration hooks, the Python Console) runs in a bubblewrap jail with no access to the application tree or the database socket |
| Audit | Every write snapshots first, writes an audit row and records the before and after state ([Audit log](audit-log)) |

Read [Security model](security-model) for the full model and
[Safeguards](safeguards) for every guard, with how to verify it is armed.

---

## Availability

Production can run as a **primary/standby pair**
([High availability](high-availability)):

| What | How it reaches the standby |
|---|---|
| Database (settings, users, devices, everything in PostgreSQL) | PostgreSQL streaming replication, continuous |
| Files under `data/` (bundles, configuration vault, source-of-truth store) | the standby pulls them with rsync over SSH every 5 minutes |
| Application code | Software Update on each node, standby first |
| Metrics store | **not replicated**: each node keeps its own |

- The standby's scheduler stays on hold, so two nodes never fire the same
  scheduled action.
- **Failover is manual.** An administrator promotes the standby from the High
  Availability page, confirming the node's hostname.
- The standby protects against the loss of the primary. It does not add
  capacity. To manage more devices, split the fleet ([Sizing](#sizing)).

A single node is protected by the nightly system backup
([System backup](system-backup)).

---

## Non-functional rules

These are the product rules every feature is held to
([Product rules](product-rules)):

:::cards
::card Six-step device writes | writes
Pre-check, versioned backup, dry-run diff, minimal change in dependency order,
post-check by re-reading the object, compensation or restore. A second run
makes zero changes.
::card HTTP 200 is not success | correctness
SATOM reads the response body. A licence error or rejected read returned with
a 200 is shown as **ERROR**, never as empty or ok.
::card Cache first, device last | load
Browsing reads the stored cache. Reaching the appliance is an explicit job that
the operator can see.
::card Every field is visible | completeness
Fields the vendor GUI hides appear under **Not in GUI, but in CLI** with their
channel ([Not in GUI](not-in-gui)).
::card Light UI only | look
There is no dark mode. Only the navigation chrome and code blocks are dark
([Design system](design-system)).
::card English is the source language | language
Everything shipped is written in English. The console offers German, Spanish,
French and Italian translations ([Languages](settings-languages)).
:::

---

## Out of scope and known limits

- **Container installs** disable five host-only actions: Software Update,
  HA promotion, service control, certificate activation and systemd unit
  health. The optional operations agent brings back four of them. HA
  promotion stays a manual PostgreSQL procedure.
- **No automatic failover** between SATOM nodes.
- **One node collects about 110 devices** in its 3-minute window. Larger fleets
  need several independent installations.
- **The integration API** cannot upgrade, flash or reboot an appliance, run an
  action flagged destructive, or write arbitrary configuration.
- **Template rollout** targets FortiWeb appliances only
  (`template_apply.SUPPORTED_KINDS`).
- **The FortiGate API console** writes to `/api/v2/cmdb/` only, and is
  dry-run by default.
- **Alpine/musl** is not supported, and **Arch** has no offline bundle.
- **The node serves no manual.** The published copy is this site. On an
  isolated node, read the bundled manuals with `satom show docs`.
- **`/healthz` answering 200** does not prove the database is healthy. Monitor
  disk space and PostgreSQL from outside the node.
