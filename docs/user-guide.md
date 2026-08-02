# SATOM — User Guide

> **Audience:** operators and network/security engineers who use the web UI to
> manage FortiWeb and FortiADC appliances day to day. No knowledge of the
> codebase is assumed. For architecture and internals see the
> [Engineering Manual](engineering.md); for a non-technical summary see the
> [Management Overview](management-overview.md).

---

## Table of contents

1. [Signing in & accounts](#1-signing-in--accounts)
2. [Core concepts](#2-core-concepts)
3. [Products (ADOMs): Global, FortiWeb, FortiADC](#3-products-adoms)
4. [Registering and operating devices](#4-registering-and-operating-devices)
5. [Server Policy](#5-server-policy)
6. [Cloning & migrating policies](#6-cloning--migrating-policies)
7. [Server Objects & the generic object editor](#7-server-objects--the-generic-object-editor)
8. [Web Protection (WAF)](#8-web-protection-waf)
9. [Exceptions & signature carve-outs](#9-exceptions--signature-carve-outs)
10. [Certificate Manager](#10-certificate-manager)
11. [Backups & restore](#11-backups--restore)
12. [Firmware upgrades](#12-firmware-upgrades)
13. [Fleet tools](#13-fleet-tools)
14. [Monitoring: fleet health, metrics & probes](#14-monitoring-fleet-health-metrics--probes)
15. [Automation: scheduled actions, change requests, jobs](#15-automation)
16. [Reports & database tools](#16-reports--database-tools)
17. [The FortiADC workspace](#17-the-fortiadc-workspace)
18. [API tokens](#18-api-tokens)
19. [Appearance: logo, colours & themes](#19-appearance-logo-colours--themes)
20. [The operator console](#20-the-operator-console)
21. [Troubleshooting](#21-troubleshooting)

---

## 1. Signing in & accounts

- Browse to the app URL and log in. A fresh install ships one seeded
  administrator (`admin` / `Sopas123.-`) — **change this password on first
  login** (Profile → password).
- **Account protection:** 10 consecutive failed logins lock the account for
  15 minutes. Login attempts are rate-limited per IP (5/min).
- **2FA:** TOTP can be enabled per account (QR enrollment in the profile).
- **Directory auth:** LDAP and RADIUS backends can be configured by an admin,
  in addition to local accounts.
- **Roles.** Three effective profiles gate what you can do:
  - *readonly* — see everything, change nothing;
  - *operator* — day-to-day changes (`config_write`): policies, objects,
    exceptions, backups;
  - *admin* (`user_manage`) — everything, including Settings, users, registry,
    templates, scheduled actions, and the Database section.
- Every write you make is recorded in the **Audit Log** with before/after
  change history.

## 2. Core concepts

**DB-first pages.** The app keeps a local, queryable copy of each device's
whole configuration (populated by *Rediscovery* and *Deep Capture*). Pages
render from that cache in milliseconds and show a freshness badge like
`DB · 2h ago`. This means:

- the UI works even when a device is **down, slow, or license-locked**;
- what you see can be *behind* the box — press the **refresh/live** control
  (⟳ / "refresh from device") when you need the current truth;
- after you save a change through the app, the affected page re-reads live, so
  your own edits are never stale.

**Dry-run first.** Every write to a device shows a **preview** (exactly what
will be PUT/POSTed) before you apply. Nothing touches an appliance until you
explicitly confirm. Applied writes are snapshotted and audited.

**Jobs dock.** Long operations (backups, discovery, deep captures, bulk
applies, firmware) run as **background jobs**. A dock at the bottom of the
screen tracks progress and survives page navigation; the **Jobs** page (Global
→ Jobs) lists everything with Pause / Resume / Stop.

**Notifications.** The bell in the top bar collects job results and system
notices, scoped to the product you are working in.

## 3. Products (ADOMs)

The app hosts three workspaces, in the style of FortiManager ADOMs:

| ADOM | URL | Purpose |
|---|---|---|
| **Global** | `/` | Fleet-wide dashboard and cross-product tools: Monitoring, Search, Architecture, Analysis, Fleet Objects, Metrics, Jobs, Certificate Manager, DNS Lookup, plus fleet administration (Classification, Database, System Backup, Software Update, Bug Reports) |
| **FortiWeb** | `/web/` | Everything WAF: Server Policy, Server Objects, Web Protection, Exceptions, Configuration sections, Operations, FortiWeb administration |
| **FortiADC** | `/adc/` | Load-balancer management: the FortiADC 8.0 GUI menu (Server LB, Link LB, Global LB, WAF, Network…), signatures, and an ADC API console |

Switch ADOMs from the product selector or the `‹ Global` link at the top of
each sidebar. **The ADOM is per browser tab** — you can keep FortiWeb open in
one tab and FortiADC in another; switching in one tab never changes the other.
Data is strictly scoped: a FortiADC session sees only FortiADC jobs,
notifications, templates and appliances (and vice versa); Global sees all.

## 4. Registering and operating devices

**Appliances** (Administrator → Appliances, or Global dashboard):

1. **Add appliance** — name, host/IP, port, kind (fortiweb / fortiadc),
   credentials (stored encrypted), TLS verification mode.
2. **Test connection** — validates REST reachability and credentials.
3. **Discovery / Rediscovery** — sweeps every registry endpoint and stores the
   device's full configuration in the local cache; also fills the hardware /
   firmware inventory. Run it after registering and after any large
   out-of-band change.
4. **Deep capture** — a deeper sweep that walks each server policy's whole
   object graph (pools, members, WAF profile sub-policies…). This is what
   powers the DB-first policy detail and the Architecture map. Can run
   fleet-wide and is normally scheduled nightly.

Each appliance's detail page is the hub for device-level actions:

- **VS/Policy Inspector** — a tree report of each policy and everything it
  references.
- **SSH Console** — read-only troubleshooting presets (`get system status`,
  HA status, routing table, sniffer…) plus a command box. Destructive CLI is
  not offered.
- **Backups / Restore / Upgrade / Boot partition** — see §11–§12.
- **Sync devices** — the fleet list can be shared/re-imported so a fresh
  install inherits the same inventory.

**Capacity limits** (Administrator → Capacity) define per-model object
ceilings; clone and exception workflows check headroom before creating
objects.

## 5. Server Policy

FortiWeb ADOM → **Server Policy** (the landing page once a device is chosen).

- The policy table mirrors the FortiWeb GUI: Name, Deployment Mode, Virtual
  Server, Server Pool, Web Protection Profile, Monitor Mode, Status.
- Click a policy for the **detail view** — rendered from the deep cache,
  including the resolved service topology: VIP + port → virtual server → pool
  → real servers (with live backend health probe when requested).
- **Edit** opens the FortiWeb-style form: the same sections as the appliance
  GUI, dropdowns populated with the device's own objects, and a **＋** next to
  creatable references (build a new pool / health check / SNI policy inline
  without leaving the form).
- Saves are **minimal-diff**: only the fields you actually changed travel to
  the device, computed against the same baseline you saw. You always get a
  dry-run preview first.
- **Delete** runs a safe cascade: the policy plus only the objects *nothing
  else uses*; shared building blocks are kept and reported.
- **⏰ Schedule** lets an operator schedule a policy enable/disable, a backend
  enable/disable, or a certificate swap for a specific date/time (see §15).

## 6. Cloning & migrating policies

From the Server Policy list, **Clone / Migrate** recreates a whole policy tree
(virtual server, VIP, pool + members, health checks, content routing, and
optionally the full WAF profile) on the same or another FortiWeb.

What the guided dialog does for you:

- **Pre-flight checklist** (runs automatically): source readable, destination
  reachable, name collisions, WAF profile present/identical/different on the
  destination, VIP IP conflicts, certificate warnings (key material can only
  move over SSH), and capacity headroom. Blocking findings disable Apply.
- **Dummy VIP rules:** cloned VIPs are rewritten to a placeholder IP so a
  clone can never take real traffic by accident. Admins configure the rewrite
  rules (e.g. `10.x → 240.x`) in Settings → Clone/Migrate; single clones can
  override the suggested IP, bulk clones always use the rules.
- **WAF profile choice:** if the destination already has a *different* profile
  with the same name, you choose — use the destination's, or copy the source
  profile under a new name.
- Objects that already exist on the destination are **validated and skipped**,
  never overwritten. The clone lands **disabled** for a manual cutover.

## 7. Server Objects & the generic object editor

FortiWeb ADOM → **Server Objects** mirrors the appliance's Server Objects
menu (Server, Service, SSL, Protected Hostnames, Lists, Global, Certificates).
Any object opens in the **generic object editor** (`objedit`), which is also
used by the Configuration sections and the WAF area:

- Fields render like the FortiWeb GUI: curated labels, enums with GUI names,
  toggles, reference dropdowns; anything uncurated still shows with a raw-JSON
  escape hatch, so nothing is uneditable.
- **Sub-tables** (pool members, VIP lists, host lists, match conditions…) are
  edited in place, several levels deep.
- Editing a referenced object opens a **slide-over panel** stacked to the
  right — exactly like FortiWeb drops in a sub-page — and every reference
  dropdown has **✎** (edit selected) and **＋** (create new in place).
- If the device is unreachable, the editor renders from the **local cache**
  with an info banner; fields stay editable and Save still targets the device.
- Every save previews as a dry-run diff before applying.

## 8. Web Protection (WAF)

FortiWeb ADOM → **Web Protection** reproduces the FortiWeb 7.6 Web Protection
menu tree exactly: Known Attacks (Signatures / Custom Signature), Protocol,
Access, Input Validation, Cookie Security, Advanced Protection, Data Loss
Prevention — plus the profile itself under Policy → Web Protection Profile
(Inline / Offline tabs).

- **Signatures editor:** browse signature categories, search the full
  signature catalog (2,400+ signatures by name/class/state), open any
  signature's details, disable it, set alert-only, or add a **per-signature
  exception** — with the same element-type-gated form as the appliance GUI.
- **166 curated object kinds** (ported from the desktop manager and validated
  against the vendor admin guide) drive the forms: correct enums, field
  gating, inline help ("what does this do", "how the backend reacts"), and an
  explanation under every Action dropdown.
- **Regex Lab:** every regex-capable field has a `.*` button that opens a
  server-side regex tester with curated examples per section; the tested
  pattern writes back into the field.
- Profile-level editing shows each sub-policy as a dropdown with Edit/＋,
  down to six levels of nesting.

## 9. Exceptions & signature carve-outs

FortiWeb ADOM → **Exceptions** is the single place for every policy-bound
carve-out (WAF exceptions *and* signature customizations). The team rules the
app enforces:

1. **Templates stay clean.** A template-managed WAF profile cannot receive
   exceptions — the app blocks the save and offers the fix.
2. **Guided clone.** When you try to except a locked/shared profile, the app
   proposes cloning it for that specific server policy (name suggested by the
   Naming catalog), re-binds the policy to the clone, moves the carve-outs,
   and re-submits your change — one flow.
3. **Lifecycle.** Exceptions are bound to server policies. Deleting a policy
   purges its carve-outs; swapping a policy's WAF profile flags them **STALE**
   (never silently deleted) with a banner to re-target.
4. **Capacity.** Injections check device limits (e.g. 128 filter entries per
   signature set) and clone operations check profile headroom.

Other tools on the page:

- **⬆ Inject to device** — push authored exceptions onto the box: pick the
  live target object, review the dry-run plan, apply.
- **🔎 Detect on device** — read the exceptions that already exist on a box
  and import them as desired-state, bound to the right policy.
- **Alignment report** — device → policy → profile → exceptions, with stale
  detection; exportable.

## 10. Certificate Manager

Global ADOM → **Certificate Manager** (product-scoped: in the FortiWeb ADOM
you see FortiWeb material, in ADC the ADC material).

- **Inventory & scan:** sweeps each device's certificate stores (FortiWeb via
  REST/SSH, FortiADC via REST), parses X.509 (CN, SANs, issuer, validity) and
  maps **bindings** — which policies / SSL profiles / admin GUI actually use
  each certificate. Removal is fail-closed: a bound or unverifiable
  certificate is refused.
- **Issuance:** create a CSR and sign it through the configured protocol —
  **Microsoft ADCS** or **ACME** (Let's Encrypt-style, http-01/dns-01) — the
  protocol is a Settings dropdown, not a code change.
- **Deploy:** FortiWeb receives cert+key over SSH (the only transport the
  appliance supports for key material); FortiADC over REST. The Admin GUI
  certificate can be swapped with a dry-run preview.
- **Lifecycle policy:** configurable rules — revoke superseded certs after a
  grace period, clean up expired/revoked material from devices, auto-apply or
  report-only. A **Run sweep now** button and a nightly scheduled action keep
  it moving; the page lists everything currently due.

## 11. Backups & restore

- **Device Backups** (FortiWeb ADOM → Operations) is the config-backup
  **vault**: every backup row shows filename, date, size, source
  (device/upload), firmware and author.
  - *Create Backup* offers a transport selector: **Auto** (REST first, SSH
    fallback), **REST only**, or **SSH only** (`show full-configuration`).
    Unlicensed/locked devices are still backed up via SSH.
  - Upload `.conf` files by hand, download or delete rows at will.
- **Restore** (appliance detail): pick a vault row and apply (FortiWeb; a
  pre-restore safety backup is taken first). For FortiADC the vault works
  (pull/upload/download) but config *apply* has no REST transport — the page
  says so honestly.
- **System Backup & Restore** (Global → Administrator) backs up the **manager
  itself**: a `pg_dump` of the database plus the reports tree in one bundle,
  with a verified restore path.
- Pre-upgrade/downgrade backups land in the same vault automatically.

## 12. Firmware upgrades

Appliance detail → **Upgrade** (FortiWeb):

1. Upload the `.out` image (or pick a previously uploaded one).
2. The runbook takes a **mandatory config backup**, probes every published
   service *before*, pushes the image, monitors the reboot/recovery, probes
   *after*, and produces a before/after diff plus a status page.
3. **Release-notes advisory:** the app maintains a harvested corpus of vendor
   known/resolved issues; the advisor diffs *current → target* so you see what
   the upgrade fixes and what it inherits.
4. Unattended (scheduled) upgrades only ever run inside an **approved Change
   Request window** (§15) — there is no way to schedule a flash without an
   approval.
5. **Boot partition** management (view/boot the alternate partition) is a
   separate, gated page.

## 13. Fleet tools

All in the Global ADOM (also linked from product Fleet groups):

- **Architecture** — an SVG network-design diagram of the whole fleet:
  Internet → published services (VIP:port, TLS lock) → appliance chassis →
  pools → backend stacks, grouped in zones. Hover lights up a service's full
  path; search (IP/device/policy/profile/pool) focuses the view; click any
  node for the full cached detail with deep links into configuration.
  Filters: zone / line / department / kind / firmware / protocol / WAF /
  policy state — saved per user.
- **Search** — fleet-wide full-text search over the cached configs and policy
  reports (names, VIPs, backend IPs, certificates, comments…).
- **Fleet Objects** — typed, cross-device object listings (server policies,
  WAF profiles, pools…) with filters and CSV export, plus a generic
  any-field search over the entire cache.
- **Analysis** — FortiView traffic/sources per device with filtering, and an
  assisted **packet capture** builder that runs the appliance sniffer over
  SSH and hands you a Wireshark bundle (`.pcap` + TLS key log for decryption).
- **DNS & LB Lookup** — resolve any name against your configured DNS servers
  (AdGuard/OPNsense/etc., admin-configurable list) and simultaneously match it
  against the fleet's load-balancing config: which policy/virtual server
  publishes it, with a mini policy→pool→backend graph and config deep links.
- **Monitoring / Metrics** — see §14.

## 14. Monitoring: fleet health, metrics & probes

Monitoring lives in **every** workspace, not only Global. It is scoped by
device kind, so the FortiWeb workspace shows FortiWeb appliances and nothing
about the manager itself. Three submenus, and they answer three different
questions.

### 14.1 Fleet health — *is the box alive?*

One card per appliance. The badge is the **worst of four independent signals**,
and every signal that is not healthy is printed underneath, so a state is never
unexplained:

| Signal | Warns | Critical |
|---|---|---|
| **Harvest** — the last scheduled config syncs | one failed run | three failed runs in a row |
| **Cache** — the newest stored snapshot | nothing cached, or older than `monitoring.stale_hours` (6 h) | older than 4× that |
| **Probes** — the enabled monitors for that device | a probe alerting, or *all* probes disabled | a probe critical |
| **Capacity** — object-count headroom against the admin cap | over `capacity.warn_pct` | over `capacity.crit_pct` |

Two rules matter when reading it:

- **`unknown` is not `ok`.** A device nothing has been measured about renders
  *unknown*, never *healthy*.
- **A disabled probe is not a passing probe.** Switching off a monitor that
  always fails removes coverage, and the card says so rather than turning green.

Appliances in **maintenance** are marked as such and are skipped by automatic
runs and by their alerts. That is the correct way to silence a box you know is
down — not lowering the alert floor.

In the Global workspace the same page also carries **Infrastructure health**
(cluster peers, repository, external backup server, database, systemd units,
redundancy) and **Encryption in transit**, where every badge is backed by a
live probe rather than by configuration. Those sections are absent from a
product workspace by design.

### 14.2 Metrics — *how much does it hold?*

Inventory counts, audit activity and change history for the active workspace,
plus daily series where the product supports them. Nothing here touches an
appliance.

### 14.3 Deep monitors — *is the service still serving?*

`Monitoring → Deep monitors`. These reach into the appliance (synthetic request
or read-only CLI over SSH):

| Kind | What it records |
|---|---|
| **Service policy (HTTPS)** | A synthetic request to a published front end: status, latency and days of certificate left. One 200 proves interface, policy, proxy daemon and backend at once |
| **Interface IP / link** | A name → address/state fingerprint per port. The **drift** against the previous sample is the event; an address change grades critical |
| **Processor load** / **Memory usage** | Read from the appliance's own performance summary |
| **proxyd process** | Worker count, memory used and free, and the **set of process IDs** — a different PID is a silent restart, which no ordinary health check shows |

### 14.4 Service monitor — telemetry over the API

`Monitoring → Service monitor`. Same engine, no shell access — these read the
appliance's monitoring API only, which means they keep working on a device
whose configuration API is refusing calls (an expired licence, typically):

| Kind | Unit |
|---|---|
| **Concurrent sessions (box)** | sessions, plus connections per second |
| **Server-policy sessions & latency** | sessions, round-trip and application response time, per-member backend health |
| **HTTP throughput** | Mbps, graded on the **peak** of the window, not the average |
| **HTTP transactions** | transactions per bucket |

The page also groups results per device: a traffic card per appliance and a
per-policy detail view, both served from stored samples.

> **Reading `sessions` on short-lived HTTP.** Connections per second is the
> number that moves; concurrent sessions can sit near zero under heavy load
> because each request lives microseconds. A threshold on `policy_sessions`
> grades *sessions* — for HTTP front ends, watch the throughput probe instead.

### 14.5 Creating probes

- **Discover from device** offers four sets: published policies, a baseline,
  one probe per interface, or the API telemetry set. Ports are picked from the
  cached configuration, so the dialog opens with the appliance switched off.
- **Interval must be a multiple of the sweep** (3 minutes). A probe only fires
  when its own interval has elapsed *and* a sweep tick happens, so a 5-minute
  probe under a 3-minute sweep would really run every 6 minutes.
- **Probe now** runs the current page's probes for the visible devices. It runs
  in the background and stays out of the progress dock — only a sweep that
  *fails* raises a notification.
- Editing a probe is the pencil icon in the table.

### 14.6 History and charts

Click any sparkline for the drill-down: 1 h / 24 h / 7 d / 30 d or a custom
range, with minimum / average / maximum, a healthy percentage, sample and
transition counts, threshold lines and a per-bucket status strip.

Raw samples are capped per probe (`retention`, ~2 days at the default). Charts
go further because every run also writes roll-ups: **hourly kept 90 days,
daily kept two years**, storing min/avg/max rather than a mean — a four-minute
spike is invisible in an average and is usually the reason the chart is open.
The footer states which table was drawn, because an hourly mean and a
three-minute reading are not the same claim about the appliance.

> **Changing a probe's unit resets its series.** If a probe starts reporting a
> different quantity, its old samples are cleared rather than plotted on the
> same axis. That is a deliberate, manual operation — never a side effect of a
> restart.

## 15. Automation

**Scheduled Actions** (FortiWeb ADOM → Administrator, plus the ⏰ button on
Server Policy for operators):

- Admin catalog: device backup, log collection, rediscovery, policy
  inspector, signature sync, release-notes scan, statistics, git sync,
  cert scan, cert lifecycle sweep, device sync, deep capture, upgrade-prep,
  and the full **upgrade**.
- User catalog (single-target, date-driven): enable/disable a policy,
  enable/disable a pool member, swap a certificate.
- Schedules: interval / daily / weekly / monthly / once, with catch-up
  semantics and a run history per action. A dedicated scheduler sidecar fires
  them; **Run now** is always available.

**Change Requests** (maintenance windows):

- A CR captures the window, affected devices **and the server policies whose
  clients must be warned** (auto-listed from the cache), the action (e.g.
  firmware image), risk/rollback notes, and an approval trail.
- Workflow: draft → notify (rendered client notice) → **approve** → schedule
  → in-progress → completed/failed, each step time-stamped in a timeline.
- The scheduled upgrade bound to a CR **refuses to run** outside its approved
  window.

**Jobs** (Global → Jobs): every background job with owner, host/PID, progress
and duration; Pause / Resume / Stop (cooperative — jobs park at safe
checkpoints); orphaned jobs from a service restart are swept and marked on
boot.

## 16. Reports & database tools

Global → Administrator → **Database** (admin only):

- **Reports** — 7 built-in reports (policies by device, expiring
  certificates, carve-outs by policy, audit activity, fleet inventory,
  backups, scheduled-action failures) plus a **4-step no-SQL Query Builder**
  (pick a base table by domain → related tables via foreign keys → columns
  and filters with value dropdowns → grouping/ordering). Built-ins are
  read-only; **Clone** one to customize. Direct SQL is available too, but
  strictly read-only and validated.
- **ER diagram** — a live, professional database diagram (crow's-foot
  notation, domain-colored, searchable, draggable, exportable SVG).
- **Tables browser + SQL console** — read-only introspection with sensitive
  columns masked.

## 17. The FortiADC workspace

The `/adc/` ADOM mirrors the FortiADC 8.0 GUI menu: Server Load Balance, Link
Load Balance, Global Load Balance, Web Application Firewall, Network Security,
Network, Shared Resources, User Authentication, System, Log & Report.

- Object pages use the same form engine: identity/mkey handling, child tables
  (e.g. pool members) derived automatically, dry-run previews, audit on
  apply.
- **Signatures** — WAF signature category/severity overview with per-severity
  actions; deep editing through the object detail.
- **API console** (bottom nav → API) — the registry-driven explorer: browse
  the ADC endpoint catalog as the GUI menu, run live GETs and gated writes
  against a chosen device, with history and syntax-highlighted responses.
- Device actions at parity where the platform allows: test connection,
  VS inspector, discovery, SSH console with ADC presets, upgrade-prep health
  battery, SSH config backups. (Firmware flash / restore-apply have **no REST
  transport on FortiADC** — the UI states this rather than pretending.)

## 18. API tokens

Administrators issue bearer tokens (API Tokens section) for the `/api/v1`
integration surface. Scope model: `read ⊂ write ⊂ admin`, capped by the
owner's own role, bound to one product (ADOM). The plaintext token is shown
**once** at creation. The API is read-biased: mutations happen only by
triggering pre-created scheduled actions; nothing destructive is reachable by
any token. Full reference: [docs/api_v1.md](api_v1.md).

## 19. Appearance: logo, colours & themes

`Settings → Appearance` (administrators). Four palettes ship — **SATOM Aurora**
(the default), **Slate**, **Graphite** and the original **Classic** — and you
can create your own.

**What you edit is a list of 34 design tokens**, grouped by sidebar, top bar,
surfaces, accent, brand ramps and glow, text, status, elevation, layout and
typography. You never edit CSS: free-form style text in a themed page is a
stored-injection hole, so every value is validated by kind and the gradients
are parsed structurally.

Practical notes:

- **A theme stores only what it changes.** Anything you leave alone keeps
  following the shipped stylesheet, so a later improvement still reaches you.
- **Contrast is audited as you save.** Each text/background pair is scored;
  below the legibility floor the save asks for an explicit *apply anyway*.
- **Logo and favicon** uploaded here live in the replicated data directory, so
  they survive a rebuild and reach the standby node. (The per-workspace product
  marks are a different, node-local setting.)
- **Built-ins cannot be edited or deleted**, and deleting the active theme
  falls back to the built-in rather than leaving the console unthemed.
- **If you lock yourself out** with two dark colours: *Revert to the shipped
  look* on this page, activate any built-in, or from a shell on the node run
  `satom execute reset theme`.
- **There is no dark console.** Roughly a hundred and forty status tints are
  still literal values in the stylesheet, so a dark canvas would leave islands
  of light. The public documentation site does offer one.

Full reference: [docs/theming.md](theming.md).

## 20. The operator console

Some failures cannot be fixed from the web interface, because the web interface
is the thing that failed. Every node ships a local command-line tool, `satom`,
with **96 commands** across four verbs — `get` (state), `show` (reference),
`diagnose` (checks) and `execute` (actions).

The three you will use most:

```bash
satom diagnose all        # 24 checks, one exit code
satom diagnose install    # infrastructure vs. protections — what is not armed
satom show docs           # print any manual, no network needed
```

Read verbs work as any user; state-changing verbs require root and refuse with
an explanation rather than a traceback. Ask your systems team for the operator
rule the tool prints itself:

```bash
satom show sudoers <account>   # prints the sudoers line; changes nothing
```

Full reference, including the complete command tree and the runbooks:
[docs/cli.md](cli.md).

## 21. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Page shows a red *device error -20010: license not valid* banner | The appliance's (trial) license is expired/flapping. The UI keeps working from cache; SSH-based features (backups, console) still work. Fix the license, then Refresh. |
| Object editor opens with a blue *Showing locally cached data* banner | The live read failed (device down, TLS mismatch, license). Fields are editable; Save still goes to the device. |
| A policy/profile detail says *no deep capture* | Run Deep Capture for that device (appliance detail or Scheduled Actions). |
| "Add row" form shows no fields | The cache has no sample of that sub-table yet — run a deep capture, or the form seeds known defaults for common tables. |
| Buttons do nothing after navigating (historical) | Fixed — was a CSP/Turbo nonce issue. If you ever see it again on a new build: hard-refresh (F5) and report it. |
| Create fails with *errcode -56 Empty value isn't allowed* | The device requires a field the form marks required (e.g. custom service needs a port). Fill it — the app surfaces the device's real error message. |
| Job stuck at *running* after a service restart | The boot sweep marks orphaned jobs as errors automatically; re-run the job. |
| Login works on the edge URL but not on `http://IP:8000` | By design: session cookies are Secure-only; always use the HTTPS edge URL. |
| A clone plan reports 🔒 certificates | Expected: private-key material can't travel over REST. Upload the cert on the destination (Certificate Manager / SSH) and re-run. |
| A newly added appliance never syncs and stays *unknown* | Almost always `verify_ssl` left on for a device with a self-signed certificate: the TLS check fails **before** authentication, so nothing else is reached. Turn it off on the appliance row. |
| A device card is red but no mail arrived | Check the appliance is not in **maintenance** (which suppresses its alerts by design), that `alerts.enabled` is on, and that a recipient is set. `Settings → Alerts → Preview now` evaluates without sending. |
| Fleet health shows every device healthy on a fleet you know is broken | You are on a build older than the four-signal badge. Upgrade — the old badge graded only capacity headroom and could not turn red on an uncapped fleet. |
| A probe grades critical naming a port that "doesn't exist" | Correct behaviour: a watched interface that disappeared from the harvest is reported by name, never dropped from a shorter list. |
| Scheduled actions all show *skipped (maintenance)* | Every target of that action is parked. Skipped does not count as a failure; unpark a device or retarget the action. |
| A chart shows fewer points than expected over a long range | The server dropped to hourly or daily roll-ups; the footer states which table it drew. Raw samples are capped per probe by design. |
| The console reports `nothing to repair` while files are clearly root-owned | The whole tree is root-owned, so the repair verb concludes the installation runs as root. Fix ownership manually, then re-run `satom diagnose privilege`. |
