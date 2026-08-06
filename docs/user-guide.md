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
3. [Products (ADOMs): Global, FortiWeb, FortiADC, FortiAuthenticator, FortiAnalyzer](#3-products-adoms)
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
17. [Product workspaces: FortiADC, FortiAuthenticator, FortiAnalyzer](#17-product-workspaces)
18. [API tokens](#18-api-tokens)
19. [Appearance: logo, colours & themes](#19-appearance-logo-colours--themes)
20. [The operator console](#20-the-operator-console)
21. [Provisioning new appliances](#21-provisioning-new-appliances)
22. [Updating SATOM itself](#22-updating-satom-itself)
23. [Troubleshooting](#23-troubleshooting)

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

The app hosts five workspaces, in the style of FortiManager ADOMs:

| ADOM | URL | Purpose |
|---|---|---|
| **Global** | `/` | Fleet-wide dashboard and cross-product tools: Monitoring, Search, Architecture, Analysis, Fleet Objects, Metrics, Jobs, Certificate Manager, DNS Lookup, plus fleet administration (Classification, Database, System Backup, Software Update, Bug Reports) |
| **FortiWeb** | `/web/` | Everything WAF: Server Policy, Server Objects, Web Protection, Exceptions, Configuration sections, Operations, FortiWeb administration |
| **FortiADC** | `/adc/` | Load-balancer management: the FortiADC 8.0 GUI menu (Server LB, Link LB, Global LB, WAF, Network…), signatures, and an ADC API console |
| **FortiAuthenticator** | `/fac/` | Identity and access: local/LDAP/RADIUS users and groups, FortiTokens, issued certificates, RADIUS and TACACS+ clients, and a FAC API console |
| **FortiAnalyzer** | `/faz/` | Logging and analytics: Device Manager, FortiView, Log View, Incidents & Events, Reports, and a JSON-RPC API console |

Each product workspace mirrors its appliance's own GUI menu, so an operator who
knows the device knows where to look. §17 covers what each one adds beyond the
shared pages.

Switch ADOMs from the product selector or the `‹ Global` link at the top of
each sidebar. **The ADOM is per browser tab** — you can keep FortiWeb open in
one tab and FortiADC in another; switching in one tab never changes the other.
Data is strictly scoped: a FortiADC session sees only FortiADC jobs,
notifications, templates and appliances (and vice versa); Global sees all.

## 4. Registering and operating devices

**Appliances** (Administrator → Appliances, or Global dashboard):

1. **Add appliance** — name, host/IP, port, kind (fortiweb / fortiadc /
   fortiauthenticator / fortianalyzer), credentials (stored encrypted), TLS
   verification mode.

   > **If a new appliance never syncs, check TLS verification first.** An
   > appliance that presents a self-signed certificate fails
   > `CERTIFICATE_VERIFY_FAILED` *before it ever authenticates*, so the row
   > sits at `unknown` forever with credentials that are perfectly good. Either
   > import its CA under Settings → Trust store, or set verification off for
   > that device. This is the single most common cause of a brand-new device
   > that will not come online.

   FortiAuthenticator authenticates with a **per-user API key**, not the login
   password: issue one by ticking *Web service access* on an Administrator
   account on the unit, and store that key as the appliance password.
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

### 10.1 The trust store — the CAs *SATOM itself* trusts

Global → Settings → **Trust store** (admin).

Every appliance row carries a `verify_ssl` switch, and until this page existed
it had only two positions: validate against the **public** roots — which an
appliance signed by your own CA can never satisfy — or validate **nothing**.
That is why the answer to "the new device never syncs" was always the same
`verify_ssl=false`, including on devices where verification would have worked.
This page is the missing third position: name the CA and keep the check on.

- **Import** accepts a pasted PEM or an uploaded file, in two labelled boxes —
  **Root CA** and **Intermediate CA**. A whole chain in one blob is the normal
  case and is handled. Both boxes are submitted as a single transaction, so a
  root cannot land while its intermediate fails and leave behind a chain gap
  you never asked for.
- **The label is a hint, not the verdict.** The role is derived from the
  certificate itself (self-issued ⇒ root), so a root pasted into the
  intermediate box is still recorded as a root. A form field must not be able
  to relabel a trust anchor.
- **Only CA certificates are accepted.** A device's own self-signed *leaf* is
  refused, with the reason: nothing can anchor a chain on it, so importing it
  would appear to work and then fail every handshake.
- **The bundle adds to the public roots; it never replaces them.** A mixed
  fleet — some devices behind your CA, others behind a publicly-signed
  wildcard — keeps working. If the bundle cannot be built at all, verification
  falls back to the public roots, never to *off*.
- The page lists **incomplete chains**: an enabled intermediate whose issuer is
  in neither the store nor the public roots.
- **Probe** aims a real TLS handshake at any device visible in this ADOM and
  separates the three causes, because each needs a different fix: untrusted
  issuer (import a CA), hostname mismatch (correct the appliance's host, or
  reissue with that name in the SAN), and an expired leaf (reissue — no CA
  rescues it). *"Verification failed"* on its own is not an answer.

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
- **Analysis** — **product-specific by design.** A load balancer, a WAF and
  an identity server do not have the same failure modes, so each ADOM gets a
  page written against the objects that product actually has. There is no
  shared fallback: a workspace whose analyser is not written yet says so
  instead of showing another product's empty panels.

  | ADOM | What Analysis shows |
  |---|---|
  | **FortiWeb** | FortiView traffic/sources per device with filtering, plus an assisted **packet capture** builder that runs the appliance sniffer over SSH and hands you a Wireshark bundle (`.pcap` + TLS key log for decryption) |
  | **FortiADC** | Delivery posture from the cached config: virtual servers and their published services, pools with member counts and **health-check coverage**, real servers, the security profiles each virtual server references (WAF / IPS / AV / DoS), client-SSL profiles and **local certificate expiry** |
  | **FortiAuthenticator** | **Entitlement first** — licensed users, groups, FSSO and SSO-mobility seats used against their ceiling, FortiToken stock, then identity inventory (local/remote users, groups, RADIUS and TACACS+ clients, issued certificates) and unit posture |
  | **FortiAnalyzer** | Its own FortiView group inside the workspace menu (§17.3) |

  Every finding names the object it came from, and the page reads the local
  cache only — it opens with the appliance switched off, and it keeps working
  when the device's configuration API is refusing calls.
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

Fleet health is **two pages**, because a number is read as a claim about the
page it sits on:

- **Device health** (`/monitoring/`) — the appliance cards above. Present in
  every workspace, scoped to that workspace's device kind.
- **SATOM health** (`/monitoring/satom`) — the installation itself: cluster
  peers, repository, external backup server, database, systemd units,
  redundancy, **the host machine** and **Encryption in transit**, where every
  badge is backed by a live probe rather than by configuration. **Global only**
  — a product workspace does not reach it, because those cards carry node
  hostnames and infrastructure addresses.

The **host machine** row grades disk, memory and load **on both HA nodes**, and
it exists because nothing in the product used to measure its own box. Its
limits live in Settings → Thresholds under the *SATOM machine* scope. Disk turns
critical at 92 %, deliberately below 95: a full filesystem stops PostgreSQL
writing WAL, so the alert has to arrive while there is still room to act on it.

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

**Not every kind fits every product, and the form says so rather than measuring
zero.** *Service policy*, *processor load* and *memory usage* are offered on
FortiWeb, FortiADC and FortiAuthenticator; *interface* and *proxyd* are
FortiWeb-only. On FortiAuthenticator, load and memory are read from the unit's
**REST** status resource, not the CLI — the FAC shell answers
`No such command.` to the performance summary, which is a *successful* round
trip carrying no reading, exactly the kind of silence a monitor must never
grade as healthy.

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

On **FortiAuthenticator** the ceiling is not bandwidth, it is entitlement, so
the kinds are different:

| Kind | Unit |
|---|---|
| **Licence headroom** | % of the licensed user / group / FSSO / SSO-mobility seats consumed, with the free count spelled out |
| **FortiToken pool** | % of the imported token stock already assigned |

Both grade on **percent consumed** — same direction as every other probe in the
product, so a threshold never has to be read backwards. A counter with no
ceiling, or a pool with no tokens imported, reports `unknown`: neither is
health.

The page also groups results per device: a traffic card per appliance and a
per-policy detail view, both served from stored samples.

> **Reading `sessions` on short-lived HTTP.** Connections per second is the
> number that moves; concurrent sessions can sit near zero under heavy load
> because each request lives microseconds. A threshold on `policy_sessions`
> grades *sessions* — for HTTP front ends, watch the throughput probe instead.

### 14.5 Creating probes

- **Discover from device** offers the sets that apply to that product:
  published policies, a baseline, one probe per interface, or the API telemetry
  set on FortiWeb; a baseline plus the entitlement set on FortiAuthenticator.
  Ports and policy names are picked from the cached configuration, so the
  dialog opens with the appliance switched off.
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

### 14.7 Collection — the metrics store

Monitoring → **Collection** (needs config-write).

A probe asks one question. That is the right shape for *"is this one thing
still working"* and the wrong shape for a fleet: at scale it becomes one API
call per object per sweep. A **collector** asks once per device and keeps
everything that came back — `policies` returns every policy on the box in a
single call. So the unit here is **(device, collector)**, never (device,
object): the table stays roughly one row per device per collector no matter how
many policies the fleet grows.

| Collector | Products | Default interval |
|---|---|---|
| `box` — CPU, memory, sessions | FortiWeb, FortiADC, FortiAuthenticator | 3 min |
| `capacity` — licence headroom, FortiToken pools | FortiAuthenticator | 3 min |
| `policies` — sessions / conn rate / RTT, every policy | FortiWeb | 3 min |
| `interfaces` — link state and byte counters | FortiWeb | 3 min |
| `traffic` — device total plus top-N policies | FortiWeb | 15 min |
| `transactions` — HTTP transactions, top-N policies | FortiWeb | 60 min |

Each row is editable in place: **interval** (1–1440 minutes), **enabled**, and
**top-N** (1–200) on the two collectors that have one. The expensive collectors
are bounded twice — a longer interval *and* a top-N cut ranked by live
connection rate — but the device total is always collected, so the headline
number never depends on where the cut fell.

- **Run sweep now** runs inside the request and reports targets, errors and
  series written, in the flash message.
- Devices in **maintenance**, and retired rows, are not scraped at all.
- A collector that fails records `satom_scrape_up 0` for that target. Missing
  data is never rendered as health.
- Targets appear automatically for new appliances. The sweep itself is the
  scheduled action **`metrics_scrape`** which, like every action, is **not**
  seeded on a fresh install (§15).

Samples land in a time-series store that runs **on each node, bound to
loopback**. It is not a shared database and it carries no authentication: each
node keeps its own, which is why a board can draw on one node of a pair and
report a query error on the other. Architecture, retention and sizing:
[docs/metrics-architecture.md](metrics-architecture.md).

### 14.8 Analytics boards

Monitoring → **Analytics**: boards of panels over the data the rest of this
section collects. It is a renderer, not a fourth source of measurements.

Built-in boards ship per ADOM. To change one, **Duplicate** it first. Panels
are dragged to reorder; each board has a default range and optional
auto-refresh.

- **Panel types:** line, area, bar, stat, gauge, heatmap, table, status strip.
- **Three ways to choose what a panel draws:**
  - **Probes** — an explicit list.
  - **Rule** — everything matching a kind or device.
  - **MetricsQL** — an expression evaluated against the node's store. One
    expression can draw a hundred devices (`topk(10, …)`), and it is the only
    mode that survives a fleet where enumerating the series is not an option.
    The expression is validated by *running* it, because the store is the only
    authority on its own query language.
- **Ranges:** 1 h, 6 h, 24 h, 7 d, 30 d, 90 d, or a custom window. Ninety days
  is the longest offered because that is how long hourly roll-ups are kept.
- **One resolution per panel.** The server picks the coarsest source any series
  on that panel needs, and the footer states which. Two series on one axis read
  from two different tables is a claim no legend can repair — the finer line
  shows spikes the coarser one averaged away, and it reads as a difference
  between *devices*.
- **A gap stays a gap.** No line is drawn across missing data: carrying the
  last value forward paints a convincing straight line over exactly the outage
  the chart was opened to investigate.
- **A failed query renders as an error, never as an empty chart.** On a canvas
  the two look identical and mean opposite things.

**Collection cadence** (button in the page header) shows every probe's
*declared* interval beside its *effective* one and flags the mismatches. A
probe fires only when its interval has elapsed **and** the sweep ticks, so the
real cadence is the tick rounded up: a 5-minute probe under a 3-minute sweep is
a 6-minute probe, and its own row still says 5. With no sweep scheduled the
modal reports **0** — never a plausible-looking number for collection that is
not happening.

### 14.9 Period reports

Monitoring → **Reports**: daily, weekly and monthly summaries over the last
**complete** period. The windows are half-open, so two adjacent reports can
never claim the same bucket.

Reports are **stored, not recomputed on demand.** Raw samples expire in about
two days, so a summary rebuilt six months later would quietly answer from
coarser data while looking exactly like one built on time.

- Generate on demand, or schedule the **`monitor_report`** action (`period`,
  optional `email`, `keep` for retention, and `push_server` to copy the summary
  to the external backup server).
- Read it in the browser or export **JSON**, **CSV** or plain **text**;
  **Email** sends it to the alert recipients.
- Re-running a period **replaces** its row rather than adding a second one, so
  a retry after a failed mail run updates the report you already have.
- **A mail failure does not fail the action.** The report is written and
  readable; failing the run would leave the action permanently red over an SMTP
  outage.
- A period with no samples reports **unknown**, not a healthy zero.

### 14.10 Thresholds — declare a limit once

Settings → **Thresholds** (admin). Before this page every limit lived on an
individual probe, so tuning a fleet meant editing each monitor by hand; in
practice nobody did, and all 42 production probes sat on the same factory
number regardless of what they were watching.

**Six scopes**, picked from the selector at the top: the four product ADOMs
(FortiWeb, FortiADC, FortiAnalyzer, FortiAuthenticator), **SATOM** the
application, and the **SATOM machine**. Each scope carries three blocks.

**Measurement limits** — CPU, memory, sessions, throughput, transactions,
licence and token headroom, interface staleness, TLS expiry, response time.

**Device roll-up** — what makes an *appliance* critical rather than a single
reading: the cache-age budget, its critical multiplier, the harvest failure
streak, and the capacity percentages. These used to be constants in the source.

**Binary facts and mute** — see below.

#### How a number is chosen

```
the probe's own column        ← only if the operator typed one there
  ↓ empty
the product scope's value     ← what you set on this page
  ↓ unset
the factory default           ← documented in code, never a crash
```

Two states that look alike and are not:

- **Empty** means *inherit*. Change the product value and every probe that
  nobody has touched moves with it, immediately.
- **`0`** means *this level is switched off*. It is a decision, and inheritance
  never overwrites it.

Newly discovered probes are created **empty**, so they inherit. If they were
stamped with a literal they would be frozen at birth and this page would only
ever affect probes that do not exist yet.

#### Every grade says where its number came from

Both probe pages print the resolved limit **and its origin** — `set on this
probe`, `inherited from FortiWeb`, or `factory default`. Live inheritance means
a probe you never edited can change severity because someone edited a product
default; without the origin printed, that critical would appear with no visible
cause. Each probe also has a **revert to inherited** control, which clears the
column rather than writing the current value back into it.

#### Binary facts

Some conditions have nothing to compare against: *every backend of a policy is
down*, *the policy is administratively disabled*, *`proxyd` is gone*, *a
monitored interface moved*. They were unconditional in the source. Per product
you can now set each one to **critical**, **warning** or **off**.

**Off changes the grade, never the visibility.** The fact is still printed on
the probe. A condition that disappears from the page when you silence it is how
an operator later concludes the check never fired.

#### Targeted, expiring mute

To silence *one* probe — a policy left over from a migration, say — mute it with
a **reason** and a duration of up to 720 hours. While muted it keeps running and
keeps showing its own status; it stops raising the device badge and the alert
mail, and it is reported as **lost coverage** in both. There is no permanent
mute: a silence nobody renews turns itself back on.

Prefer this to the alternatives. Lowering a product default to hide two dead
policies blinds the whole fleet, and putting a healthy appliance into
maintenance switches off its other working monitors as well.

#### What this does not do

It does not decide *who* is mailed or *how often* — that is Settings → Email &
Alerts, which is delivery policy. This page is measurement policy, and the two
are kept apart on purpose.

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

## 17. Product workspaces

Beyond the shared pages (appliances, monitoring, backups, jobs, automation),
each product ADOM carries its own menu, mirrored from the appliance's real GUI
so the navigation matches what the device itself shows.

### 17.1 FortiADC

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

### 17.2 FortiAuthenticator

The `/fac/` ADOM mirrors the six top-level groups the unit's own GUI declares:
**System**, **Authentication**, **Fortinet SSO**, **Monitor**, **Certificate
Management** and **Logging**.

- **The GUI is wider than the API, and the pages admit it.** The unit advertises
  58 REST resources, of which 40 answer a read; its menu has 129 leaves. Panes
  with nothing behind them (Network, Portals, SAML IdP, LDAP Service, the
  Monitor group, Certificate Authorities, Log Access…) render an explicit
  **"no endpoint bound"** state and name which GUI leaves they cover. An empty
  table would read as "nothing is configured" — which is a different, and
  wrong, statement.
- **Read-only section pages.** Writes go through the API console, where they are
  dry-run by default, permission-gated and audited.
- **API console** (bottom nav → API) — the registry-driven explorer over the
  FAC catalogue, with live GETs and gated writes against a chosen device.
- **Analysis** — entitlement, identity inventory and posture (see §13).

> **Two FortiAuthenticator quirks worth knowing.** Its REST paths need the
> trailing slash (`/api/v1/<resource>/`), and secrets are genuinely
> **write-only**: RADIUS client secrets and local-user passwords are *absent*
> from read payloads, not masked — so they can never leak into the
> configuration source of truth.

### 17.3 FortiAnalyzer

The `/faz/` ADOM mirrors the FortiAnalyzer menu: **Device Manager**,
**FortiView**, **Log View**, **Fabric View**, **Incidents & Events**,
**FortiAI**, **Reports** and **System Settings**.

- The unit speaks **JSON-RPC** on a single endpoint, in two dialects, and the
  endpoint registry stores which one each URI needs — an upgrade that moves a
  URI is a Registry edit, never a code change.
- Section pages read **one tab per request**, so a heavy log view never blocks
  the rest of the page.
- **API console** (bottom nav → API) — same registry-driven explorer, JSON-RPC
  aware, with audited and permission-gated writes.
- Operational endpoints (alerts, incidents, log statistics, storage) are
  deliberately **excluded from the configuration source of truth**: they change
  between two reads of an idle unit and would defeat change detection.

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

## 21. Provisioning new appliances

Two entries under **Automation**, answering different questions:

| Page | Question it answers |
|---|---|
| **Device Provisioning** | *Build me an appliance that does not exist yet.* |
| **System Provisioning** | *Apply this system profile or baseline to appliances that already exist.* |

The rest of this section is the first one.

### 21.1 Registering a hypervisor

Settings → **Hypervisors** (admin). The backends are **Proxmox VE** and
**VMware ESXi**, and the registry is multi-target: a site can hold several of
each. Credentials are encrypted at rest, exactly like an appliance row.
**Test** resolves that host's capabilities against the live endpoint and
records the verdict.

> **Capabilities are reported, never assumed.** A free-licensed ESXi host
> answers the vSphere API *read-only*, so SATOM refuses to build through it and
> says why — rather than failing halfway with "provisioning failed", which
> sends you to the wrong end of the problem. Likewise a Proxmox storage without
> the `import` content type cannot receive a disk image, and the page says so
> instead of discovering it mid-run.

**Test** is therefore worth reading rather than glancing at. It answers four
questions, and each one closes off a different option:

| The probe reports | If it is missing |
|---|---|
| Can create / power / delete a machine | nothing can be built here — only **Config only** remains |
| Can receive an uploaded image | you must place the install image on the hypervisor yourself |
| Has a serial console SATOM can drive | **Full** is unavailable; **Semi** is the ceiling |
| Which storages and networks exist | the run form has nothing to offer you |

### 21.2 Choosing a backend

Both backends do the same job and they fail in different places. Neither is
"better" — pick the one whose disadvantage you can live with.

| | **Proxmox VE** | **VMware ESXi** |
|---|---|---|
| How SATOM talks to it | REST API, username + password | vSphere SOAP API |
| Create / boot / delete | yes | **only on a paid licence**, or over the host shell (21.3) |
| Upload an install image | yes, to a storage carrying the `import` role (21.4) | the file upload works; turning it into a machine is a licensed write |
| Serial console SATOM can drive | **yes** | **no — at any licence tier** |
| Highest mode reachable | **Full** | **Semi** |
| Advantage | the only backend where a run can finish with nobody at the console | fits an existing VMware estate; no second virtualisation platform to operate |
| Disadvantage | another platform to run if your estate is VMware | a free licence blocks the write API outright, and unattended first boot is impossible regardless of licence |

> **Why "Full" is Proxmox-only, and why that is not a licensing question.** A
> factory Fortinet appliance boots into a first-boot dialog — `admin`, empty
> password, forced change — and **nothing can reach its API until that dialog
> is completed**. Driving it needs a serial console SATOM can type into.
> Proxmox exposes one. A standalone ESXi's only console is graphical, and
> adding a network serial port to the machine would itself be a licensed
> configuration write. Paying for ESXi unlocks the write API; it does not
> create a console. On ESXi the ceiling stays **Semi**.

### 21.3 When the write API is closed: the ESXi host shell

A free ESXi licence gates the **remote API write calls** — create, power on,
import — while every read keeps working. The host's own shell is a different
path inside ESXi and is not gated the same way, so giving a target SSH
credentials gives SATOM a second way to write.

| | API transport | Shell transport |
|---|---|---|
| Needs | nothing beyond the account you already gave | the host's SSH service running, plus SSH credentials on the target |
| Create / power / delete | blocked on a free licence | works |
| Attach a disk image | OVF/OVA only | any format the host can convert |
| Advantage | no extra service, no extra credential, nothing new exposed | a free-licensed host can build machines |
| Disadvantage | unusable on a free licence | it is a **standing remote-root path into your hypervisor** — that is a security decision, and it is yours |

Three things this path deliberately will not do:

1. **It never switches SSH on for you.** Enabling it is a durable change to the
   security posture of a machine SATOM does not own. The page detects the state
   and tells you what to enable; it does not reach in and enable it.
2. **It never claims the shell works until a command has actually run on it.**
   A capability inferred from "the port looks open" would promise a run that
   dies three steps later — after an address and a DNS record were already
   committed.
3. **It never puts what you typed into a shell command unquoted.** Machine
   names are validated and every value is quoted, so a name containing shell
   syntax is refused at the form rather than escaped somewhere downstream.

> **Honest status:** on the host this was developed against, SSH is switched
> off — so this transport is implemented and unit-tested but **has not been
> exercised end to end against a live host**. The capabilities panel says
> exactly that rather than reporting a confident yes.

### 21.4 Two Proxmox storages, two different jobs

Proxmox lets a storage declare what it may hold, and the two roles provisioning
needs are frequently **on different storages**:

- **`images`** — can hold a running machine's disk.
- **`import`** — can receive an uploaded appliance image.

A stock installation commonly has the default `local` storage carrying
`import` but not `images`, while the thin pools carry `images` but not
`import`. That is a working configuration, not a fault: the run form asks for
both, and they are simply not the same answer.

If **Test** reports that no storage can receive an image, add the `import`
content type to a storage in *Datacenter → Storage* on the hypervisor, picking
one with room for the appliance images you intend to keep. Nothing in SATOM can
grant that — it is the hypervisor's own setting.

### 21.5 Install media is not upgrade media

Firmware → **Upload**, with kind **Install** and the hypervisor flavour: KVM /
Proxmox (`.qcow2`) or VMware ESXi (`.ovf` / `.ova`). An upgrade `.out` applies
to a *running* appliance and cannot build a machine — two different artefact
families, kept apart on purpose.

### 21.6 Modes — advantages and disadvantages

The product cannot promise unattended first boot on every hypervisor, so how
far a run goes is a **choice**, not a guess. Each mode is a different answer to
the first-boot dialog described in 21.2.

| Mode | What it does | Advantages | Disadvantages |
|---|---|---|---|
| **Full** | Address, DNS, machine, boot, walks the first-boot dialog over the serial console, registers the appliance, applies the configuration profile. | No human step at all. Repeatable and auditable end to end — every action lands in the run log. | **Proxmox only.** The most moving parts, so the widest surface for a mid-run failure; this is what rollback exists for. |
| **Semi** | Builds and boots, then stops. You complete the first-boot dialog on the hypervisor console and resume the run. | Works on **every** backend, including a free-licensed ESXi. The one manual step is the one a human is genuinely required for. | Not unattended — the run waits until somebody acts on it. |
| **DHCP** | Builds and boots; the appliance takes a lease, SATOM finds it there and carries on. | Unattended without needing a serial console. | Needs DHCP reachable from that network, and the appliance ends up on an address you did not choose. Not every appliance takes a lease on its factory configuration. |
| **VM only** | Creates and powers on the machine. Stops. | Smallest blast radius. The right choice when another team or tool configures the appliance. | No address, no DNS, no registration — nothing else in SATOM knows the machine exists until you add it. |
| **Config only** | No hypervisor involved: reserve the address, issue the certificate, register and apply the profile against a machine that already exists. | Needs **no hypervisor at all** — the path for physical appliances and for anything built outside SATOM. | You built the machine, so its CPU, memory, disk and network are outside the run log and outside the audit trail. |

> **Stopping is not failing.** *Semi* and *VM only* are designed to stop. Such
> a run lands as **paused** with its reason printed, and you resume it. Marking
> a deliberate handoff as *failed* would teach everyone to ignore the status
> column — and then they ignore the real failures too.

### 21.7 Running one

1. **New run** — name, mode, hypervisor, node / datastore / network, CPU, RAM,
   disk, management address (or tick **use IPAM**), admin account, install
   image and system profile. Started from the Global ADOM you must also say
   which product you are building, because that decides what gets registered at
   the end.
2. **Preflight** prints the exact plan and the host's capabilities *before
   anything is created*. A run that cannot finish is **refused** with the
   blockers named — not started and then failed halfway.
3. **Advance** walks the plan one step at a time and logs each step.
4. A **paused** run is not a failed one — see 21.6. The reason is printed
   verbatim, so *"why did it stop?"* never needs a support round trip.
5. **Rollback undoes the run from what it recorded**, never from inspecting the
   world: the address is released only if SATOM allocated it (a hand-typed
   address belongs to whoever typed it), the machine is deleted only if a
   handle was written down, and a device that already reached **onboarded** is
   deliberately left registered — deleting it would orphan the configuration
   history already hanging off it.

### 21.8 Where the address comes from

Two options, and the choice changes what rollback is allowed to undo:

| | You type the address | **Use IPAM** |
|---|---|---|
| Requires | nothing | an address-management provider configured in Settings, and the tick on this run |
| Advantage | always available; you keep full control of the plan | no spreadsheet, no collision, and the record is created for you |
| Disadvantage | you are responsible for the address being free | the run now depends on a second system being reachable |
| On rollback | **left alone** — an address you chose is not SATOM's to release | released, because SATOM allocated it |

IPAM is never implicit: with no provider configured the option is not offered,
and with one configured it still applies only to a run you ticked it on.

Backend detail, the capability matrix and the state machine:
[docs/provisioning-hypervisors.md](provisioning-hypervisors.md).

## 22. Updating SATOM itself

Administrator → **Software Update** (admin). Two paths, for two situations:

1. **From the repository** — *Check*, then *Apply*. The normal path on a node
   that can reach the code remote.
2. **An offline signed package** — for a node on a management network with no
   route out. Same update, delivered as a file.

In both cases the web application only **enqueues**. A separate privileged
runner does the work, which is why the application itself never needs the
rights to install packages or restart services.

### 22.1 Applying an offline package

**Upload → read the preflight → Apply.** The preflight names every check, and a
blocking one disables Apply:

| Check | What it answers |
|---|---|
| Trust store | Is there a key that could vouch for this at all? |
| Archive | Is the file a well-formed package? |
| Signature & integrity | Is it signed by a trusted key, and do the contents match what was signed? |
| Version | Where does this move the node? |
| Upgrade path | Is this node new enough to accept it? |
| Python / Dependencies | Are the shipped wheels the ones this node needs? |
| Disk space | Is there room? |
| This node | Which machine, in which role, you are about to change. |

> **Staging is not applying.** Uploading changes nothing. And when you do press
> Apply, the privileged runner **re-verifies everything from scratch** — the
> page you were reading could be minutes old, and *"the button was enabled"* is
> not a safety property.

- **Signing keys live outside the application**, in a root-owned directory the
  web application cannot write to. An empty trust store accepts nothing.
  Manage it from the console: `satom show trust`, `satom execute trust add-key`.
- **Downgrades require an explicit tick.** Going backwards is legitimate and is
  never the default.
- **Local work survives.** Commits that are not on the remote are parked in a
  backup ref before anything is reset, and the update aborts rather than
  continuing if it cannot park them. The apply commits only the paths the
  package itself wrote.
- Uploads are size-capped and the staging area keeps only the newest few.

### 22.2 On a pair

The metrics store, the virtual environment and the installed packages are **per
node** — none of it replicates. Apply on each node, then confirm each one:

```bash
satom diagnose updates    # trust store, runner, staged packages
satom diagnose code       # is the running process actually on the new code?
```

How packages are built and signed:
[docs/offline-update-packages.md](offline-update-packages.md).

## 23. Troubleshooting

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
| A hypervisor's **Test** says it cannot create machines | Expected on a free-licensed ESXi: the write API is licensed, reads are not. Either license the host (or put it behind vCenter), or give the target SSH credentials to build over the host shell (21.3). |
| A Proxmox target reports that no storage can receive an image | No storage carries the `import` content type. Add it in *Datacenter → Storage* on the hypervisor — `images` and `import` are different roles and are often on different storages (21.4). |
| **Full** is unavailable on an ESXi target | By design, and not a licensing problem: a standalone ESXi exposes no serial console SATOM can drive, so the first-boot dialog cannot be automated. Use **Semi** (21.2). |
| A run was refused before creating anything | That is preflight working. The blockers are named on the page; a run that cannot finish is never started, so there is nothing to clean up. |
| A run says **paused**, not finished | *Semi* and *VM only* stop on purpose. The reason is printed verbatim — do the console step, then resume. |
| A machine SATOM just created is missing from the hypervisor's own list | Cluster-wide inventory in Proxmox is a cached aggregate and lags by seconds. Look at the node's own view, or wait for the refresh. The run log is authoritative about what was created. |
| Rollback left the appliance registered | Deliberate: a device that reached *onboarded* keeps its registration, because deleting it would orphan the configuration history and captures already hanging off it. Remove it from the appliance list if you really want it gone. |
| A probe grades on a number nobody typed on it | It is inheriting. The probe page prints the origin next to the value — `inherited from <product>` points at Settings → Thresholds; `factory default` means that scope has no value set either (14.10). |
| Editing a product threshold changed nothing for some probes | Those probes carry their own value, which always wins. Use **revert to inherited** on the probe to hand it back to the product default. |
| A threshold set to `0` is being ignored | `0` is not *unset* — it switches that level off, on purpose. Clear the field entirely to inherit instead. |
| A muted probe is still shown as failing on its own page | Correct: mute changes the grade, not the visibility. It stops raising the device badge and the mail, and is counted as lost coverage in both. |
| A probe started alerting again on its own | Mutes expire (720 h maximum) and there is no permanent mute. Re-mute it with a reason, or fix the condition. |
| Host disk alerts at 92 % rather than 95 % | Deliberate. A full filesystem stops PostgreSQL writing WAL, so the warning has to arrive while there is still room to act. Adjustable under the *SATOM machine* scope. |
