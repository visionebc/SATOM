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
23. [Studio: custom views, plugins & Lua](#23-studio-custom-views-plugins--lua)
24. [High availability](#24-high-availability)
25. [AppIDs](#25-appids)
26. [Settings, tab by tab](#26-settings-tab-by-tab)
27. [Operations: log collection and importing a backup](#27-operations-log-collection-and-importing-a-backup)
28. [System provisioning: profiles and baselines](#28-system-provisioning-profiles-and-baselines)
29. [Template library & the section catalog](#29-template-library--the-section-catalog)
30. [The endpoint registry & the API explorer](#30-the-endpoint-registry--the-api-explorer)
31. [Release notes & the SATOM changelog](#31-release-notes--the-satom-changelog)
32. [Troubleshooting](#32-troubleshooting)
33. [AI Advisor](#33-ai-advisor)

---

## 1. Signing in & accounts

- Browse to the app URL and log in. A fresh install ships one seeded
  administrator (`admin` / `Sopas123.-`) — **change this password on first
  login** (Profile → password).
- **Account protection:** 10 consecutive failed logins lock the account for
  15 minutes. Login attempts are rate-limited per IP (5/min).
- **2FA:** TOTP can be enabled per account, with QR enrollment on
  `Settings → Security`. Enabling it issues **backup codes that are shown
  exactly once** — save them then; you can regenerate a fresh set later, which
  immediately invalidates the old one. Set a **recovery email** on the same tab
  if you want *Forgot password* to be able to reach you (§26.13).
- **Directory auth:** LDAP and RADIUS backends are configured at
  `Settings → Authentication` (§26.7), alongside local accounts. That tab also
  **tests** the connection against unsaved form values, and **syncs directory
  users** into local rows so an admin can assign a profile *before* first
  sign-in — synced accounts are created **disabled**, pending approval.
- **Who can reach the app at all** is a separate question from who can sign in:
  `Settings → Access Control` (§26.2) carries an **IP whitelist** and an
  **allowed-users** list. Both mean *everything* when left empty, and loopback
  and admins are always allowed so neither can lock you out.
- **Roles.** Three effective profiles ship, and they gate what you can do:
  - *readonly* — see everything, change nothing;
  - *operator* — day-to-day changes (`config_write`): policies, objects,
    exceptions, backups;
  - *admin* (`user_manage`) — everything, including Settings, users, registry,
    templates, scheduled actions, and the Database section.

  **These three are seeded, not a closed set.** `Settings → Profiles` (§26.3)
  composes profiles freely from the granular permission catalog, so a profile
  that can, say, use the Lua Studio but not administer users is a configuration,
  not a feature request.
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

The app currently hosts five workspaces, in the style of FortiManager ADOMs.
**The list is data, not code:** the ADOM registry is a database table, and an
admin creates, renames, reorders, deactivates or deletes workspaces at
`Settings → ADOMs` (§26.11) — including which shared capabilities (banner, API
tokens, firmware, naming, regex) each one offers. `global`, `fortiweb` and
`fortiadc` are the exception: their keys are wired into URL scoping, so they can
be deactivated but not deleted. What you see below is this installation's
current list:

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

**The ACME DNS-provider registry** lives on the same settings tab
(`Settings → Certificate Manager`), and it is a *registry*, not a fixed list.
Each entry is a provider: a slug, a label, the flag the ACME client needs, a
documentation link, an enable switch, a sort order, and **its own list of
credential fields**. Because the field list is data, adding a DNS provider that
was never shipped is a catalog entry, not a code change.

- **Credentials are saved per provider**, into that provider's own named fields,
  and are never returned to the browser — the audit record names which variables
  were touched, never their values. Each field has an explicit *clear* tick, so
  emptying a credential is a decision rather than a side effect of leaving a box
  blank.
- **Built-in providers cannot be deleted** — disable them instead; only entries
  you added are deletable.
- The shipped catalog and any local additions are layered: the base file plus an
  overlay, so an update to the shipped list never discards your entries.

> **The node's own certificate is a different concern.** This section is about
> certificates **on the appliances**. The certificate *SATOM itself* presents to
> your browser and to its peer is `Settings → Node TLS` (§26.8), and the CAs
> SATOM **trusts** when it dials an appliance are the trust store (§10.1). Three
> different questions, three different pages.

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

**Off-box copies — the source of truth and the external server.** The vault above
lives on this node. Two settings decide what leaves it:

- `Settings → Git` (§26.4) is the code repository this node tracks. It is also
  the transport the shared release-notes corpus (§31.1) rides on. What still
  works when that remote is down, and how to recover afterwards, is
  [git-backup-and-outage.md](git-backup-and-outage.md).
- `Settings → SoT & Backup` (§26.5) configures the **firmware manifest repo**
  and the **external backup server** over SFTP. That server is where the
  appliances push their own scheduled config backups, and it is the target of the
  `push_server` option on the system-backup action and the monitoring reports
  (§15, §14.9). The scheduled action **`device_inspect`** is the one that
  uploads the versioned source-of-truth blobs off-box.

How the local source of truth is versioned and what it does and does not hold:
[source-of-truth-spec.md](source-of-truth-spec.md).

**Recovery custody — the sealed envelope.** A bundle holds a `pg_dump` in which
every appliance credential, the node identity key and the backup-server password
are Fernet ciphertext. The key that opens them is `FERNET_KEY` in `.env`, and the
internal CA key lives in `pki/` — **neither is in git, in the HA datasync or in
any bundle**, on purpose. The consequence is the part worth remembering: *a
bundle restored onto a rebuilt node is a database of unreadable secrets.*

SATOM closes that without putting the key in the backup. Both secrets are wrapped
in a scrypt+AES-GCM envelope at `data/recovery/seal.json`, which the datasync
replicates to the peer within five minutes and every bundle carries off-box from
then on. Whoever steals a bundle holds ciphertext; you, holding a passphrase and
nothing else, can rebuild the installation from any copy.

- **The passphrase is minted at install**, shown once, and never stored by the
  product. A secondary node inherits it through the join key, so both nodes open
  the same envelope. **Write it down somewhere that is not the cluster** — if it
  lives on the same disk as the node, you have three copies of a box you cannot
  open.
- **Seal on the primary, not the standby.** Only the primary holds the internal
  CA key, so a standby seal would produce an envelope that cannot re-issue the
  replication mTLS; and the standby's `data/` is overwritten from the primary
  every five minutes, so the file would not survive anyway.
- Verbs: `satom execute seal recovery` (re-run at any time; it replaces rather
  than accumulates), `satom execute unseal recovery`, and
  `satom diagnose recovery`, which reports an absent, stale, unreadable or
  **unreachable** envelope. A node with no envelope is noisy on purpose.


Its two nav siblings under **Operations** — Log Collection and Import Backup —
are §27. Neither is a backup: one collects read-only diagnostics over SSH, the
other parses a config file entirely offline.

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

**The Firmware library** (Fleet → **Firmware**, admin) is the store the upgrade
step 1 picks from, and it is worth using rather than re-uploading an image per
device.

- Each row is an image with its **version, build, product, platform** (hardware /
  VM / any), size, uploader, notes and a **sha256** recorded at upload. The binary
  lives on disk; the database row keeps the metadata and the hash, so integrity is
  checkable later.
- **Uploads are chunked and resumable.** A firmware image is hundreds of
  megabytes and a single POST across a slow link is a coin flip; the upload goes
  in parts with a status endpoint, and the file is only assembled and hashed once
  every part has landed.
- **The page is ADOM-scoped at the query, not in the template** — a FortiWeb
  workspace sees FortiWeb images and Global sees everything, and a hidden row was
  never fetched in the first place. Inside a concrete ADOM the product is not
  offered as a choice, because the upload handler would overrule it anyway.
- **Two artefact families, kept apart:** kind **Upgrade** (`.out`, applies to a
  running appliance) and kind **Install** (a hypervisor image, builds a new
  machine — see 21.5). Choosing the wrong one is the mistake this field exists to
  prevent.
- Images are downloadable and deletable, and a JSON manifest of the library is
  published for the console and the provisioning runs to read.
- Which ADOMs offer a Firmware page at all is the `firmware` capability on the
  ADOM registry (§26.11), so a newly firmware-capable workspace appears without a
  code change.

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

### 14.2 Metrics — *how much does it hold, and who changed it?*

`Monitoring → Metrics`. Inventory counts and activity for the **active
workspace**, over a date range. **Nothing here touches an appliance** — it reads
the local cache, the audit log and the change history, so it opens with the whole
fleet off.

**Four inventory cards**, labelled per ADOM rather than shared: FortiWeb counts
Server Policies / Backends / WPPs / Certificates, FortiADC counts Virtual Servers
/ Real Servers / Server Pools / Certificates, FortiAuthenticator counts Users /
Groups / RADIUS clients / Certificates, FortiAnalyzer counts Devices / Log
sources / Reports / Certificates. The totals are rendered **server-side**, so the
cards are still there if the charts fail to draw.

**Where the totals come from differs by product, and the page will not fake it.**
FortiWeb and Global read the daily typed snapshots written by the
`inventory_snapshot` scheduled action (§15) — which is why that action has to be
scheduled daily for the trend to exist at all. FortiADC has no snapshot pipeline,
so its totals are counted live off the fleet and cached briefly. A product with
neither reports **no totals rather than borrowing another product's**: an ADOM
printing FortiWeb's object counts under its own labels is worse than printing
nothing, because the numbers look like its own.

**Activity over the range:** total audited actions, real (non-dry-run) config
changes, distinct active users, and how many appliances were actually touched —
plus a breakdown of changes by object category (server policy, backend, WAF
profile, certificate, other) derived from the endpoint each change hit.

**Ranges and comparison:** 7 / 30 / 90 days or a custom window, with a
**compare** toggle that puts the immediately preceding window of the same length
beside it — so "is this a busy week" has an answer rather than a number.

**It is ADOM-scoped, precisely.** Audit rows carry their own product stamp;
change-history rows are scoped through the *kind* of the appliance they were made
on, by inclusion rather than exclusion. Manager-level changes with no appliance
count under FortiWeb, which is where they originate. Global sees everything.

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
| `vservers` — virtual servers: sessions / RTT / pool health, every VS | FortiADC | 3 min |
| `identity` — accounts, groups, tokens, certificates, RADIUS/TACACS+ clients | FortiAuthenticator | 15 min |
| `faz` — log volume, storage, alerts, incidents, devices, task queue | FortiAnalyzer | 15 min |

Each row is editable in place: **interval** (1–1440 minutes), **enabled**, and
**top-N** (1–200) on the two collectors that have one. The expensive collectors
are bounded twice — a longer interval *and* a top-N cut ranked by live
connection rate — but the device total is always collected, so the headline
number never depends on where the cut fell.

Three of those need a note, because what they can and cannot tell you is not
obvious from the name:

- `vservers` is FortiADC's counterpart to `policies`, and it reads a runtime
  API that is **not** the one the object browser uses. FortiADC publishes CPU
  and memory as *installed hardware* ("1 CPU/1 allowed"), never as
  utilisation — so those two keep coming from the read-only CLI, and a
  percentage you see for a FortiADC came from there.
- `identity` counts what the directory **contains**. It cannot tell you whether
  authentication is succeeding: no FortiAuthenticator resource reports an
  auth-rate counter, and that signal only exists in syslog, which SATOM does
  not ingest.
- `faz` never fetches a log body. Every series is a counter or a state summary,
  which is the point of monitoring a log collector rather than mirroring it.

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

- **Admin catalog**, by what it is for:

  | Group | Actions |
  |---|---|
  | Source of truth | `device_sync` (refresh the local cache from a device), `device_inspect` (sync **and** push the SoT off-box), `deep_capture`, `signature_sync` |
  | Backups | `backup` (on-device config backup), `system_backup` (the manager's own `pg_dump` bundle, optionally pushed to the backup server) |
  | Monitoring — all four are the ones §14 asks you to schedule | `metrics_scrape` (the Collection sweep, §14.7 — **every 3 minutes**), `deep_monitor` (the deep-monitor probe sweep, §14.3 — **every 5 minutes**), `monitor_report` (the period summary, §14.9 — *after* the period closes), `inventory_snapshot` (daily inventory counts for §14.2) |
  | Certificates | `cert_scan`, the three `cert_manager_*` renewals (server / client+server / client), `cert_lifecycle` (the revoke-and-cleanup sweep) |
  | Health | `health_check`, `ha_check`, `stats` |
  | Catalog | `appid_import` (the nightly AppID feed, §25) |
  | Firmware | `upgrade_prep` (backup + health, flashes nothing) and the full `upgrade` — destructive, fixed date/time, and only inside an approved Change Request window |
  | Escape hatch | `custom_rest` — any FortiWeb REST request you define; GET is a live read, writes go through the snapshot + audit + dry-run path |

  Two notes on reading that list. **There is no separate `service_monitor`
  action** — Deep monitors (§14.3) and Service monitor (§14.4) share one storage,
  one runner and one sweep, so the single `deep_monitor` action populates **both**
  pages. Two sweeps would mean two sets of samples for the same box. And
  `git_bundle` is **retired**: git no longer carries the device source of
  truth, so new installs do not seed it, though the handler still works for a
  manual run of the code repository.

- **User catalog** (single-target, date-driven): enable/disable a server policy,
  enable/disable a backend (pool member), **change a backend's IP or port**, and
  swap a server-policy certificate.
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
- **Section pages live at `/fac/m/<item_key>`** — one URL per menu leaf, where
  the key is the leaf's own identifier from the unit's menu definition. Each page
  loads its tabs from the registry endpoints bound to that leaf, capped at 500
  rows with the truncation stated rather than silently applied, and it never
  renders a device refusal as an empty table.
- **API console** (bottom nav → API) — the registry-driven explorer over the
  FAC catalogue, with live GETs and gated writes against a chosen device
  (§30 covers the registry model behind all four consoles).
- **Analysis** — entitlement, identity inventory and posture (see §13).

**What does *not* apply to FortiAuthenticator.** The FAC ADOM's sidebar carries
no Operations group, and that is not an oversight:

| Feature | In the FAC ADOM? |
|---|---|
| **Certificate Manager (§10)** | **No.** Scanning, issuance, deployment and the lifecycle sweep dispatch on FortiWeb and FortiADC only. The unit's own *Certificate Management* menu group is a **read view of the device's** certificates through the FAC section pages — it is not the fleet Certificate Manager, and material there is not managed, bound or swept by §10. |
| **Device Backups (§11)** | **Not offered in this workspace.** The vault page is not in the FAC menu; the backup transports are written against the FortiWeb/FortiADC backup APIs. |
| **Firmware upgrade (§12)** | **No.** Upgrade and Boot Partition are FortiWeb-only even on the appliance detail page, and the SSH console, discovery and upgrade-prep actions there are gated to FortiWeb and FortiADC. The firmware **library** may still open in this workspace — it is governed by the `firmware` capability on the ADOM row (§26.11), which an admin can tick, and this installation has it on. Storing an image there is harmless; there is simply no upgrade path that consumes it. |
| **Monitoring (§14)** | **Yes**, with product-appropriate kinds — a baseline plus the **entitlement** set (licence headroom, FortiToken pool), and load/memory read over REST rather than the CLI (§14.3, §14.4). |
| **Appliances, Audit log, Network segment** | **Yes** — the shared administration pages. |

> **Two FortiAuthenticator quirks worth knowing.** Its REST paths need the
> trailing slash (`/api/v1/<resource>/`), and secrets are genuinely
> **write-only**: RADIUS client secrets and local-user passwords are *absent*
> from read payloads, not masked — so they can never leak into the
> configuration source of truth. (The section pages additionally refuse to render
> a handful of secret-looking field names into a table cell even if a future
> firmware starts returning them — a belt to that braces, because the cost of
> being wrong is a credential in every screenshot of the page.)

Full product notes: [docs/fortiauthenticator.md](fortiauthenticator.md).

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
- **The way to make a theme is to duplicate one.** *Duplicate* copies an
  existing theme's tokens under a new name and leaves it inactive, so you edit a
  working palette instead of a blank one. Nothing is applied until you press
  **Activate**, which is a separate action — editing a theme that is not active
  changes nothing for anyone. **Preview** renders the current form values without
  saving.
- **Export / import moves a theme between installs.** Export downloads a small
  JSON file — *token overrides only*, no ids and no node state — so it imports
  cleanly onto any install regardless of what themes that one already has. Import
  checks the file's schema tag and **validates every token by kind before the
  theme is created**: a file with a bad value is rejected in full, naming the
  offending tokens, rather than partially imported. A name that already exists is
  suffixed rather than overwritten.
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
with a command tree across four verbs — `get` (state), `show`
(reference), `diagnose` (checks) and `execute` (actions). `satom show tree` prints
the whole tree; `satom show tree --commands` flattens it to one runnable command
per line, with the root-only and destructive ones marked.

The three you will use most:

```bash
satom diagnose all        # every check, one exit code
satom diagnose install    # infrastructure vs. protections — what is not armed
satom show docs           # print any manual, no network needed
```

The exact command count is deliberately not repeated here: `satom show tree`
prints the live tree, and [docs/cli.md](cli.md) is generated from it, so neither
can drift from the console you are running. A number typed into prose can.

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

> **There is a third update path, and it is not on this page.** The **Libraries**
> panel on `Settings → General` (§26.1) updates the **Python dependencies** —
> one package at a time, from a curated allowlist, with a per-package rollback
> point. This page moves the **application code**; that panel moves what the code
> runs on. They use the same privileged runner and the same queue, they are both
> **node-local**, and they are deliberately not merged: a dependency bump and a
> code release have different blast radii and different reasons to happen.

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

## 23. Studio: custom views, plugins & Lua

Three admin-only authoring tools, grouped under **Studio**. In the Global ADOM
they sit at Administrator → Studio; in the FortiWeb and FortiADC ADOMs the same
two authoring pages plus the read side (**Custom Views**) appear in their own
**Plugins** nav group.

They are gated by **three separate permissions** — `studio.python_console`,
`studio.plugin_studio` and `studio.lua_studio` — which are *not* the same thing
as `user_manage`. A profile can be given one studio tool without being given the
others, and without being given user administration.

| Tool | Page | What it authors |
|---|---|---|
| **Python Console** | `/database/py-console` | Throwaway Python over the curated fleet datasets |
| **Plugin Studio** | `/plugins` | Server-rendered custom views/widgets, published as **Custom Views** |
| **Lua Studio** | `/lua` | Device scripts for FortiWeb *Web Scripting* and FortiADC *Scripting* |

### 23.1 Plugin Studio and Custom Views

A plugin is a Jinja body plus optional CSS and JS, bound to a list of **curated
datasets** (fleet appliances, cached server policies, pools, WAF profiles,
managed certificates, recent audit activity, fleet counts, scheduled actions).
You pick datasets from a checklist; you never write SQL.

**Lifecycle: draft → testing → published.** The two gates are deliberate:

- you cannot jump from *draft* straight to *published* — a view has to sit in
  *testing* and be previewed first;
- publishing is **refused if the saved body does not render cleanly**. A broken
  view can never be promoted into every engineer's Custom Views list.

A **published** plugin is readable by any signed-in user in that ADOM; *draft*
and *testing* stay author-only. Demoting back to draft is always allowed.

**The sandbox contract** — worth understanding before you write anything, because
it explains what a plugin *cannot* do:

- The body renders in an **immutable Jinja sandbox**. Attribute access to
  mutating methods and the usual `__class__`/`__mro__` gadget chains raise a
  security error: the template can read the data it was handed and nothing else.
- **Data is curated, never author-supplied.** Each dataset is a fixed SELECT-only
  query run through the same masked, row-capped, read-only path the SQL console
  uses. There is no way for a plugin to run its own SQL or reach a write.
- The rendered document is served **only** inside an
  `<iframe sandbox="allow-scripts">` **without `allow-same-origin`**. That gives
  the plugin's JavaScript an *opaque origin*: it cannot read the app's cookies,
  DOM or session, and it cannot fetch anything back from the app. Its datasets
  are injected into the frame as a JSON island precisely because it cannot go
  and get them.
- A render error is a **visible red card inside the frame**, never a broken host
  page.

**Input parameters.** A plugin may declare selectors (device, select, text,
number, date) so the consumer can filter it. Values arrive as `?p_<name>=…` and
reach the body as `params.<name>`. They **never touch SQL** — the dataset stays
fixed, so a parameter can only narrow data that was already loaded, never widen
access. A `device` selector is populated from the live appliance list, scoped to
the ADOM you are in.

> **Custom Views is ADOM-scoped; Plugin Studio is not.** The read-side gallery
> ("Custom Views") is only surfaced in the FortiWeb and FortiADC ADOMs, and every
> plugin is stamped with the ADOM it was authored in. The *authoring* pages are
> reachable from the Global ADOM too, under Administrator → Studio.

### 23.2 Lua Studio

Author a device script, lint it, read a static analysis of it, and deploy it —
in that order. Targets are **FortiWeb "Web Scripting"** and **FortiADC
"Scripting"**, picked when you create the script.

- **Nothing here ever executes device code.** Linting is `luac -p`, which parses
  without running; the worst a pasted script can do is fail to compile, and the
  error comes back with its line number. FortiADC's *Scripting* is an
  iRule-style event DSL rather than standalone Lua, so `luac` cannot parse it —
  that target gets a **structural** check instead (bracket balance plus at least
  one event block), and the result says which engine produced it.
- **Analysis is static.** It reports what the script touches (request/response,
  headers, URL, pools…) against a curated API dictionary, lists calls it does not
  recognise, and flags cheap mistakes — an unbalanced `end` count, an `=` inside
  a condition, `os.execute`/`io.popen`.
- **Lifecycle: draft ↔ tested, and `deployed` only from a real push.** Marking a
  script *tested* re-runs the lint gate and refuses if it fails. You cannot stamp
  `deployed` by hand — only a successful non-dry-run deploy sets it.
- **Deploy is dry-run by default.** A dry run returns the exact request that
  *would* be sent (endpoint, method, content field, body) and contacts nothing.
  A real push needs **both** `config_write` **and** an explicit confirmation, and
  the lint gate runs again first — a script that does not parse is refused before
  any transport is opened.
- The dry-run plan is marked **not verified**: the scripting wire format has not
  been round-tripped live on this fleet, which is exactly why the default is a
  preview and the real push asks twice.

### 23.3 Python Console

Admin-authored Python, run against the **same curated dataset bundle** the
plugins use, in a bubblewrap jail with no environment, no network namespace and
none of the application tree mounted — so a script cannot open the `.env`, the
database or the keyring, and cannot open a socket. Wall-clock, CPU, memory and
process-count caps stop runaway loops. The console receives a JSON snapshot of
the data; it never touches the database itself. Every run is audited, including
the first kilobyte of the source.

## 24. High availability

Global → Administrator → **High Availability** (admin, `user_manage`). This page
was **split out of Software Update** so that the two questions get their own nav
entry: *Software Update* (§22) is "what code is this node running"; *High
Availability* is "how many nodes are there, which one is primary, and is the
standby actually receiving anything".

**Loading it never touches an appliance.** Everything on it comes from this
node's own PostgreSQL plus a best-effort HTTP probe of the peer, so the page
opens with the entire fleet switched off.

**Cluster architecture graph.** One card per registered node, laid out with the
live replication arrow drawn between them: role (primary / standby), host,
reachability, revision, health. Click a node to load it into the editor below.
The arrow's direction is the real streaming direction and its label carries the
current WAL lag — the reconciler drives the staged code rollout along that same
path. Below the graph is a fixed reference table of the **node-to-node channels**
and what each carries, which exists because `:443` (your browser → the app) is
routinely confused with the node-to-node traffic; the heavy sync — the standby's
actual database — is Postgres streaming replication, not the peer HTTPS channel.
Live per-channel encryption status is on Monitoring → SATOM health (§14.1).

**Deployment mode.** A switch between **HA** and **STANDALONE**. It lives in the
replicated settings table, which means it can only be *written* where Postgres is
read-write: **the primary**. On a standby the page says so instead of failing the
save. (The related *deploy automation* switch — reconciler AUTO vs MANUAL — is on
the Software Update page, because it is about how code rolls out.)

**The HA node registry.** Add / update / remove the peer by name (its hostname)
and host. The registry is a file in the replicated data directory: it reaches the
peer on the next data sync, and its *live* state is probed on this page rather
than trusted from the record. You cannot remove the node you are on.

**Database replication & failover.** The card shows the live streaming state read
from the local PostgreSQL — on a primary the sender side (who is connected, in
what state, how many bytes behind), on a standby its own apply lag.

**Manual failover is guarded three ways.** *Promote this node to PRIMARY* only
appears on a node that is genuinely in recovery; it requires typing that node's
hostname exactly; and it does not run in the web worker — it enqueues, and a
privileged runner performs the promotion. Promote only when the old primary is
confirmed **down**: nothing in SATOM arbitrates a split brain for you. On the
primary the card says plainly that failover is initiated from the standby's own
page.

Further reading — neither of these is a page in the product, and both matter the
day something goes wrong:

- [Encryption in transit, node TLS & the service certificate](encryption-and-node-tls.md)
  — what each channel encrypts, and how the node's own certificate is issued and
  renewed (the settings for it are §26.8).
- [Git backup and surviving a Gitea outage](git-backup-and-outage.md) — what
  keeps working when the code remote is unreachable, and how to recover from it.

## 25. AppIDs

Global ADOM → Administrator → **AppIDs** (admin, `user_manage`).

An **AppID** is two things at once, which is why it has its own catalog rather
than living in a policy comment:

- a **billing key** — which customer a FortiWeb Server Policy is charged to;
- an **access-control unit** — the scope an API token can be pinned to, so an
  external integrator only reaches the backends of *their* AppIDs.

Because it decides money *and* permissions, the authority is always the two local
tables — the catalog and the policy bindings — never a file and never a comment
string. Files and URLs are *sources* that feed the catalog.

**Manual vs imported, and the stale badge.** A row you type by hand is a *manual*
entry. A row that arrived from a feed is *imported*. Import is strictly
**additive**: it inserts, updates and stamps `last_seen`. An imported AppID that
stops appearing in the feed is flagged **stale** for review — it is never deleted
and never unassigned, because that would silently de-bill a customer or drop a
token's scope. Manual rows are never auto-staled.

**The upload flow — map once, reuse forever.**

1. **Upload** a CSV, TSV, TXT or PDF. The file is parsed and previewed; nothing
   is imported yet.
2. **Map the columns** to the fields: `app_id` (required), plus customer, label
   and rate, and any number of extra named columns you want carried along.
   Column references are header names, or index numbers if you say the file has
   no header row.
3. **Import.** The mapping is **saved**, and it is reused by every later upload
   *and* by the nightly scheduled action — that is the whole point. You map once,
   not once per file.

**External source (for the nightly).** Configure a URL, its auth mode (none /
basic / bearer) and the credential; the secret is stored Fernet-encrypted and is
never returned to the browser (the page only tells you whether one is set). The
scheduled action **`appid_import`** (§15) fetches that URL, applies the saved
mapping and imports additively. With no source configured the nightly reports
"no source configured" rather than pretending it ran.

**Assignment.** Assign an AppID to a Server Policy by picking the device and the
policy name. The binding is unique per `(appliance, server policy)`, so a policy
belongs to exactly **one** AppID; assigning a second one replaces the first
rather than double-billing. Unassign is a separate action. Deleting an AppID also
deletes its bindings, and says so.

The assignment picker spans both FortiWeb and FortiADC appliances — the catalog
is a single **global** one, not per-ADOM.

## 26. Settings, tab by tab

`Settings` is one page with **22 tabs**. Twenty of them are admin-only
(`user_manage`); the last two — **Security** and **Change Password** — are
self-service and are the only ones a non-admin sees. Throughout this manual a
setting is addressed as `Settings → <Tab>`.

Six tabs are documented where the feature they configure is documented, because
the setting is meaningless without it. They are not repeated here:

| Tab | Documented in |
|---|---|
| **Thresholds** | §14.10 — measurement policy for every probe and device roll-up |
| **Trust store** | §10.1 — the CAs *SATOM itself* trusts when it dials an appliance |
| **Certificate Manager** | §10 — issuance protocol, lifecycle policy, and the ACME provider registry |
| **Hypervisors** | §21.1 — the Proxmox / ESXi endpoints provisioning may build on |
| **Clone / Migrate** | §6 — dummy-VIP rewrite rules and the copy-WPP default |
| **Appearance** | §19 — themes, tokens, logo and favicon |

The rest follow.

### 26.1 General — identity, logging, and the Libraries panel

Application name (browser title and top bar), environment (which drives the
**PROD**/**DEV** badge), default appliance platform, session-lock timeout, status
poll interval, which log severities are written, display timezone, log format,
and whether policy detail pages expose their raw JSON. A separate card opts an
admin in or out of **bug-report notifications** (bell + email).

The **System Information** card is read-only inventory — version, node, Python,
and the library list. Underneath it sits **Libraries**, which is a **second,
separate updater** and is easy to confuse with §22:

- §22 *Software Update* moves the **application code** (a git revision, or a
  signed offline package).
- Settings → General → **Libraries** moves the **Python dependencies** — one
  package at a time, from a **curated allowlist**, with a rollback point recorded
  per package.

They are different mechanisms with different blast radii, and they are
deliberately not merged. Practical notes:

- **"Check for updates"** is the only thing that reaches PyPI, and it does so
  *outside* the page render — the Settings page itself never touches the network,
  so an unreachable PyPI cannot hang or 500 it. Results are cached for hours;
  the button forces a fresh look.
- **The web worker never runs `pip`.** It writes a request that the privileged
  updater applies, and the allowlist is enforced in both places. A package that
  is not on the list is refused before it reaches the queue.
- **It is node-local.** The virtual environment does not replicate. The card
  prints which node you are on, and you repeat the change on the other one (§22.2).
- A queued change is polled live and its steps are written by the runner.

### 26.1b Services — starting, stopping and restarting this node's units

The **Services** card at the bottom of the tab controls the units this node
runs: the web app, the scheduler, the reconciler, the metrics store, the alert /
certificate-renewal / data-sync timers, nginx and PostgreSQL. It is the same
mechanism as Libraries above — the web worker never runs `systemctl` itself, and
is deliberately not granted it, because a general `systemctl` permission reaches
every unit on the machine and is therefore root by another name. Each click is
queued for the privileged updater, which applies it and then re-reads the unit's
state: a zero exit code from `systemctl` means *the job was accepted*, not that
the daemon came up.

What you can do to each unit is a fixed table, and three restrictions in it are
deliberate:

- **The updater itself is not listed.** It is the component that applies these
  requests. Stopping it would mean no later request could be processed —
  including the one that would start it again.
- **The web app, nginx and PostgreSQL cannot be stopped from here**, only
  restarted. Stopping any of them leaves recovery possible only from a shell,
  and this page exists for the operator who has the browser and not the shell.
- **Nothing is enabled or disabled.** Start and stop are runtime-only, so a unit
  you stop here comes back at the next boot. The **At boot** column shows what
  the node arms, so that is visible rather than surprising. Changing it is a
  durable decision and stays with the installer and the CLI (§20).

Three practical notes:

- **Restarting the web app is safe to click.** It kills the worker handling your
  click, so the page cannot report the result directly — instead the privileged
  runner keeps writing the log while the app is down, and the panel reconnects
  and shows you how it ended, health check included. Expect a few seconds where
  the console is unresponsive.
- **Restarting PostgreSQL** bounces the cluster; a standby reconnects its
  replication stream on its own. If the app is left holding dead pooled
  connections the runner recycles the workers for you rather than leaving you a
  500 with no obvious cause.
- **It acts on this node only.** systemd is node-local; a peer is never touched
  from here. The card prints which node and role you are on. A unit that is not
  installed on this node — `satom-ha-datasync.timer` on a primary or a
  standalone install — is shown greyed with no buttons, not as a failure.

### 26.2 Access Control — who may reach the app at all

Two independent gates, and **both are empty-means-everything**:

- **IP whitelist** — only these source addresses or CIDRs may reach the app.
  Leave it empty to allow all. Each entry is validated as an IP or CIDR on save
  and an invalid one is skipped with a warning rather than silently stored.
- **Allowed users** — only the ticked users may sign in. Tick none to allow all.

**Loopback and admins are always allowed**, on purpose: this page is exactly
where a typo would otherwise lock everybody — including you — out of a running
appliance. Only non-admin accounts are even offered in the list.

> The per-user **top-bar banner** picker is *not* here and is not a login
> banner: it is a personal appearance preference, saved against your account, on
> your **Profile** page. Each ADOM can carry a different one.

### 26.3 Users and Profiles

**Users** is the account list — create, edit, disable, reset, assign a profile.

**Profiles** is the one that matters for §1: the three named profiles
(*readonly*, *operator*, *admin*) are **seeded, not hard-coded**. This page
composes permission sets from the granular catalog — eleven areas
(Monitoring, Web Protection, Network, Operations, Backups, API Registry, Audit
Log, Appliances, Studio, Users, Profiles), each with its own view/edit/apply-
style actions — and you can create your own profiles freely. The three seeded
ones exist because they reproduce the legacy role behaviour exactly; they are a
starting point, not the ceiling.

An **anti-lockout guard** keeps at least one active account holding both user
management and profile management, so this page cannot be used to remove the
last administrator.

### 26.4 Git — the code repository this node tracks

- **Repository** — remote, branch, HEAD, working-tree status and ahead/behind,
  refreshed on demand.
- **Configure repository** — set the remote URL, an optional token (embedded in
  the URL, never displayed back) and the branch.
- **Update from Gitea** — a fast-forward-only `git pull`. Python changes need a
  service restart to take effect; the normal path for a code change is §22, not
  this button.
- **Manual git console** — one git command per line, `#` for comments. It is
  **git-only, not a shell**: anything that is not a git subcommand is refused.
- **Recent commits** lists what actually landed.

See also [git backup and surviving a Gitea outage](git-backup-and-outage.md).

### 26.5 SoT & Backup — the firmware manifest repo and the external backup server

Two settings that the rest of the product leans on:

- **Firmware source-of-truth repository** — a *separate* git repo from the
  application code. It versions the firmware **manifest** (filenames, versions,
  sha256, where the blob lives). The `.out` binaries themselves stay on the
  backup server: git is the wrong tool for multi-hundred-megabyte blobs.
- **Backup server access (SFTP)** — host, port, user, password, and the two
  paths (config backups, firmware). This is the external box the appliances push
  their own scheduled config backups to and where firmware binaries live. SATOM
  connects read-mostly: inventory on the System Backup page, pulling firmware for
  console-driven restores, and the `push_server` option on the system-backup and
  monitoring-report actions (§15, §14.9).
- **Test connection** proves the credentials and the paths before anything
  depends on them. The password is stored Fernet-encrypted; the paths are as seen
  *inside* the SFTP session, because the server chroots the backup user.

### 26.6 Email & Alerts — this is the delivery policy §14.10 defers to

**Email (SMTP)** — enable/disable, server, port, TLS verification (with an
explicit "uncheck for an internal self-signed server, and know that it is
insecure"), optional authentication, from-name and from-address, default
recipients and a timeout. **Send a test email** uses the *currently saved*
settings — save first, then test.

**Alerts & notifications** — this is where *who is told, and how often* is
decided. §14.10 is measurement policy (what counts as bad); this is delivery
policy (what happens then), and the two are kept apart deliberately.

- **Enable alert dispatch** and the **alert recipients**. Blank recipients fall
  back to the email tab's defaults, and the page prints what that fallback
  currently resolves to.
- **Checks enabled** — tick the individual health checks that may raise mail.
- Delivery-shaping numbers: certificate warning days, a **cooldown** in hours so
  a flapping condition cannot mail every sweep, git-behind and git-unpushed
  limits (a local commit that never reached the remote is a *silent* push
  failure), backup staleness, a drift window, an automation **failure streak**
  that escalates to critical, an automation **overdue** window — because a
  scheduler that stops firing produces no failed runs at all and would otherwise
  be invisible — and the **device alert floor**, the severity at which device
  health starts mailing.
- **Preview now** evaluates every enabled check and shows what *would* fire,
  including the resolved recipient list, **without sending anything**. This is the
  right first move when a device is red and no mail arrived.

### 26.7 Authentication — LDAP / RADIUS and directory sync

Choose the backend and configure it; local accounts keep working alongside it.

- **Test** validates the connection using the values **in the form**, unsaved, so
  you can iterate without committing a broken configuration.
- **Sync directory users** imports the accounts in the configured sync group/OU
  as local rows, so an admin can assign a profile and decide access **before the
  user's first sign-in**. Imported rows are created **disabled** — pending
  approval — and you land on the Users page to act on them. Nothing about this
  grants access on its own.

Directory accounts manage their own password and MFA at the directory; the
Security tab says so rather than offering controls that would not work.

### 26.8 Node TLS — the certificate *SATOM itself* presents

A different concern from §10 (which is about certificates **on the appliances**)
and from §10.1 (which is about the CAs SATOM **trusts**). This tab is the
certificate the node **serves**, and the "Encryption in transit" card on
Monitoring → SATOM health (§14.1) points here.

- **State** shows the current certificate, its subject and expiry, the node
  hostname it was issued for, the renew mode, and the Postgres SSL policy.
- **Issue** mints one from the internal CA. **Import** takes a cert + key PEM
  pair (plus an optional chain) for a certificate issued elsewhere. **Renew**
  forces the renewal pass now instead of waiting for the timer.
- **Renew mode** decides what happens to an *imported* certificate as it ages:
  `alert` (warn only — you renew it wherever it came from) or `autopull` (fetch
  and install the new material from a configured SFTP source). **Autopull** also
  has a one-off *test now* button that ignores the mode gate.
- **PostgreSQL SSL policy** — minimum protocol version and cipher list for the
  replication/database channel, applied from this tab.

Background: [encryption-and-node-tls.md](encryption-and-node-tls.md).

### 26.9 DNS Lookup and DNS Records

- **DNS Lookup** is the resolver list behind the fleet DNS & LB Lookup tool
  (§13): a variable-length list of name + server rows, each individually
  enabled. Clearing a row removes that server.
- **DNS Records** is the *write* side — the DNS/IPAM provider SATOM may create
  records through (used by ACME dns-01 in §10 and by provisioning in §21). Pick
  the provider, fill its connection fields, and store its one secret
  Fernet-encrypted. A blank secret on save keeps the stored one; an explicit
  *clear* tick wipes it, which is what you want when switching provider.
  **Test connection** runs against the values in the form and falls back to the
  stored secret if you left the field blank.

### 26.10 Policy Links — deep links onto every Server Policy page

Up to ten links rendered at the top of every **Server Policy** detail page, with
`{token}` placeholders that each policy fills from its own context — so one entry
(a log search, a ticket query, a dashboard) jumps straight to *that* policy's
data. The available tokens are listed on the tab. A link naming a field the
policy does not have is **skipped, never rendered broken**. Each row can be
enabled and can open in a new tab; the list is shared by all ADOMs.

### 26.11 ADOMs — the product list is data, not code

Create, edit, deactivate and delete ADOMs. This is why §3's five workspaces are a
*current* list rather than a fixed one.

Each row carries a key (lowercase, the URL-scoping identifier), a display name,
title, tagline, description, sort order, an uploaded logo, a default banner, an
**active** flag, a **placeholder** flag (a workspace that is listed but has no
product pages behind it yet), and five **capability** switches — banner, API
tokens, firmware, naming and regex — which decide which shared features that
workspace offers.

**`global`, `fortiweb` and `fortiadc` cannot be deleted**; their keys are wired
into URL scoping and deleting them would orphan data. Deactivate them instead.
Everything else is fully deletable.

### 26.12 FAZ Menu — trim the FortiAnalyzer sidebar

Hide FortiAnalyzer menu groups and leaves. Turning a **group** off cascades to
everything under it; turning a single **item** off hides just that leaf. Hidden
entries disappear from the sidebar and dashboard **and are not reachable by URL**.
It applies to every user of that ADOM, and it changes only the GUI menu — the
devices and the configuration harvest are unaffected.

### 26.13 Security and Change Password — self-service, for every account

The two tabs any signed-in user gets.

- **Two-factor authentication (TOTP).** Scan the QR with an authenticator app and
  confirm one code to enable it. Enabling generates **backup codes shown exactly
  once** — save them then. *Regenerate backup codes* issues a fresh set and
  immediately invalidates the old one. Disabling 2FA asks for your current
  password first.
- **Recovery email** — used by *Forgot password* on the sign-in page to send a
  reset link. It needs server email (§26.6) configured to be worth anything.
- **Security status** and your **active session**, with a clean sign-out.
- **Change Password** — current, new, confirm.

Directory-backed accounts see an explicit note instead of these controls: they
manage password and MFA at the directory.

### 26.14 Settings endpoints owned by other pages

A few settings are *stored* by this blueprint but *edited* elsewhere, so looking
for them among the tabs is a dead end:

- **Naming** — the object-naming patterns; edited on the Naming page.
- **Classification** — the zone / line / department vocabulary that scopes
  baselines (§28); edited on the Classification page.
- **Segments** — the network-segment registry; edited on the Network Segment
  page.
- **PostgreSQL SSL policy** — saved from the Node TLS tab (§26.8).
- **ACME provider registry** — saved from the Certificate Manager tab (§10).

## 27. Operations: log collection and importing a backup

The FortiWeb ADOM's **Operations** group has three entries. §11 documents the
third one (Device Backups). These are the other two — they look adjacent and they
do completely different things.

### 27.1 Log Collection — a read-only diagnostic battery over SSH

FortiWeb ADOM → Operations → **Log Collection** (`config_write`).

**What it is not:** it is *not* a viewer of the appliance's on-box log database.
It does not page attack or event logs.

**What it is:** tick one or more FortiWeb appliances, give the run a label, and
it opens one SSH session per box and runs a curated battery of read-only
`get` / `diagnose` commands — system status and performance, HA (nodes, status,
sync state, event log), hardware (CPU, NIC, interrupts, disks and their SMART
health), routing, ARP, memory, proxy debug — writing each device's output to its
own labelled `.txt`.

- **Read-only by construction.** Every command in the run — the battery *and*
  anything you type into the custom-commands box — is asserted read-only before
  the session opens. One command that could mutate configuration refuses **the
  whole run**, not just that line.
- Long fleet runs happen in the background and report progress through a file, so
  the status keeps updating no matter which worker serves the poll.
- **History** lists every previous run; open any file in the browser or download
  it. That is what makes this useful for a support case: the artefact is a plain
  text file with a label and a timestamp.
- FortiWeb only. It is `config_write`-gated even though it writes nothing to the
  device, because it opens an administrative SSH session with the stored
  credentials.

### 27.2 Import Backup — parse a config file with no appliance at all

FortiWeb ADOM → Operations → **Import Backup** (`config_write`).

Upload a FortiWeb configuration backup — `.conf`, `.txt`, `.cfg`, `.zip` or
`.gz` — and it is parsed **entirely offline**. **No appliance is contacted**, at
any point. The result is a structured per-device snapshot: detected firmware,
total object count, per-section counts, and the raw text, all browsable
afterwards from the same page.

Use it for a box you do not manage, a backup someone emailed you, or a
pre-migration comparison. A file that is encrypted, truncated or simply not a
FortiWeb configuration is rejected with the reason and **no snapshot is stored** —
a half-parsed snapshot that looks real is worse than no snapshot.

## 28. System provisioning: profiles and baselines

FortiWeb ADOM → Automation → **System Provisioning** — the second of the two
entries named in §21. Device Provisioning builds an appliance that does not
exist; this one applies *system* configuration to appliances that already do.

Every route on this page requires `config_write`, except approve/reject which
require the template-approval permission (`operations.template_approve`).

### 28.1 Composing a system profile

A **system profile** is a declarative list of configuration elements — DNS, NTP,
RADIUS, SNMP, administrators, and in fact any `cmdb` object the endpoint registry
knows about, offered grouped by the GUI section it belongs to. For each element
you pick the object, say whether it is a singleton or carries an mkey, and supply
its values as JSON. Rows reorder with the up/down buttons, and the order is the
order they are pushed in.

A profile also carries a **scope** — zone, line, department — drawn from the
Classification vocabulary. That is what later lets a baseline match devices.

**Secrets are entered at apply time and are never persisted.** Elements that
carry secret material are flagged sensitive, and saving the profile **strips**
every secret-looking field out of the stored body — recursively — before it is
written. The RADIUS shared secret, admin passwords and SNMPv3 auth/priv keys are
supplied again at apply time. A template is a thing that gets versioned, shared,
exported and reviewed; a template is not a place for a password.

Saving stores the profile as a **versioned Template of kind `system-profile`**
(§29). Editing it creates a **new version** rather than overwriting the old one.

### 28.2 Applying to one device or to the fleet

Apply asks for a target hostname and a **Change ID** — both are required, and both
land in the audit record, so a system-wide push is always attributable to a
change.

Then it is two-phase, as everywhere else in the product:

1. **Preview** — `dry_run`, showing the exact planned requests per device.
   Nothing is contacted for real.
2. **Confirm** — a **canary-gated** live write: the first device goes first and
   the rest only follow if it succeeded. The result reports `{canary, rest,
   aborted}`.

Choosing *Entire fleet* is explicit. Selecting "selected devices" and then
selecting nothing is **refused**, rather than being quietly treated as "all" —
the empty selection is exactly the shape a fleet-wide accident takes.

### 28.3 Approval

A saved profile is pending until someone with the approval permission
**approves** it (making it selectable for baselines) or **rejects** it with a
reason the author can read. Approval and authorship are separate permissions on
purpose.

### 28.4 Baselines

A **baseline** is a *combo* — a zone × line × department permutation — with a set
of **approved** templates assigned to it. It answers "what should every device in
this scope have".

- **Generate** creates a combo for every zone × line × department permutation
  that does not have one yet. (It does **not** read a device: a baseline is
  composed from approved templates, not captured from a box.)
- **Assign / unassign** attaches an approved template to a combo, one at a time
  from the combo's own page, or one template to many combos at once from the
  catalog grid.
- **Matching devices** are computed from the appliances' own classification. An
  empty facet on a combo means *any*, so a combo with no zone matches every zone.
- **Apply** is the same two-phase machinery: a dry-run preview across the matching
  devices, then a confirmed rollout that runs as a **background job** with live
  progress in the job dock — a fleet rollout must not live inside an HTTP request.
- A baseline that matches no devices, or that has no composing templates, says so
  and does nothing.

The filter (zone / line / department / name) can be **saved to your account** and
is restored on your next visit.

## 29. Template library & the section catalog

Two pages that are the same data seen from two ends: the **Template Library** is
where desired state is authored and reviewed, and the **Section Catalog** is the
approved subset, arranged the way FortiWeb arranges it.

### 29.1 The Template Library

FortiWeb ADOM → Administrator → **Template Library**. A template is a named,
**versioned** blob of desired state of a given kind (web-protection profile,
system profile, and the other configuration kinds). Editing never overwrites:
saving produces a **new version** of the same kind and name, and the previous
version stays.

Permissions are split three ways, and they are not the same permission:

| Action | Needs |
|---|---|
| Browse the library | `operations.view` |
| Create / edit / clone / delete a template | `operations.template_save` |
| Apply a template to **one** device | `operations.template_apply` |
| Apply to **several** devices (a fleet rollout) | `operations.apply` **and** an approved template |
| Approve / reject / revoke approval | `operations.template_approve` (admin) |

So an operator can author a draft and try it on a single box; making it
fleet-deployable is a separate, gated decision by someone else.

**Lifecycle: pending → approved (or rejected) → applied.**

- A new or edited template lands **pending**.
- **Approve** makes it fleet-deployable. **Reject** records a reason the author
  can read. **Revoke approval** returns an approved template to pending.
- Applying is two-phase everywhere: a POST without confirmation returns a
  **dry-run preview** and contacts nothing; a confirmed apply runs canary-first
  and, for more than one device, as a **background job** in the job dock.
- **Approval status and deployment are different things.** A template can be
  approved and never applied. The one deliberate exception: approving a **Web
  Protection Profile** template *does* start a fleet-wide rollout immediately,
  because the team rule is that a template-managed WPP is read-only on the devices
  — the approved version is what must be on every one of them (§9).

### 29.2 The Section Catalog

FortiWeb ADOM → **Section Catalog** (admin). It lists **only templates whose
status is `approved`**, grouped by the FortiWeb section each kind belongs to,
with an unknown-section bucket last so nothing silently vanishes.

Two things it is not:

- It is **not a live device browser.** That is the *Configuration* area, which
  reads what is on the box. This page is **desired state** — what someone decided
  should be true, approved.
- It is not the whole library. Pending and rejected templates are absent by
  construction, so the catalog is clean without anyone curating it.

**This is the connective tissue to §28.** The approved templates listed here are
exactly the pool that baselines draw from: a template is authored in the library
(29.1), approved, appears here grouped by section, and is then assignable to a
zone × line × department combo in System Provisioning (28.4). A template that
never got approved cannot reach a baseline, which is the point.

## 30. The endpoint registry & the API explorer

Every product workspace has an API console (§17.1, §17.2, §17.3 cover the ADC,
FAC and FAZ ones). This section documents the **FortiWeb** one and, more
importantly, the **registry model all four share**.

### 30.1 What the registry is

The registry is the map from a **logical endpoint name** the application uses
(`server_policy`, `dns`, `system_global`…) to the **concrete URI** on that
firmware. There is one catalog per product, each with its own API dialect
(FortiWeb `v2.0`, FortiADC `v1`, FortiAuthenticator `v1`, FortiAnalyzer
JSON-RPC).

It is **DB-first with the YAML as seed and fallback**:

- the live catalog is a database table, editable from the console and captured by
  the nightly database dump;
- the git-tracked `endpoints*.yaml` files at the repository root are the **seed**.
  At boot they are synced **INSERT-ONLY**: a name already present in the database
  is never touched, so an operator edit always wins over the shipped file;
- if the database cannot serve the catalog at all — an early script, a standalone
  tool, a fresh tree — the YAML is served directly, so nothing ever breaks for
  want of a table.

Reads go through a short-lived per-process cache. An edit invalidates the cache
of the worker that served it immediately; the other workers converge within a
minute.

**This is why §17.3's claim holds.** When a firmware upgrade moves a URI, the fix
is a registry edit on the affected product's console — a row change, audited,
effective across the workers within a minute. It is not a code change, not a
release, and not a redeploy.

### 30.2 Editing the catalog

Editing needs `registry_edit`, every change is **audited** with the before/after
URI, and it happens **in place on the console's API-menu tree** — the standalone
Registry page was fused into the explorer, so there is one page and one write
path rather than two that can disagree. Old `/registry` and `/registry/<section>`
bookmarks redirect to the explorer; `/registry/search` still serves a plain
name/URI search across the catalog.

Two rules on the write path:

- A name is validated (letters, digits, `_`, `-`, `.`) and a URI must be an
  absolute API path. A duplicate name within the same product and API version is
  refused, naming the row it collides with.
- **Removal is a soft delete.** Disabling a row sets `enabled=false` and *keeps
  the row*, precisely so the boot seeder cannot resurrect a name the operator
  removed. Re-enabling is the same button. Nothing here hard-deletes a catalog
  entry.

### 30.3 The FortiWeb API explorer

FortiWeb ADOM → **API** — the registry catalog browsed as the FortiWeb API menu
on the left, and a request console on the right: pick an appliance, pick or type
an endpoint, choose a method, supply a JSON body, execute.

- **GET is always allowed** to any user who can reach the page.
- **POST / PUT / DELETE / PATCH require the `registry.execute_write` permission**
  and are refused with that message otherwise. Note that this is a *separate*
  permission from `registry.edit`: one lets you change the catalog, the other
  lets you fire writes at a device through it.
- Every execution is audited with the method and endpoint.
- The device's own response is shown as it came back — a device error is rendered
  as the device's error, never smoothed into an empty result.

Unlike the FortiAuthenticator console (§17.2), the FortiWeb explorer's writes are
**not dry-run by default** — this is the raw request console, and the confirmation
is the permission.

Endpoint conventions, dialects and per-product quirks:
[docs/device-api.md](device-api.md).

## 31. Release notes & the SATOM changelog

**Two different things share the name "release notes", and confusing them wastes
an afternoon.** One is the **vendor's** notes for the *appliance* firmware,
harvested into the product. The other is **SATOM's own** changelog, which tells
you what changed in *this manager*. This section covers both, in that order.

### 31.1 Vendor release notes (the topbar modal)

In the FortiWeb and FortiADC ADOMs the top banner opens a **Release Notes**
modal. It reads a corpus of harvested vendor notes — Known and Resolved issue
tables plus the prose sections — and it is the corpus §12 step 3 diffs against
when it advises you on an upgrade.

Three tabs:

| Tab | What it answers |
|---|---|
| **Issues** | Every Known / Resolved issue, filterable by version, status, topic and free text |
| **Upgrade advisor** | Pick a current and a target version: what the move **resolves**, what is still **known** in the target, and the relevant notes |
| **Notes** | The prose sections of a release, by version and section |

Reading any of it needs only the view permission. Two buttons change the corpus:

- **⤓ Sync from git** — `git pull`, then reload the corpus from disk. **Any
  signed-in user** may do this; it is how a second node or a colleague picks up a
  scan somebody else ran. With nothing in git yet it says so and tells you to run
  a scan.
- **🔎 Scan from Fortinet** — **admin only**. It auto-discovers every published
  version for that product on the vendor documentation site and harvests the
  issue tables and prose into the corpus. You choose which majors (or all), and
  the transport (direct fetch, an optional crawler fallback, at least one
  required). If **publish** is left on, the corpus is committed and pushed so the
  whole team shares one harvest rather than each node scraping the vendor
  separately.

Two operational details worth knowing:

- **A scan runs in a background thread and writes its progress to a status file**,
  so the poll is answered correctly no matter which worker handles it — and you
  can close the modal. When it finishes, the result arrives as a **bell
  notification** in that ADOM, success or failure.
- A second scan is refused while one is running, but a "running" flag older than
  half an hour is treated as dead, so a crashed thread cannot trap you behind a
  permanent conflict.

The corpus holds both products in one shared file, tagged per row, and every read
is filtered by the ADOM you are in — a FortiADC workspace never shows FortiWeb
rows.

### 31.2 SATOM's own changelog — what changed in *your* version

The manager's own history lives in **`CHANGELOG.md`** at the repository root. It
is a normal Keep-a-Changelog file, one section per released version, and it is
the authoritative answer to "what is new since we last updated".

Where to read it:

- **On the published documentation site** — the release pipeline renders
  `CHANGELOG.md` into the site's **Releases** section, one page per version.
- **On the node, with no network at all** — the operator console (§20) prints it:

  ```bash
  satom show changelog          # the most recent release notes from the tree
  satom show docs changelog     # the same file through the manual reader
  ```

**Which version am I on?** Three answers, all equivalent:

- the **console footer** of every page prints `v<version>`;
- `satom show version` — the app, the CLI and Python;
- `satom get system status` — identity, version, HA role and your privilege
  level, in one place. On a pair, run it on **each** node: the code is per-node
  and a half-applied update is exactly the situation this tells you about (§22.2).

## 32. Troubleshooting

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
| A page says the object is **locked by another user** | A lease lock. Edit pages hold a short lease on `<kind>:<name>` per appliance and refresh it with a heartbeat; a browser that closed or crashed stops heartbeating and the lease **expires by itself in about two minutes**. Wait it out. If the holder is genuinely gone and you cannot wait, the page offers an explicit take-over — deliberately explicit, because two concurrent editors on one device object is what the lease exists to prevent. |
| A plugin preview renders as a blank iframe | The frame is a sandboxed **opaque origin** by design (no `allow-same-origin`), so anything the plugin's JS tries to read from the parent app silently yields nothing. Use `window.pluginData` / `window.pluginParams`, which are injected into the frame — a plugin cannot fetch its datasets back (23.1). A *render* error would show as a red card instead, so a truly blank frame is usually empty output or JS reaching outward. |
| Lua **Deploy** returns a plan instead of pushing | Correct: deploy is dry-run by default. A real push needs `config_write` **and** an explicit confirmation, and the lint gate runs again first (23.2). A refusal naming *lint failed* means the script does not parse — fix it, then mark it tested. |
| The HA page shows the standby with growing WAL lag | Replication is streaming but not keeping up, or the standby is stalled. Read the replication card on Global → Administrator → **High Availability** (§24); it prints the sender/apply state and byte lag from Postgres itself. Do not promote a lagging standby: promotion is for a primary confirmed **down**. |
| Deployment mode / HA node changes will not save | The setting is in the **replicated** settings store, so it is writable only where Postgres is read-write — the **primary**. The standby's database is read-only and the page says so (§24). |
| An AppID import lands zero rows, or the wrong columns | The saved column mapping does not match this file. The importer says *no rows with a non-empty AppID were found* when the `app_id` column is mapped wrong. Re-upload, re-map on the preview, and import — the corrected mapping is then reused by later uploads **and** by the nightly (§25). |
| An AppID went **stale** after the nightly | It stopped appearing in the feed. That is a flag for review, not a deletion: the row, its billing and its policy bindings are all intact by design (§25). |
| LDAP/RADIUS sign-in fails, or a directory sync imports nothing | Use `Settings → Authentication → Test`, which runs against the values **in the form**, then check the sync group/OU. Remember that synced users are created **disabled** — they exist, pending your approval, and until you enable them their sign-in will fail (§26.7). |
| The node certificate expired although autopull is on | Autopull only applies to an **imported** certificate and only in `autopull` renew mode; in `alert` mode SATOM warns and renews nothing. Check the source connection with the one-off pull button on `Settings → Node TLS`, and confirm the mode (§26.8). |
| Log Collection returns 403, or refuses the whole run | The page is `config_write`-gated even though it writes nothing to the device (27.1). A run refused with a read-only violation means one command — battery or custom — could mutate configuration; the whole run is refused rather than the offending line skipped. |
| A template is stuck in **pending** and will not roll out to the fleet | Single-device apply works at any status; a **multi-device** rollout needs the template **approved** *and* the Run-operations permission. Approving is a separate permission (`operations.template_approve`) from authoring (29.1). |
| A registry-driven page 404s on the device after a firmware upgrade | The firmware moved that URI. Fix it as a **registry edit** on that product's API console — the catalog is DB-first, the edit is audited, and it converges across workers within a minute. No code change or release is involved (30.1). |
| `diagnose recovery` says the sealed envelope is **unreachable** | The envelope is on disk but not owned by the account that carries it, so the HA datasync skips it and the bundle writer records it absent. Re-run `satom execute seal recovery` on the primary — sealing hands the file to the tree owner. This is reported as **critical**, deliberately worse than an honest "not sealed": an unreadable envelope looks like durability and is not (11). |
| `satom execute seal recovery` printed the passphrase and I lost it | Re-run it. Sealing is idempotent and replaces the envelope, so a new passphrase is fine as long as **every** copy is re-sealed from the primary — the peer and the next bundle pick it up automatically. An old bundle stays locked to the old passphrase, which is why the copy you keep off-box needs the passphrase that matches it (11). |
| A registry endpoint you disabled came back after a restart | It did not — disabling is a **soft delete** and the row survives exactly so the boot seeder cannot resurrect the name. If the name is live again, someone re-enabled it; the toggle is audited (30.2). |

## 33. AI Advisor

A chat assistant (`/advisor`, permission `advisor.use`) for three things:
interpreting a WAF false positive and drafting the exception for it, drafting
a Lua script, and searching the versioned device-configuration source of
truth. Full design write-up: `docs/ai-advisor.md`.

### 33.1 Turning it on

**Settings → AI Advisor** (`advisor.configure`, admin-only) has three
switches, all off on a fresh install: **Enable AI Advisor**, **Allow
read-only tool calls**, and **Allow external providers**. A local Ollama
provider (`ollama-local`) is seeded automatically the first time the page is
opened — enabling the feature and leaving the other two switches off is
enough to chat entirely within the LAN.

### 33.2 Providers

Add a provider under the same tab: `ollama` (local, no key), `openai`
(OpenAI itself or any OpenAI-compatible gateway — the field for a corporate
LiteLLM/vLLM front door, not a personal login), or `anthropic`. **Test
connection** fires one real call with the form's current values before you
save anything. Delete a provider to revoke it instantly — its API key is
Fernet-encrypted at rest and never re-displayed.

### 33.3 Attaching context and the external-provider preview

The paperclip menu attaches a concrete piece of SATOM data (an appliance's
exception list, an existing Lua script) to the next message. If the active
conversation's provider is external, clicking Send first shows exactly what
will leave the LAN — the redacted text and how many internal identifiers were
rewritten — before anything is sent. Nothing goes out until you confirm.
Local Ollama has no such prompt: it never leaves the LAN, so there is nothing
to preview.

### 33.4 Proposals — how a chat turns into a change

When the model suggests a concrete change, it appears as a card under the
conversation with the exact JSON it proposed, **Apply as draft** and
**Dismiss**. Apply requires the SAME permission the manual form already
needs:

- A WAF/signature exception needs `config_write` and creates a row on the
  **Exceptions** page for that appliance, in the state it would be in had you
  filled the form in yourself. Pushing it to the device is still a separate,
  later step on that page.
- A Lua script needs `studio.lua_studio` (super-admin) and creates a
  **draft** script in Lua Studio, linted the same way a manually typed one is.

Dismissing a proposal just marks it dismissed — nothing was ever written
anywhere.

### Troubleshooting

| Symptom | What's happening |
|---|---|
| Sending a message returns *"AI Advisor is disabled"* | The master switch in Settings → AI Advisor is off (33.1). |
| Sending to a non-local provider returns *"external providers are disabled"* | A provider is configured but **Allow external providers** is off — two separate gates on purpose (33.1). |
| A provider shows *"no route to host"* / times out on the first message | If it's the local Ollama provider, a large model can take well over a minute to load into memory on a cold call — that is not a hang, wait for it (`docs/ai-advisor.md`). |
| A chat reply mentions a proposal but no card appears | The model's fenced `` ```satom-proposal `` block did not parse as valid JSON against the schema — the chat reply still reached you, the malformed block was silently dropped rather than turned into something that only looks valid. |
| **Apply as draft** is refused (403) | You don't hold the permission the MANUAL form for that kind requires (`config_write` for an exception, `studio.lua_studio` for Lua) — the AI path is never a shortcut around it (33.4). |
