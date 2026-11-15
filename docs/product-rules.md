# Product rules — the decisions every feature is held to

These are the product decisions that code, documentation and reviews hold to.
Each rule says what it is, why it exists, and — where one exists — the test
that enforces it. When a rule changes, this file changes in the same commit.

Related: the team's day-to-day conventions are in
[Project overview & operating rules](overview.md) §5, the visual rules in
[Design system](design-system.md), the hard-won implementation gotchas in
[Engineering manual](engineering.md) §13, and the architecture vocabulary in
[SATOM and the NAF Framework](naf-alignment.md).

---

## 1. Talking to appliances

### 1.1 The cache first, the device last

Presentation reads what the collectors stored. Going to the appliance is an
explicit action, run as a job and visible to the operator — never a side
effect of opening a page. Day-to-day browsing must not hammer the fleet.

### 1.2 Writing to a device is six steps

Every new or reworked write flow (policy clone, mass deploy, provisioning,
restore) runs:

1. **Pre-check** — reachable, build, licence, HA role (write to the primary).
2. **Versioned backup** of what is about to change.
3. **Dry-run diff** of intent against the device's actual state.
4. **Minimal change in dependency order** — certificate → health check → real
   server → pool → virtual server / server policy; deletions in reverse order.
5. **Post-check by re-reading the object.** FortiWeb silently ignores fields
   of a PUT; only a re-read catches it.
6. **Compensation or restore** with a clear message if anything failed.

A flow is idempotent: the second run makes zero changes. An existing flow that
lacks a step is a defect.

### 1.3 Truth per build, not from memory

Paths, fields and authentication change between firmware builds. The answer
comes from the API library for the **exact** build, a measurement in the lab,
or the vendor documentation for that version. What is not verified is marked
— `# TODO verify: <product> <build> <endpoint>` in code, *"unverified on this
build"* in the interface.

### 1.4 HTTP 200 is not success

Read the body. Appliances answer 200 with `{"payload": "Invalid VM License"}`,
licence errors, or their own error codes inside `results`. A licence failure,
a rejected read or a collector that is down is shown as an **ERROR** — never as
empty and never as "ok". A failed metrics collector writes
`satom_scrape_up 0`: absence is not health.

### 1.5 Everything done to a device leaves a trace

Every action SATOM takes against an appliance is a step in a job and a line in
the audit log. A channel that talks to a device without going through job
progress (a login, a GUI reader) is a defect.

### 1.6 Every field the device has is visible

In every form of every product (FortiGate, FortiWeb, FortiADC, FortiAnalyzer,
FortiAuthenticator), each field of the exact build is shown. What the vendor's
GUI shows sits in its section; what it does not show sits in
**"Not in GUI, but in CLI"**, with its channel (`REST`, or `CLI` through the CLI
writer). A field whose channel is unknown says *"unverified on this build"*.
Nothing is hidden; without a measured layout the section says so.
Implemented in `app/services/not_in_gui.py`; enforced by
`tests/test_not_in_gui.py`.

---

## 2. Security

- **No secret** in code, logs, commits, job steps or output. Credentials are
  encrypted in the database; keys live in the environment file.
- **TLS is verified by default** against the trust store. Verification is off
  only when an operator turned it off explicitly — never as a fallback.
- **Readers cannot write, by construction.** Read-only and read-write device
  profiles are separate; read paths call `assert_readonly`.
- Sessions log out, requests time out, dependencies are pinned.
- **RBAC on the route, not only on the template:** hiding a button is not
  authorisation.
- Behind a reverse proxy on a non-standard port, the proxy must pass
  `Host $http_host` (the installer writes it). Never lower
  `WTF_CSRF_SSL_STRICT` to work around a header problem.

---

## 3. Architecture: do not mix the blocks

SATOM maps onto the NAF reference model. A change names the block it touches
and does not blur them:

| Block | In SATOM |
|---|---|
| Intent | Templates, system profiles, processes, the local source of truth |
| Executor | REST writes, the CLI writer |
| Collector | Device sync, the knowledge harvester, metrics collection |
| Observability | Metrics store, drift, CVE/PSIRT |
| Orchestrator | Processes, scheduler, jobs |
| Presentation | Web console, `satom` CLI, API v1 |

Signs of mixing: a view that calls the device, a process that writes without
intent, a collector that writes.

---

## 4. Navigation and information architecture

### 4.1 Settings configures; Operations operates

Decided **per card, not per page**. A card that writes a value or row that
changes behaviour belongs in **Settings**. State, health, logs, explanations,
demos, live lists and one-off actions (sync, list/release) belong in
**Operations**. Example: Settings › AI › Sentinel holds only the Sentinel form,
context and response policy; Operations › Sentinel holds the incidents
console, overview, border blocklist and architecture.
Enforced by `tests/test_settings_nav_groups.py`.

### 4.2 A basic element is native; a plugin is a plugin

A **basic element of an ADOM** lives natively in that ADOM's menu and can be
switched off per ADOM with a capability (for example the Web Server Manager
of the Linux ADOM, `cap_webserver`). What is delivered **as a plugin** ships as
signed plugin packages (several = a bundle). A basic element may also have a
bundle for automation (fine-grained steps on the same code) without a menu
folder. Never switch off something operators use in the name of unifying it.

### 4.3 Troubleshooting is a set of plugin apps

Backend Reachability, Config Compare, HTTP Observatory, Path Diagnostics,
Transaction Tracer and Diagnose Log Collection are signed plugin apps in the
**Troubleshooting** menu group; each is one SATOM step over the same code as
its page (`app/services/studio_troubleshoot.py`). There is no native
Troubleshooting submenu; the pages remain reachable by URL. A change to one of
those pages is reflected in its step.

### 4.4 In Plugin Studio everything is an app

- Two kinds: **flow** (form + diagram) and **script**. A script's code stays
  under `data/scripts/`, because the sandbox runner must never hold a database
  connection.
- **Examples are templates and cannot be deleted** — by no route (app, script,
  store, connection). They can be edited, disabled, reset and downloaded.
- **Reset** deletes the app's data (its runs and the store rows only that app
  uses); shared stores are respected.
- **A plugin's code is its dependency, not a second plugin** (2026-11-13). A
  script that a flow app runs is listed under **Plugin Studio › Code** with
  the apps that run it and the package that brought it, and in the app's
  Dependencies tab; it has no row under Apps and no entry under Plugins. A
  script no app runs is an app of its own. The plugin's logic stays in the
  plugin (its view or its own scripts); SATOM only gains generic capabilities.
- **A File field takes at most 20 MiB** (2026-11-13), the same number for flow
  apps, scripts and the browser; only an app with a File field takes a run
  request that large, every other request stays at 1 MiB.

### 4.5 Menu groups are assigned in SATOM, never in the Builder

The Builder creates apps; the menu group is assigned in SATOM. Groups are
**folders**: a folder grants its ADOMs and user groups to all its apps,
**adding** to each app's own grants, never removing. A folder is chosen from a
list ("+ New folder…"), never typed as free text. A package carries the folder
name only — never the grants.

### 4.6 Top-level entries

Plugin Studio is a first-level sidebar entry. Scout sits directly above Wiki.

---

## 5. Language

Everything the product ships is **English**: the interface, installers and
builders, deployment scripts, `--help` text, generated file headers, code
comments, documentation, the changelog and tests. One language — no `--lang`,
no `LANG` detection, no fallback. Requests quoted in the changelog are quoted
translated.

Exceptions: the web console's translations (German, Spanish, French, Italian
through Babel; English is the default), language names, `app/translations/`,
internationalisation test fixtures, and installers silently accepting `s`/`si`
as yes for answer files written by old versions.

Measure compliance with a stop-word scorer, not with a grep for accented
letters: most non-English text is plain ASCII.

---

## 6. Look and feel

SATOM is a **light** product built on its own tokens and components. The full
rules — stylesheets, colours, badges, card grids, charts, plugin views — are in
[Design system](design-system.md).

---

## 7. Documentation and tests travel with the change

- A change with visible behaviour updates, in the same round, the user guide,
  the `CHANGELOG.md` entry and the matching Documentation Center article.
- A new or changed test runs targeted; only a green test lands on `main`. The
  full suite runs nightly against `main`.
- Only the test files of the touched modules run during development; the full
  suite is not a per-change ritual.

---

## 8. Licence

SATOM is licensed under the **Elastic License 2.0**: source-available, free for
internal use including production; offering it to third parties as a hosted or
managed service needs a commercial licence (see `LICENSE`). Eight surfaces
declare the licence and must agree — `tests/test_license_consistency.py`.
