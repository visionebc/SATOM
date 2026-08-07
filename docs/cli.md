# The operator CLI (`satom`)

A console tool for diagnosing, controlling and rebuilding a SATOM node —
including, and especially, when the web UI will not start. It is modelled on the
appliance CLIs the product manages: verbs first (`get`, `show`, `diagnose`,
`execute`), `?` for completion at any depth, and an interactive prompt.

```
$ satom get system health
$ satom diagnose all
$ sudo satom execute restart web
$ satom                       # interactive prompt
```

---

## 1. Why it looks the way it does

Three constraints shaped every decision below. They are load-bearing; if you
extend the CLI, keep them.

### 1.1 It must work on a node that is broken

That is the only reason it exists. So the CLI is **standard library only** at
module level: no Flask, no SQLAlchemy, no psycopg, not even the app package. A
tool that needs a healthy venv to tell you the venv is unhealthy is not a
recovery tool.

Commands that genuinely need the app (queueing an update, running
`flask cert-renew`) import it **lazily**, inside the function, and degrade with
a stated reason when it is unavailable. `tests/test_cli.py` enforces the
module-level rule with an AST check, because a stray import would not be
noticed until the day it matters.

### 1.2 It degrades by privilege instead of failing

`get`, `show` and `diagnose` work as **any** user — that is the half of the tool
that rescues an operator staring at a dead node before they have sudo. `execute`
requires root and refuses with an explanation, an exit code of `3`, and the full
command echoed back so the arguments do not have to be retyped from memory. It
never prints a traceback for a permission problem.

Where a probe needs a credential the caller cannot read (`.env` is `0640
root:<service account>` on purpose), the command reports **degraded** and says
so. A probe that could not run must never render as a pass — that is the exact
failure mode that let the Fleet health badge show four dead appliances as
healthy (see `safeguards.md` §9b).

### 1.3 It is a root tool for a human, and that must not weaken the app

Reinstalling a venv, writing unit files or installing packages **is** root.
There is no subset of that which is "a bit less than root" — a `.deb` runs its
own maintainer scripts as root, so permission to install packages *is* root.

That is fine, because the privilege model
([`privilege-model.md`](privilege-model.md)) governs the **service account**,
not the human at the console. What it forbids is:

> **Never add `satom` to the service account's sudoers.**
> A `NOPASSWD: /usr/local/sbin/satom` line for the app user equals
> `NOPASSWD: ALL`: it would turn a compromised web worker into root and undo
> the entire deprivilege work. `satom diagnose privilege` fails loudly if it
> finds such a line.

And the corollary that dictates where the code lives:

> **The CLI never executes from `/opt/satom`.**
> The app tree is writable by the service account. A launcher that exec'd code
> from there would let a compromised worker rewrite what an operator is about to
> run under `sudo`. So the binary is `/usr/local/sbin/satom` (`root:root 0755`)
> and its code is a **copy** at `/usr/local/lib/satom-cli/` (`root:root`).
> Both are verified — ownership, mode, and *not a symlink* — by the installer
> and again by `satom diagnose privilege`.

---

## 2. Getting the privilege

Print the rule and hand it to whoever administers the box. This needs no
privilege and changes nothing, so you can produce it from the account that does
not yet have rights:

```bash
satom show sudoers alice
```

```
alice ALL=(root) /usr/local/sbin/satom
```

Install it as `/etc/sudoers.d/satom-operator`, `0440`, after
`visudo -cf`. What it grants: everything under `execute` — service control,
venv and unit reinstall, queued code and pip updates, promote, certificate
operations. What it does **not** grant: a shell. There is no "run arbitrary
command" verb, and package changes go through the curated allowlist, never a
free-form `pip install`.

The path must stay fixed and the target `root:root`. If the operator can write
`/usr/local/sbin/satom`, the rule is equivalent to `NOPASSWD: ALL`. Same trap
as the installer sudoers rule documented in `INSTALL.md` §5.

---

## 3. Command reference

`?` works at every level — `satom ?`, `satom get ?`, `satom execute reinstall ?`
— and in the prompt, where Tab completes as well. A `*` marks commands that
need root.

Two rules run through the whole table and are enforced by
`tests/test_cli_ops.py`:

* **A read never writes.** `get`, `show` and `diagnose` must leave the node
  byte-identical. This is not theoretical: `git status` run as root rewrites
  `.git/index` and takes it from the service account, and `compileall` leaves
  root-owned `__pycache__` behind — so two *diagnostics* were creating the
  ownership drift a third diagnostic then reported. Fixed with
  `--no-optional-locks`, an in-memory `compile()` and
  `PYTHONDONTWRITEBYTECODE=1`.
* **Absence of data is never health.** A check that cannot read reports
  *unknown* and exits 4. It never reports OK.

### `get` — read state (any user)

| Command | What it answers |
|---|---|
| `get system status` | Identity, version, git head, HA role, and *your* privilege level |
| `get system health` | **Start here.** Units + `/healthz` + disk, folded into one status |
| `get system performance` | Load, memory, filesystems |
| `get system disk` | Space, **inodes**, and the directories that actually grow here |
| `get system interface` | Addresses and the ports SATOM cares about |
| `get system time` | Clock and NTP. Skew breaks TLS, ACME and every "age" below |
| `get service status [<svc>]` | One unit (with journal tail) or all of them |
| `get timer status` | Every timer and `.path`: enabled, last fire, next fire, last result |
| `get node status` | Role, peer list, peer reachability over `:8443` |
| `get database status` | Connection, size, replication stream |
| `get certificate status` | Served cert, expiry, renewal journal |
| `get certificate list` | **Every** certificate this node holds: served, node leaf, internal CA |
| `get backup status` | The four copies side by side, with their real ages |
| `get backup list` | The bundles `execute restore db` accepts |
| `get scheduler status` | Scheduled actions: what exists, last run, failure streak, overdue |
| `get device status` | Appliances: sync state, maintenance flag, last contact |
| `get monitor status` | Probe states; parked devices are shown but do not raise the roll-up |
| `get job list` | The background-job ledger, including ghosts |
| `get update history` | Recent updates, and whether the runner ever picked them up |
| `get git status` | Branch, drift, oldest unpushed commit, parked safety refs |
| `get user list` | Who can log in — and whether anyone still can |
| `get alerts status` | Whether anyone is actually **told** when something breaks |
| `get log <svc> [lines]` | Journal tail |

Most of this half has no console of its own in the product: the scheduler, the
timers, the four backup copies and the alert delivery path are things you
otherwise only see indirectly, through their consequences.

### `show` — configuration and reference (any user)

| Command | What it answers |
|---|---|
| `show privilege` | How privilege is split here and why. Read this before asking for rights |
| `show sudoers [<account>]` | The rule to request for an operator account |
| `show config` | `.env` with secrets redacted by pattern |
| `show units` | Alias → unit map with install state |
| `show services` | What each unit is *for*, and which are off limits |
| `show paths` | Canonical layout: what is replicated, what is node-local, what is secret |
| `show ports` | Which port belongs to which listener, and why |
| `show schedule` | What *should* run and how often |
| `show runbook [<topic>]` | **Offline recovery procedures** — see below |
| `show changelog` | The most recent release notes from the tree |
| `show version` | App, CLI, Python, node |

`show runbook` carries twelve procedures inside the binary: `web-down`,
`db-down`, `scheduler-idle`, `update-stuck`, `cert-expired`, `disk-full`,
`peer`, `promote`, `restore`, `fresh-install`, `locked-out`,
`device-unreachable`. They live in `deploy/satom_cli/runbooks.py` rather than in
this file because the operator who needs them is on a node with no web UI, no
browser and usually no route to the internet. Keep the commands in them
copy-pasteable.

The CLI never prints a secret and no command accepts one as an argument — it
would land in shell history and in the process table.

### `diagnose` — active probes (any user)

| Command | What it finds |
|---|---|
| `diagnose all` | All 24 checks, folded into one exit code. The one to paste into a ticket |
| `diagnose install` | **Is this node ARMED, or merely installed?** Run it on day one |
| `diagnose code` | Is each long-running process running the code that is on disk? |
| `diagnose scheduler` | Is anything automated actually firing here? |
| `diagnose units` | Unit inventory, `User=` drop-ins, and who each process really runs as |
| `diagnose config` | `.env`: present, correctly owned, internally consistent |
| `diagnose service <svc>` | State, resolved `User=`, drop-ins, journal |
| `diagnose database` | Connect, recovery state, TLS in use, lock waits |
| `diagnose python` | venv, `pip check`, in-memory compile, **and the lazy-import smoke test** |
| `diagnose network` | Listening ports, `nginx -t`, local HTTPS probe |
| `diagnose nginx` | Syntax, which vhost owns `default_server` on `:443`, and the ACME redirect trap |
| `diagnose certificate` | Expiry, live handshake, the renewal timer's last result |
| `diagnose acme` | Client, account key, webroot, provider credentials |
| `diagnose peer` | Peer reachability, datasync key mode, datasync timer |
| `diagnose git` | Repository integrity, including the root-owned-files trap |
| `diagnose privilege` | Integrity of the CLI install and the sudo boundary |

**`diagnose install` is the one to run on a new node.** The installer delivers
code, units, TLS and a database. It does *not* deliver the automated
protections, because those are DATA and operator edits win over code defaults
in this product — no `ScheduledAction` row is ever seeded. A fresh node
therefore has every capability, zero coverage, and looks perfectly healthy.
`diagnose install` prints that difference; `execute seed actions` closes it.

**`diagnose code` exists because the scheduler carries its own copy of the
application.** Touching an action spec or the probe registry and restarting only
`web` leaves the sidecar on the old code, and the symptom is pathognomonic: the
manual run succeeds while the scheduled run fails with `Unknown action`.

**`diagnose python` exists because of a real incident.** In 1.2 and 1.2.1 a
stray `import os` above `from __future__ import annotations` made
`app/services/cert_service.py` a hard `SyntaxError`. Every caller imports that
module *inside a function*, so the app booted, `/healthz` returned 200 and 757
tests stayed green while the nightly certificate renewal died on both nodes.
The check therefore does two things nothing else does: it compiles every module
under `app/` and `deploy/`, and it explicitly imports the known lazily-imported
modules (`LAZY_MODULES` in `cmd_diagnose.py`). **When you add a module that is
only imported inside functions, add it to that list.**

**`diagnose nginx`** watches the vhost trap: exactly one config must own
`default_server` on `:443`. With none, the alphabetically first config wins and
the application becomes unreachable by hostname while the static site keeps
serving — which reads like a DNS fault. It also flags a `return 301` at *server*
level in a config with no ACME challenge location: that redirect runs in the
rewrite phase, before a location is chosen, so it swallows the HTTP-01
challenge.

### `execute` — change state (root)

| Command | Notes |
|---|---|
| `execute restart\|start\|stop <svc>` | Restart **verifies** `/healthz` afterwards; `systemctl` returning 0 has lied before |
| `execute restart-all` | The stack in dependency order, then `nginx -t` + reload, then verify |
| `execute enable\|disable <unit>` | Timers and `.path` units. `disable updater` is refused — see below |
| `execute reload nginx` | Runs `nginx -t` first and refuses on invalid config |
| `execute seed actions [--yes]` | **Creates the protections a fresh install does not.** Prints the plan; `--yes` applies |
| `execute update code [<target>]` | **Queues** a git update (or a rollback, by commit) for the privileged runner |
| `execute update pip <pkg> <ver>` | Curated allowlist only. Node-local: the venv is not replicated |
| `execute update status [<id>]` | The runner's `steps[]` log (any user) |
| `execute reinstall venv --yes` | Rebuilds `venv/`, saving a `pip freeze` and moving the old one aside |
| `execute reinstall units` | Re-copies the units **and re-pins `User=` via drop-in** |
| `execute reinstall cli` | Refreshes the root-owned copy of this CLI |
| `execute repair permissions` | Gives root-owned files in the app tree back to the service account |
| `execute repair jobs [--older-than N] --yes` | Sweeps ghost jobs and prunes the terminated ledger |
| `execute repair tmp [--older-than N] --yes` | Deletes aged scratch under `data/tmp`. Nothing else prunes it |
| `execute cert renew` | Runs the renewal pass now instead of waiting for 03:30 |
| `execute alerts run [--dry-run]` | Evaluates the health checks now |
| `execute backup db [--push]` | A **bundle** in the product's own format; `--push` also sends it off-node |
| `execute backup git` | `git bundle --all`, including the parked safety refs |
| `execute restore db <bundle> --yes` | Stops the writers, restores, restarts, verifies `/healthz` |
| `execute admin reset-password <user>` | Asked interactively; never in `argv` |
| `execute admin unlock <user>` | Clears a lockout without touching the password |
| `execute scheduler run\|enable\|disable <id>` | One action, now |
| `execute maintenance <device> <on\|off>` | Park or un-park an appliance |
| `execute support bundle` | Every diagnostic, journal and unit file in one `0600` archive |
| `execute preflight` / `postflight` | The existing risky-change harness |
| `execute promote --yes` | Standby only; requires the explicit flag |

Anything destructive prints its plan and **exits 2** unless given `--yes`.
`tests/test_cli_ops.py` fails the suite if a command flagged destructive does
not document that confirmation.

Two units are deliberately **not** operator-controllable:
`satom-updater.{path,service}` (it *is* the privileged root runner — a verb that
restarts it re-enters the privilege boundary sideways) and `postgresql`
(shared state; use `systemctl` and know why). `execute disable updater` is
refused outright for the opposite reason: disabled, every enqueued update sits
at `queued` forever and *nothing* reports an error. `execute enable updater` is
allowed, because that is the fix.

`execute backup db` and `execute restore db` **delegate to
`app/services/system_backup.py`**. The bundle is a `.tar.gz` of `db.dump` +
`reports/` + a manifest, and the System Backup page, the retention policy, the
push to the external server and `restore_backup` all read exactly that format.
An earlier version of this CLI wrote a bare `pg_dump` instead: invisible to
every one of them. A backup nothing can restore is not a backup. What the CLI
adds on top is the part a web request cannot do — stopping the writers around
the restore and verifying the node afterwards.

`execute reinstall units` writes a **drop-in**, never an edit to the unit file,
because `self_update_runner.py` re-copies `deploy/<unit>` on every code update.
That is exactly how the standby silently reverted to `User=root` after the
2026-07-26 deprivilege — a `sed` on a unit does not survive.

`execute repair permissions` exists because running anything as root inside
`/opt/satom` (pytest, a git command, a manual script) leaves root-owned files
in `.git/`, `data/jobs/` and `reports/`. The symptoms are indirect: git publish
keeps working, because git renames refs and only needs the directory, while some
other write fails quietly.

### The complete table

Everything above is a curated tour — grouped, with the reasoning. The table
below is the *exhaustive* list, and it is **generated from the live registry**
(`deploy/satom_cli/tree.py`) by `deploy/gen_cli_reference.py`. A hand-typed
enumeration of this many commands goes stale at the fifth addition, and the
person who most needs it is the one whose web interface is down and who cannot
check. `tests/test_docs_publication.py` fails the suite when this block no
longer matches the console you are running.

<!-- BEGIN GENERATED COMMAND REFERENCE -->

*96 commands in 34 groups. This table is generated from `deploy/satom_cli/tree.py` by `deploy/gen_cli_reference.py` — it cannot drift from the console you are running. `!` marks a command that changes state destructively and demands `--yes`.*

### `get`

Read state. Every command below works as **any user** — this is the half of the console that has to keep working when everything else does not.

| Command | Root | ! | What it does |
|---|:--:|:--:|---|
| `satom get system status` | — | — | Identity, version, HA role and your privilege level. |
| `satom get system health` | — | — | One-shot roll-up: units, /healthz, disk. Start here. |
| `satom get system performance` | — | — | CPU, memory and filesystem usage. |
| `satom get system interface` | — | — | IP addresses and the ports SATOM cares about. |
| `satom get system disk` | — | — | Space, inodes, and the directories that actually grow. |
| `satom get system time` | — | — | Clock and NTP. Skew breaks TLS, ACME and every 'age' here. |
| `satom get service status [<service>]` | — | — | State of one unit, or all of them. |
| `satom get timer status` | — | — | Enabled, last fire, next fire, last result. |
| `satom get node status` | — | — | Role, peer list and peer reachability over :8443. |
| `satom get database status` | — | — | Connection, size, replication. |
| `satom get certificate status` | — | — | Served certificate, expiry and the renewal journal. |
| `satom get certificate list` | — | — | Every certificate this node holds, not just the served one. |
| `satom get backup status` | — | — | All four, side by side, with their real ages. |
| `satom get backup list` | — | — | Database bundles you can hand to 'execute restore db'. |
| `satom get scheduler status` | — | — | What exists, when it last ran, what is overdue. |
| `satom get device status` | — | — | Sync state, maintenance flag, last contact. |
| `satom get monitor status` | — | — | Probe states, and how much coverage is disabled. |
| `satom get job list` | — | — | The ledger, including ghosts that keep the dock's toast open. |
| `satom get update history` | — | — | Recent updates and whether the runner ever picked them up. |
| `satom get git status` | — | — | Branch, drift, unpushed age, parked safety refs. |
| `satom get user list` | — | — | Who can log in — and whether anyone still can. |
| `satom get alerts status` | — | — | Whether anyone is actually told when something breaks. |
| `satom get log <service> [lines]` | — | — | Tail a unit's journal. |

### `show`

Configuration, reference material and the console's own map. Also unprivileged: `show sudoers` prints the rule you need *before* you have it.

| Command | Root | ! | What it does |
|---|:--:|:--:|---|
| `satom show trust` | — | — | Public keys this node accepts update packages from. |
| `satom show package <file.tar.gz>` | — | — | Inspect an update package without applying it. |
| `satom show config` | — | — | The .env, with secrets redacted. |
| `satom show units` | — | — | Alias -> systemd unit map, with install state. |
| `satom show services` | — | — | What each unit is FOR, and which ones are off limits. |
| `satom show paths` | — | — | Canonical filesystem layout: what is replicated, what is not. |
| `satom show ports` | — | — | Which port belongs to which listener, and why. |
| `satom show schedule` | — | — | What SHOULD run and how often. |
| `satom show runbook [<topic>]` | — | — | Offline recovery procedures. 'show runbook' lists them. |
| `satom show privilege` | — | — | How privilege is split here, and why. Read this first. |
| `satom show sudoers [<account>]` | — | — | Print the sudoers rule to request for an operator account. |
| `satom show docs [<name>] [<section>]` | — | — | The manual, from the tree. 'show docs' lists it. Works with no network. |
| `satom show changelog` | — | — | The most recent release notes from the tree. |
| `satom show version` | — | — | Versions of the app, the CLI and Python. |
| `satom show tree [<prefix>...] [--commands] [--depth N] [--root] [--danger]` | — | — | The WHOLE command tree in one view. Filters: --commands/--depth/--root. |

### `diagnose`

Active probes that reach out — sockets, database handshakes, compilers, peers. Unprivileged, but they take longer than `get`.

| Command | Root | ! | What it does |
|---|:--:|:--:|---|
| `satom diagnose all` | — | — | Every check, folded into one exit code. |
| `satom diagnose service <service>` | — | — | One unit: state, definition, drop-ins, journal. |
| `satom diagnose install` | — | — | Is this node ARMED, or merely installed? Run on day one. |
| `satom diagnose code` | — | — | Is each process running the code that is on disk? |
| `satom diagnose scheduler` | — | — | Is anything automated actually firing here? |
| `satom diagnose units` | — | — | Unit inventory and whether the privilege model survived. |
| `satom diagnose config` | — | — | The .env: present, correctly owned, internally consistent. |
| `satom diagnose database` | — | — | Connect, replication role, TLS, lock waits. |
| `satom diagnose python` | — | — | venv integrity, compileall, and the LAZY-import smoke test. |
| `satom diagnose network` | — | — | Listening ports, nginx -t, local HTTPS probe. |
| `satom diagnose nginx` | — | — | Syntax, which vhost wins :443, and the ACME redirect trap. |
| `satom diagnose certificate` | — | — | Expiry, live handshake, renewal timer result. |
| `satom diagnose acme` | — | — | Client, account key, webroot, provider credentials. |
| `satom diagnose peer` | — | — | Peer reachability, datasync key and timer. |
| `satom diagnose git` | — | — | Repository integrity, including the root-owned-files trap. |
| `satom diagnose updates` | — | — | Can this node accept a signed offline package, and is that safe? |
| `satom diagnose privilege` | — | — | Integrity of the CLI install and the sudo boundary. |
| `satom diagnose recovery` | — | — | Does anyone hold the two secrets no backup carries? |

### `execute`

Everything that changes state. **Root required.** Without it each command refuses with the full command line you tried and exit code 3, never a traceback.

| Command | Root | ! | What it does |
|---|:--:|:--:|---|
| `satom execute export recovery-key [--out PATH] [--yes]` | yes | ! | Print FERNET_KEY + the internal CA key so a rebuild is possible. |
| `satom execute restart <service>` | yes | — | Restart a service and VERIFY it actually came back. |
| `satom execute restart-all` | yes | — | Restart the whole stack in order, then verify /healthz. |
| `satom execute start <service>` | yes | — | Start a service. |
| `satom execute stop <service>` | yes | — | Stop a service. |
| `satom execute enable <unit>` | yes | — | Enable a timer or .path unit (--now). |
| `satom execute disable <unit>` | yes | — | Disable a timer. Refuses the privileged runner. |
| `satom execute reload nginx` | yes | — | Validate the config, then reload nginx. |
| `satom execute reset theme` | yes | — | Activate the built-in theme — the way back from a palette that made the console unreadable. |
| `satom execute seed actions [--yes]` | yes | — | The minimum scheduled actions. Shows the plan; --yes applies. |
| `satom execute update code [<target>]` | yes | — | Queue a git update — or a rollback, by passing a commit. |
| `satom execute update pip <package> <version>` | yes | — | Queue a curated-allowlist package change. Node-local. |
| `satom execute update package <file.tar.gz> [--yes] [--allow-downgrade] [--no-backup]` | yes | ! | Apply a SIGNED offline update package. Works with no network. |
| `satom execute update status [<id>]` | — | — | Show the latest (or a specific) update record. |
| `satom execute reinstall venv` | yes | ! | Recreate venv/ from requirements.txt. Needs --yes; keeps a freeze to roll back to. |
| `satom execute reinstall units` | yes | — | Re-copy the systemd units AND re-pin User= via drop-in. |
| `satom execute reinstall cli` | yes | — | Refresh the root-owned copy of this CLI from the repo. |
| `satom execute reinstall runner` | yes | — | Refresh the root-owned copy of the privileged update runner. |
| `satom execute trust add-key <file.pub> [--name <slug>]` | yes | — | Install a signing public key into the trust store. |
| `satom execute trust remove-key <name\|fingerprint> --yes` | yes | ! | Stop accepting packages signed by a key. Needs --yes. |
| `satom execute repair permissions` | yes | — | Give root-owned files in the app tree back to the service account. |
| `satom execute repair jobs [--older-than N] [--yes]` | yes | ! | Sweep ghost jobs and prune the terminated ledger. |
| `satom execute repair tmp [--older-than N] [--yes]` | yes | ! | Delete aged scratch under data/tmp. Nothing else prunes it. |
| `satom execute repair nginx [--yes]` | yes | ! | Re-pin the proxied Host header and the served names in the vhost. |
| `satom execute cert renew` | yes | — | Run the renewal pass now instead of waiting for 03:30. |
| `satom execute alerts run [--dry-run]` | yes | — | Evaluate the health checks now. |
| `satom execute backup db` | yes | — | pg_dump the application database into data/system_backups/. |
| `satom execute backup git` | yes | — | git bundle --all, including the parked safety refs. |
| `satom execute restore db <file> --yes` | yes | ! | Replace the database from a bundle. Dumps the current one first. |
| `satom execute admin reset-password <username>` | yes | — | Set a password (asked interactively, never in argv). |
| `satom execute admin unlock <username>` | yes | — | Clear a lockout without touching the password. |
| `satom execute scheduler run <action-id>` | yes | — | Fire one action NOW as a manual run. |
| `satom execute scheduler enable <action-id>` | yes | — | Enable one action. |
| `satom execute scheduler disable <action-id>` | yes | — | Disable one action. |
| `satom execute support bundle` | yes | — | Collect every diagnostic and journal into one 0600 file. |
| `satom execute maintenance <device> <on\|off>` | yes | — | Park or un-park an appliance. |
| `satom execute preflight [<label>]` | yes | — | Capture a health baseline BEFORE a risky change. |
| `satom execute postflight` | yes | — | Diff the current health against the last preflight. |
| `satom execute promote` | yes | ! | Promote this standby to primary. Requires --yes. |

### `tree`

| Command | Root | ! | What it does |
|---|:--:|:--:|---|
| `satom tree [<prefix>...] [--commands] [--depth N] [--root] [--danger]` | — | — | The whole command tree. Alias for 'show tree'. |

<!-- END GENERATED COMMAND REFERENCE -->

---

## 4. Exit codes

Stable contract; scripts and the recovery steps in `INSTALL.md` depend on them.

| Code | Meaning |
|---|---|
| `0` | OK |
| `1` | The command ran and the result is bad (unit dead, cert expired) |
| `2` | Usage error — the parser could not resolve what you typed |
| `3` | Insufficient privilege |
| `4` | Could not run (missing dependency, unreadable credentials) |

`--json` switches every command to machine output with the same status and exit
code. `SATOM_CLI_TRACE=1` adds a traceback when a handler itself crashes.

---

## 5. Extending it

**The command tree is data.** `deploy/satom_cli/tree.py` holds the whole
grammar; the parser, `?` help, Tab completion, the privilege gate and the JSON
renderer all read that structure. Adding a command is one entry:

```python
_n("throughput", "Live throughput for a server policy.",
   run=g.throughput, usage="get service throughput <policy>"),
```

Handlers take `(ctx, args)` and return a `Result`. `ctx` (see `context.py`)
gives you `run()`, `psql()`, `http()`, `unit_state()`, `journal()`, `role`,
`env`, `is_root` and `app_user` — all of them already degrading correctly.

Same contract the rest of the product already uses for `registry_endpoints`,
`adoms` and `acme_dns_providers`: **behaviour is data, so extending it is a row,
not a refactor.** A tree of `if/elif` rots by the fourth command.

`tests/test_cli.py` walks the tree and fails the suite if a node lacks help
text or a declared privilege level, if a read-only verb requires root, if a
state-changing verb does not, or if a node both runs and has children (the
parser cannot resolve that). Those are not style checks: an undeclared node
fails with a traceback for the unprivileged operator, at the one moment a
traceback is least useful.

### Where the code lives

| Module | Holds |
|---|---|
| `tree.py` | the grammar — **the extension point** |
| `context.py` | `Ctx`: process, env, role, units, HTTP, psql. Everything degrades |
| `render.py` | `Result`, the exit-code contract, the refusal message |
| `dbq.py` | every SQL read, in one place, so `get` and `diagnose` cannot disagree |
| `cmd_get.py` / `cmd_ops.py` | reads: the node itself / the automated layer |
| `cmd_show.py` / `cmd_docs.py` | configuration / reference and runbooks |
| `cmd_diagnose.py` / `cmd_checks.py` | probes: core / install-completeness and drift |
| `cmd_execute.py` / `cmd_fix.py` | state changes: core / repair, seed, restore, accounts |
| `runbooks.py` | the twelve offline procedures, as data |

Split by *when you reach for it*, not by size. A new read about scheduled work
belongs in `cmd_ops.py`; a new SQL read belongs in `dbq.py` next to the others,
never inline in a handler.

`tests/test_cli_ops.py` adds the operational guards: reads that cannot write,
the checker/fixer key sets staying identical, seeded action keys existing in the
real catalogue, destructive verbs refusing without `--yes`, and every runbook
being listed and containing at least one command. When you add a lazily-imported
module, add it to `LAZY_MODULES`; when you add a protection to
`MIN_ACTIONS`, add it to `SEED_PLAN` in the same commit — the suite fails
otherwise, on purpose.

### Deliberately not built yet

A FortiWeb-style `config … / set … / end` mode. It is a real state machine
(buffer, `abort`, validation on `end`) and there is nothing yet that justifies
it — reconfiguration today goes through the web UI or the installer. The
one-shot dispatcher is the substrate it would sit on, so adding it later costs
nothing that has been built here.

---

## 6. Installation and drift

The CLI is installed by `deploy/install-cli.sh`, which is idempotent and called
from **three** places so the root-owned copy cannot age behind the app:

1. `installers/install-satom.sh` — on a fresh install.
2. `deploy/self_update_runner.py` — after every code update. This matters: the
   CLI lives *outside* the app tree, so a `git pull` does not reach it. Without
   this step the console tool would silently drift from the app it exists to
   repair.
3. `satom execute reinstall cli` — by hand.

Verify at any time:

```bash
satom diagnose privilege
```

It fails if the binary or the library is not `root:root`, is group/world
writable, is a symlink, is loaded from inside the app tree, or if
`/etc/sudoers.d/satom` has been widened to grant the CLI to the service account.

---

## 7. Output: what is decoration and what is contract

The rule the renderer exists to keep:

> **Decoration is for a TTY. Content is identical either way.**

An operator redirects this tool into a ticket, greps it, and pastes it into a
chat window. So colour, the rules under headings and the box-drawing in
`show tree` appear only when a human is looking at a terminal. Through a pipe
the bytes are plain — and, because there is no width to fit, nothing is
truncated either: help text you would lose is text you cannot get back.

| control | effect |
|---|---|
| `--color` / `--no-color` | force colour on or off, whatever the stream is |
| `NO_COLOR=1` | the cross-tool convention; honoured. An explicit flag still wins |
| `SATOM_CLI_COLOR=1` | force colour from the environment (for a wrapper script) |
| `--ascii` / `SATOM_CLI_ASCII=1` | plain `|-` branches instead of box-drawing |
| `--width N` | pretend the terminal is N columns (used by the tests) |
| `--json` | machine contract: never coloured, never wrapped |

`TERM=dumb` and an unset `TERM` disable colour on their own. The glyph set is
chosen from the stream's **encoding**, not from a guess: on a serial console
with an ASCII stdout the box characters would be unprintable, so the CLI falls
back to `|-` / `` `- `` automatically.

**Two layers keep the output path from raising.** Typographic characters this
code emits (em dashes in titles, middots in the banner, the truncation
ellipsis) are folded to ASCII when the stream cannot carry them; anything
outside that table — a device name, a certificate subject, a journal line —
is caught by reconfiguring the stream with `errors="replace"`. This is not
theoretical: an em dash in a title once crashed the whole command under an
ASCII stdout. *A diagnostic tool that dies while printing its diagnosis, on a
node that is already broken, is worse than no tool.*

**Colour has a narrow vocabulary, on purpose.** Only words this CLI emits as a
*verdict* are painted: `pass`/`ok` green, `warn` amber, `FAIL`/`error` red.
State words — `active`, `inactive`, `enabled`, `disabled` — are deliberately
never painted. `satom-ha-datasync` is `inactive` on the primary **by design**;
painting it red is the same false positive that had to be removed from
`get system health`. A check that always complains is a check that gets
ignored, and so is a colour that always complains.

### `show tree` — the whole command surface

```
satom show tree                      every command, as a tree
satom tree                           same thing (alias, for muscle memory)
satom show tree execute              just that branch
satom show tree --commands           flat list, one runnable command per line
satom show tree --depth 2            stop two levels down
satom show tree --root               only branches that require root
satom show tree --danger             only destructive commands
satom show tree --json               the registry as nested JSON
```

Marks: `*` requires root, `!` destructive (needs `--yes`). Both propagate up,
so a group shows `*!` when anything under it does.

This renders the **live registry** (`deploy/satom_cli/tree.py`), so it cannot
describe commands this build does not have, and it cannot omit ones it does. A
hand-written command list in a document is a copy, and copies go stale the
first time somebody adds a node — `tests/test_cli_render.py` fails the suite if
any runnable command is missing from `--commands`.

`--commands` is fixed-column and always separated by two spaces, so it can be
`cut`/`awk`'d. That mattered: on the widest row the padding is zero, and a
single separator space fused the path, the mark and the help into one
unsplittable field for exactly the longest command.

## Related

* [`privilege-model.md`](privilege-model.md) — accounts, sudoers, HA trust
* [`safeguards.md`](safeguards.md) §3 — the privilege boundary and how to verify it
* [`INSTALL.md`](INSTALL.md) §1.2, §5 — installer privilege and hardening
