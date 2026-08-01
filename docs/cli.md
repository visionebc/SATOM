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

### `get` — read state (any user)

| Command | What it answers |
|---|---|
| `get system status` | Identity, version, git head, HA role, and *your* privilege level |
| `get system health` | **Start here.** Units + `/healthz` + disk, folded into one status |
| `get system performance` | Load, memory, filesystems |
| `get system interface` | Addresses and the ports SATOM cares about |
| `get service status [<svc>]` | One unit (with journal tail) or all of them |
| `get node status` | Role, peer list, peer reachability over `:8443` |
| `get database status` | Connection, size, replication stream |
| `get certificate status` | Served cert, expiry, renewal journal |
| `get log <svc> [lines]` | Journal tail |

### `show` — configuration and policy (any user)

| Command | What it answers |
|---|---|
| `show privilege` | How privilege is split here and why. Read this before asking for rights |
| `show sudoers [<account>]` | The rule to request for an operator account |
| `show config` | `.env` with secrets redacted by pattern |
| `show units` | Alias → unit map with install state |
| `show version` | App, CLI, Python, node |

The CLI never prints a secret and no command accepts one as an argument — it
would land in shell history and in the process table.

### `diagnose` — active probes (any user)

| Command | What it finds |
|---|---|
| `diagnose all` | Every check below, folded into one exit code. The one to paste into a ticket |
| `diagnose service <svc>` | State, resolved `User=`, drop-ins, journal — and warns if a unit reverted to `User=root` |
| `diagnose database` | Connect, recovery state, TLS in use, lock waits |
| `diagnose python` | venv, `pip check`, `compileall`, **and the lazy-import smoke test** (see below) |
| `diagnose network` | Listening ports, `nginx -t`, local HTTPS probe |
| `diagnose certificate` | Expiry, live handshake, the renewal timer's last result |
| `diagnose peer` | Peer reachability, datasync key mode, datasync timer |
| `diagnose privilege` | Integrity of the CLI install and the sudo boundary |

**`diagnose python` exists because of a real incident.** In 1.2 and 1.2.1 a
stray `import os` above `from __future__ import annotations` made
`app/services/cert_service.py` a hard `SyntaxError`. Every caller imports that
module *inside a function*, so the app booted, `/healthz` returned 200 and 757
tests stayed green while the nightly certificate renewal died on both nodes. The
check therefore does two things nothing else does: `compileall` over `app/` and
`deploy/`, and an explicit import of the known lazily-imported modules
(`LAZY_MODULES` in `cmd_diagnose.py`). **When you add a module that is only
imported inside functions, add it to that list.**

### `execute` — change state (root)

| Command | Notes |
|---|---|
| `execute restart\|start\|stop <svc>` | Restart **verifies** `/healthz` afterwards; `systemctl` returning 0 has lied before (gunicorn active, workers crash-looping) |
| `execute reload nginx` | Runs `nginx -t` first and refuses on invalid config |
| `execute update code [<target>]` | **Queues** a git update for the privileged runner; warns if `satom-updater.path` is disabled (the queue would sit forever) |
| `execute update pip <pkg> <ver>` | Curated allowlist only. Node-local: the venv is not replicated |
| `execute update status [<id>]` | The runner's `steps[]` log (any user) |
| `execute reinstall venv` | Recreates `venv/` from `requirements.txt`, saving a `pip freeze` to `/root/` first and moving the old venv aside rather than deleting it |
| `execute reinstall units` | Re-copies the units **and re-pins `User=` via drop-in** |
| `execute reinstall cli` | Refreshes the root-owned copy of this CLI |
| `execute repair permissions` | Gives root-owned files in the app tree back to the service account |
| `execute cert renew` | Runs the renewal pass now instead of waiting for 03:30 |
| `execute alerts run [--dry-run]` | Evaluates the health checks now |
| `execute backup db` | `pg_dump -Fc` into `data/system_backups/` |
| `execute preflight` / `postflight` | The existing risky-change harness |
| `execute promote --yes` | Standby only; requires the explicit flag |

Two units are deliberately **not** operator-controllable:
`satom-updater.{path,service}` (it *is* the privileged root runner — a verb that
restarts it re-enters the privilege boundary sideways) and `postgresql`
(shared state; use `systemctl` and know why).

`execute reinstall units` writes a **drop-in**, never an edit to the unit file,
because `self_update_runner.py` re-copies `deploy/<unit>` on every code update.
That is exactly how the standby silently reverted to `User=root` after the
2026-07-26 deprivilege — a `sed` on a unit does not survive.

`execute repair permissions` exists because running anything as root inside
`/opt/satom` (pytest, a git command, a manual script) leaves root-owned files
in `.git/`, `data/jobs/` and `reports/`. The symptoms are indirect: git publish
keeps working, because git renames refs and only needs the directory, while some
other write fails quietly.

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

## Related

* [`privilege-model.md`](privilege-model.md) — accounts, sudoers, HA trust
* [`safeguards.md`](safeguards.md) §3 — the privilege boundary and how to verify it
* [`INSTALL.md`](INSTALL.md) §1.2, §5 — installer privilege and hardening
