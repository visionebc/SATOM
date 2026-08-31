# SATOM — Installation manual

**Product:** SATOM (System Automation & Task Orchestration Manager) — web console for
managing and automating FortiWeb, FortiADC and FortiAnalyzer.
**Manual version:** 1.2 · **Target:** Debian 12 (bookworm) amd64 as the reference;
also RHEL/Rocky/Alma 9, openSUSE and Arch (see §1.4).

This document is meant to be handed to the **systems team** together with the
privilege request. It contains everything the installer does, what it needs and how
to undo it.

---

## 1. Requirements

### 1.1 Minimum hardware (per node)

This table is a **floor** — what the installer needs to finish and what a lab
node can live on. It is NOT a sizing recommendation, and treating it as one is
how a node ends up with a full disk and a database in a crash loop:

| Resource | Minimum | Recommended (lab / PoC) |
|---|---|---|
| CPU | 2 vCPU | 4 vCPU |
| RAM | 2 GB | 4 GB |
| Disk | 15 GB | 20 GB |

**Size the node for your fleet with [`sizing.md`](sizing.html)**, which gives a
formula per resource and the measured constants behind it. The short version:

| Tier | Devices | Policies/device | vCPU | RAM | Disk |
|---|---|---|---|---|---|
| Lab / PoC | ≤ 10 | ≤ 100 | 2 | 4 GB | 20 GB |
| Small | ≤ 25 | ≤ 250 | 4 | 4 GB | 30 GB |
| Medium | ≤ 60 | ≤ 250 | 4 | 8 GB | 40 GB |
| Large | ≤ 110 | ≤ 750 | 8 | 8 GB | 120 GB |

Past ~110 devices a single node cannot finish its 3-minute collection window;
split the fleet across installations rather than growing the node
(`sizing.md` §2.1 and §3.1). Whatever tier you pick, keep
**`max(15 % of the volume, 3 GB)` free** — the margin PostgreSQL needs for a
checkpoint it cannot defer, and a bundle build needs before it prunes.

### 1.2 Software
- A distribution with **systemd as PID 1** (Alpine/musl is not supported).
  Reference: Debian 12 amd64. RHEL/Rocky/Alma 9, openSUSE and Arch are also
  supported — the installer detects the package manager.
- **An account with `sudo` scoped to the installer** for the duration of the
  installation window — **the root password does not have to be handed over**
  (§5 ships the `sudoers` rule ready to copy). The privileged steps still run
  as root, because creating accounts, installing packages and writing systemd
  units *is* root; what is avoided is an interactive, anonymous root session.
  Before anything else the installer checks that it **can really write** to
  `/opt`, `/etc`, `/etc/systemd/system`, `/var/log` and `/usr/local/sbin`: in an
  unprivileged container, or with `/` mounted read-only, being uid 0 is not
  enough.
- **The installed application does NOT run as root**: it uses a shell-less
  service account and a two-command `sudo` allowlist (§5 and
  [`privilege-model.md`](privilege-model.md)).
- Python **>= 3.10** (required by the pinned dependencies). If it is missing,
  the installer installs the distribution's own.
- **Online:** HTTPS egress to the distribution mirrors + PyPI + the product's
  git repository.
- **Offline:** no Internet egress at all — the bundle carries everything.

> Check the machine **without installing anything** with
> `sudo bash install-satom.sh --preflight` (see §1.6).

### 1.3 Network / ports
| Port | Use | Who must reach it |
|---|---|---|
| `<chosen port>` (default 443) | HTTPS web console | operators |
| 80/tcp | Redirect to HTTPS + ACME challenge (`/.well-known/acme-challenge/`) | operators and, if public ACME is used, the CA |
| 8443/tcp | Node-to-node health probes (TLS + shared identity key) | the other node (cluster only) |
| 5432/tcp | Postgres replication (cluster only, TLS `verify-ca` enforced) | the other node |
| 22/tcp | `data/` sync over rsync/SSH (cluster only) | the other node |
| egress to the Fortinet devices | management HTTPS/SSH | this node → appliances |

Ports 80 and 8443 are **fixed**; the console port is chosen at installation
time. The preflight warns if any of them is already taken, and by which process.

### 1.4 Packages that get installed (for prior approval by the systems team)

The installer **compiles nothing** and only uses the distribution's official
repositories. This is the complete and exact list — the same content as the
script's `REQUIRED_PKGS` lists:

| Concept | Debian / Ubuntu (`apt`) | RHEL / Rocky / Alma 9 (`dnf`,`yum`) | openSUSE (`zypper`) | Arch (`pacman`) | What for |
|---|---|---|---|---|---|
| Python >= 3.10 | `python3` `python3-venv` `python3-pip` | `python3.11` `python3.11-pip` | `python311` `python311-pip` | `python` `python-pip` | run the app in its own venv |
| Database | `postgresql` | `postgresql-server` `postgresql` | `postgresql-server` `postgresql` | `postgresql` | source of truth (database `satom`) |
| Web server | `nginx` | `nginx` | `nginx` | `nginx` | TLS and reverse proxy to gunicorn |
| Synchronisation | `rsync` | `rsync` | `rsync` | `rsync` | copy of `data/` between nodes |
| Cryptography | `openssl` `ca-certificates` | `openssl` `ca-certificates` | `openssl` `ca-certificates` | `openssl` `ca-certificates` | internal PKI, CSR, TLS validation |
| Downloads | `curl` | `curl` | `curl` | `curl` | ACME client, HTTP probes |
| Privileges | `sudo` | `sudo` | `sudo` | `sudo` | the runtime's **two**-command allowlist (§5) |
| Code — **ONLINE** only | `git` | `git` | `git` | `git` | clone the production repository |
| SSH — **CLUSTER** only | `openssh-client` `openssh-server` | `openssh-clients` `openssh-server` | `openssh` | `openssh` | rsync/SSH channel between nodes |

Notes the systems team usually asks about:

- **In OFFLINE mode none of them is downloaded**: the bundle carries the full
  dependency closure (`.deb`, or a local `dnf` repository for EL9) and the
  `wheels`.
- Python dependencies are **not installed system-wide**: they live in
  `/opt/satom/venv`. `pip` never touches the system Python.
- A **standalone node does not get `openssh-server`**: it is only installed if
  you pick cluster mode, because the standby syncs `data/` by pulling from the
  primary over SSH.
- **`lego`** (the ACME client, optional) is not a distribution package: it is a
  static binary that goes to `/usr/local/bin/lego`, with a verified `sha256`, or
  is copied from `bundle/lego/` in offline mode.
- On uninstall **the packages are deliberately left installed** (§6).

### 1.5 What the base image must already provide (the installer does NOT install it)

If any of these is missing, the image is too minimal and the preflight names it
instead of dying halfway through the installation:

| Utility | Usual package | Use |
|---|---|---|
| `useradd` `usermod` `passwd` | `shadow` / `passwd` | create the shell-less service account |
| `runuser` | `util-linux` | operations as `postgres` and as the service account |
| `install` `df` `tar` | `coreutils`, `tar` | file deployment and free-space check |
| `awk` `sed` `grep` `hostname` | `gawk`/`busybox`, `sed`, `grep`, `hostname` | installer scripting |
| `ss` *(optional)* | `iproute2` | check for busy ports; without it you only get a warning |
| systemd as **PID 1** | — | the whole service lifecycle |

### 1.5b Per-distribution notes (validated on real installations)

**openSUSE Leap 15.6 / SLES 15** — the `zypper` family works, with two caveats
that are NOT SATOM's but the base image's:

- **An outdated `libexpat` breaks venv creation.** The `python311` on the
  current mirrors is built against `libexpat` 2.7.x; a template image ships
  2.4.4 and `zypper install python311` **does not upgrade a dependency that is
  already installed**. Symptom:
  `pyexpat.cpython-311.so: undefined symbol: XML_SetAllocTrackerActivationThreshold`
  and `python3.11 -m venv` aborting in `ensurepip`. Fix before installing:
  ```bash
  sudo zypper --non-interactive update libexpat1
  ```
- **There is no `/usr/bin/python3`.** The binary is `python3.11`. The installer
  resolves it with `pick_python()` and uses `$PYBIN` everywhere; it only matters
  if you run fragments of this manual by hand.
- **The vhost goes to `/etc/nginx/vhosts.d/`**, not to `conf.d/`: openSUSE's
  factory `nginx.conf` includes `conf.d/*.conf` **twice** (anything left there
  is parsed in duplicate) and ships its own `server` on port 80 that collides
  with SATOM's `default_server`. The installer picks `vhosts.d` automatically
  and neutralises the factory block.
- **`sshd` is not active** on the openSUSE LXC template. The installer enables
  it itself in **cluster** mode (the standby *pulls* `data/` over SSH and
  without it there is no file replication at all); in **standalone** it does not
  touch it, so if the machine is administered over SSH you have to enable it by
  hand.

**Service account:** openSUSE ships `USERGROUPS_ENAB no` in `login.defs`, so a
plain `useradd --system` would leave the account in the shared `users` group
(gid 100) alongside the interactive users. The installer passes `--user-group`
to force a private group on every family.

**PostgreSQL:** openSUSE's default `pg_hba.conf` uses **`ident`** for
`127.0.0.1/32` (Debian uses `scram-sha-256`). The installer inserts its own rule
**at the top** of the file — `pg_hba` is *first-match*, so appending it at the
end would achieve nothing.

### 1.6 Checking beforehand without installing anything (`--preflight`)

```bash
sudo bash install-satom.sh --preflight     # alias: --check
```

It asks nothing, modifies nothing and **returns 0 if the machine is ready**, or
1 with the complete list of blockers. It accumulates every problem and reports
them together, so that a change-window request carries the whole list rather
than the first failure. It checks:

1. **Real privileges** — uid 0 *and* effective write access to `/opt`, `/etc`,
   `/etc/systemd/system`, `/var/log`, `/usr/local/sbin`.
2. **systemd as PID 1** (having the `systemctl` binary is not enough).
3. **Package manager** supported, and online/offline mode detected.
4. **Base utilities** from §1.5.
5. **Python >= 3.10** present, or a warning that it will be installed.
6. **Disk and memory** — blocks below 4 GB free in `/opt`, warns below the
   recommended 15 GB or below 2 GB of RAM.
7. **Previous installation** — if `satom.service` is **active**, that is a
   **blocker**: reinstalling on top rewrites `.env` and the units. To upgrade,
   use the *Software Update* page; to force it, `SATOM_ALLOW_REINSTALL=1`.
8. **Ports 80 and 8443** free (or who is holding them).
9. **Clock synchronised by NTP** — with drift, TLS, the ACME challenge and
   `verify-ca` replication all fail.
10. **Internet egress** in online mode (PyPI and the code repository). No PyPI
    is a blocker; use the offline bundle instead.
11. **SELinux** (informational; the installer applies booleans and ports).

In cluster mode, a second check runs once the mode is chosen: SSH client
(`ssh`, `ssh-keygen`, `ssh-keyscan`) and `rsync` available, and whether the SSH
server is installed and active — mandatory on the **primary**.

---

## 2. Ways to install

**Every path below ends with the same thing: the console on `https://`, and
plain `http://` answering `301` to it.** No path leaves the choice to the
operator, and none of them needs a certificate to be supplied first — the
install issues one, and you replace it whenever you are ready
(`deploy/tls-bootstrap.sh import-cert`, which a later re-run will not overwrite).

Two details of that redirect are deliberate:

- It is scoped to `location /`, so `/.well-known/acme-challenge/` still answers
  over plain `:80`. A server-level `return` would run before location selection
  and swallow the ACME challenge — the certificate would work for months and
  then fail to renew.
- The redirect listener claims `default_server`. nginx awards the unnamed
  default to the first `:80` block in parse order, which **between files is
  alphabetical**, so a packaged `default.conf` or Debian's enabled default site
  would otherwise keep `:80` and answer the welcome page while `:443` works
  perfectly. Each installer removes those and, if some *other* vhost already
  claims the default, rewrites its own without the claim rather than failing.

### 2.1 Online (with network)
```bash
sudo bash install-satom.sh
```
Downloads packages from the mirrors and clones the **public source of record**,
`https://github.com/visionebc/SATOM.git` — configurable at the prompt.

> **The default clone needs no credentials, and that is the point.** Until
> 2026-08-30 this document named an internal mirror that only resolved inside
> one company's network, so an unattended install anywhere else hung on a clone
> it could never complete. That mirror has been retired and **no longer
> exists**: a runbook that still names it sends an operator to a `404` in the
> middle of a maintenance window. The installer's own default has pointed at
> the public repository since before the retirement — it was this page that was
> wrong, not the code.
>
> **If you point the prompt somewhere else** — an air-gapped copy, or a private
> development repository — `git clone` will ask for credentials, and an
> unattended run has to supply them in the URL
> (`https://<user>:<token>@<host>/...`). A `401` at this point stops the
> installation before anything is touched.
> **Wipe the credential from the checkout when you are done:**
> `git -C /opt/satom remote set-url origin <url-without-the-token>`

### 2.2 Offline (no network)
```bash
# Debian 12
tar xzf satom-offline-<ver>-debian12-amd64.tar.gz
# RHEL / Rocky / AlmaLinux 9
tar xzf satom-offline-<ver>-rhel9-x86_64.tar.gz
# openSUSE Leap 15 / SLES 15
tar xzf satom-offline-<ver>-suse15-x86_64.tar.gz

cd satom-installer
sudo bash install-satom.sh        # detects bundle/ and never touches the network
```
There is a bundle for **Debian 12**, **RHEL/Rocky/Alma 9** and, since **1.3**,
**openSUSE Leap 15 / SLES 15**. **Arch only has an ONLINE path** — there the
installer needs egress to the distribution mirrors and to PyPI.

There is one bundle PER distribution FAMILY — the installer rejects a bundle
from the wrong family with a clear message:
- **Debian 12**: full `.deb` dependency closure + `wheels/` + `app.tar.gz`.
- **RHEL 9**: `bundle/rpms/` is a local dnf repository (with metadata) — dnf
  resolves only what the machine actually needs; it includes `python3.11` (the
  app's pins require Python >= 3.10 and the system python3 on EL9 is 3.9) and
  the matching `wheels/` (cp311).
- **openSUSE / SLES 15**: `bundle/rpms-suse/` — also `.rpm`, also with metadata,
  but **a deliberately different directory**. The two RPM bundles are not
  interchangeable: the package names differ (`python311` versus `python3.11`),
  the base library versions differ, and zypper and dnf do not read repositories
  the same way. Keeping them apart turns "wrong bundle" into an explicit error
  before anything is touched, instead of a dependency resolution that blows up
  halfway through the installation. On the target, zypper is given its own
  repository directory (`--reposd-dir`) containing only the bundle: it resolves
  with no network, without touching the system repositories, and without
  leaving a repository registered behind.

**What the bundle carries**, besides the dependency closure: the complete
application tree, the manuals under `docs/` — readable without a network from
the console with `satom show docs`, because the application **no longer serves
documentation**: the published copy lives on the public site, which an isolated
management network deliberately cannot reach — and the ACME client `lego` in
`bundle/lego/`. Since **1.2** the bundles also include `sudo` and `openssh-*`:
without them a minimal image with no network failed halfway through the
installation, with the service account already created. Bundles 1.1 and earlier
carried neither those nor `lego` in the RHEL variant.

The bundle is a **snapshot of the repository at build time**: the guards it
contains are the ones that existed then. To know exactly which version you have
before installing:

```bash
tar xzOf satom-offline-<ver>-*.tar.gz --wildcards '*/bundle/app.tar.gz' | tar xzO VERSION
```

Verify integrity with the `.sha256` that accompanies each tarball.
The bundles are produced by `installers/build-offline-bundle.sh` (on a Debian 12
with network), `installers/build-offline-bundle-rhel.sh` (on a `rockylinux:9`
machine or container with network) and `installers/build-offline-bundle-suse.sh`
(on `opensuse/leap:15.6` with network).

The SUSE builder downloads against an **empty root** (`zypper --root`). zypper
only fetches what is missing on the machine it runs on, so a normal
`--download-only` would produce a bundle that only works on a target identical
to the build host. With an empty root zypper believes nothing is installed and
resolves the full closure — the equivalent of `dnf download --resolve
--alldeps`. That root needs a copy of `/etc/os-release`: the `.repo` files use
`$releasever` and zypper derives it from the `os-release` **of the root**.
Without it the URLs come out malformed, the refresh appears to work, and every
package is reported as *not found in package names* — a failure that reads as
"this distribution does not have python311".

### 2.3 Containers (Docker)
```bash
cd deploy/docker
cp env.example .env
./satom-docker.sh gen-secrets     # real SECRET_KEY / FERNET_KEY / passwords
./satom-docker.sh build satom:<ver>
./satom-docker.sh up
```
A third shape, for a host that runs containers rather than services. The
application, PostgreSQL, Redis and the metrics store come up as one stack.
`web`, `scheduler` and `cron` are **the same image**, selected by `SATOM_ROLE`:
three images would let the scheduler run code the web worker does not have, and
that difference is invisible until a scheduled action behaves differently from
the same action fired by hand.

**It is not the full install in a box, and the difference is deliberate.** A
container administers no host, so this shape **renounces** four capabilities
instead of shipping them broken:

| capability | what to do instead |
|---|---|
| **Software Update & HA** (in-place self-update) | deploy a new image tag and recreate the stack |
| **Service control** (start/stop/restart of node units) | `docker compose restart <service>` |
| **Certificate activation** | the stack serves TLS already; swap the certificate with `deploy/tls-bootstrap.sh import-cert` and restart `proxy` |
| **systemd unit health** | read container health from the container engine |

Each of the four refuses with a message naming its alternative; none of them
fails silently, and the refusals are asserted in `tests/test_container_runtime.py`
rather than promised here. Everything else — device management, probes and
monitors, the metrics store, backups and restore, the source of truth, reports,
the CLI, RBAC and SSO — behaves exactly as on a host install.
**If you need in-place self-update, install on a host.**

**TLS is provisioned by the stack itself**, like every other install shape: the
`proxy` service terminates HTTPS on `:443` with a certificate issued at first
start and redirects `:80` to it, and the application container publishes no
port. The certificate is self-signed by a per-node internal CA, so the browser
warns until you replace it — set `SATOM_SERVED_NAMES` in `.env` first, so the
SAN covers the name operators actually type.

The runtime is **declared by the image** (`SATOM_RUNTIME=container`), never
detected. `system_health.is_container()` returns true on an LXC *host* install
as well, so keying these capabilities off a `/proc` probe would strip the
updater from the nodes that most need it. Only the exact value `container`
selects the container runtime — a typo means `host`, so a stray environment
variable can never quietly disarm an appliance.

Production runs two nodes: a primary, and a **standby** whose PostgreSQL is a
streaming replica and whose scheduler idles until the database is promoted (two
nodes must never both fire the same action — a duplicated firmware upgrade is a
double flash). A node with no route to a registry is served the same way the
offline bundles are, as a file:

```bash
./satom-docker.sh export satom:<ver> /tmp/satom-<ver>.tar.gz
# copy the tarball AND its .sha256, then on the target
./satom-docker.sh import /tmp/satom-<ver>.tar.gz
```

`import` verifies the checksum **before** loading, because a truncated transfer
otherwise surfaces as a layer error inside `docker load` — which reads like a
corrupt image rather than a short file.

**Full page: [`docker.md`](docker.md)** — the stack service by service, the
development single node, the production cluster and its failover rules, offline
image delivery, and what a backup has to cover. (A `pg_dump` alone is not a
backup: the source-of-truth index lives in PostgreSQL while its blobs live in
the data volume, so restoring only the database leaves rows pointing at
nothing.)

---

## 3. What the installer asks (in this order)

**Step 0 — preflight.** Before the first question it verifies that the machine
meets everything in §1.6. If anything fails, it aborts without having touched
a thing.

1. **The machine's IP** — auto-detected; used in the TLS certificate and in the
   cluster configuration.
2. **HTTPS port** of the console (default 443).
3. **Standalone or cluster?**
4. If cluster: **primary or secondary?**
   - *secondary*: asks you to **paste the join key** generated by the primary
     (format `SATOMJOIN1.…`; the legacy `OFMJOIN1.…` is still accepted). It is
     validated BEFORE anything gets installed.
   - *primary*: asks for the intended IP of the secondary (Enter = allow the
     whole subnet).
5. **Password for the console's `admin` user** (standalone/primary only; the
   secondary inherits it through database replication).
6. Summary and confirmation. **Up to this point nothing on the system has been
   modified.**

It then runs, in order: packages → code+venv → PostgreSQL → PKI/certificates →
configuration+services → health check.

- If a package is missing, **it installs it**; if there is an old version
  (e.g. Python < 3.9), **it warns that it will upgrade it** to the
  repository's before touching it.

---

## 4. Cluster mode — how joining works

1. Install the **primary** (`cluster` → `primary`). At the end it prints the
   **JOIN KEY** (`SATOMJOIN1.` + a base64 blob). The legacy `OFMJOIN1.` prefix
   is still accepted on the secondary.
2. Install the **secondary** on the other machine, choose `cluster` →
   `secondary` and **paste the key**. Automatically it:
   - inherits the application's encryption keys (`FERNET_KEY`/`SECRET_KEY`);
   - receives the cluster's **internal CA** and **issues its OWN certificate
     locally** (the node's private key never travels over the network);
   - clones the database with `pg_basebackup` and becomes a **streaming
     replica** with TLS `verify-ca` + a client certificate;
   - **generates its own SSH key locally** for the `data/` synchronisation and
     prints its **public** half together with the exact command to run on the
     primary to authorise it:

     ```bash
     sudo ./install-satom.sh --authorize-peer <standby-ip> "ssh-ed25519 AAAA..."
     ```

     Until you run that command, Postgres IS already replicating but the
     `data/` synchronisation fails. That is on purpose: the private key never
     travels, so somebody has to approve the public one;
   - its scheduler stays **on hold**: it only activates if the node is promoted
     (`deploy/satom-promote.sh`), so that two nodes never fire actions at the
     same time.

> ⚠️ **The join key is a high-value secret**: it contains the internal CA's
> private key, `FERNET_KEY`, `SECRET_KEY` and the database passwords. Move it
> over a secure channel, use it once and delete it.
>
> Since v1.2 it **no longer contains the datasync private key** — the secondary
> generates its own and only its public half is authorised on the primary,
> constrained with `from=`, `restrict` and a `command=` that only allows a
> **read-only** rsync of `data/`. That key used to grant a root shell from any
> IP.

---

## 5. Permissions to request from the systems team

There are **two distinct accounts** in play, and it pays not to mix them up:

| | account | when | privilege |
|---|---|---|---|
| **Installation** | `satominstall` (named, the operator's) | only the installation window, ~10–20 min per node | `sudo` to **one binary at a fixed path** |
| **Runtime** | `satom` (service account, no shell) | permanent | `sudo` to **two commands** (`nginx -t`, `systemctl reload nginx`) |

**Option A (recommended): a named installer account with a `sudoers` rule.**
The root password is handed to nobody and there is a trace of who installed and
when. The file lives in the repository
([`deploy/satom-installer.sudoers`](../deploy/satom-installer.sudoers)) and the
installer itself emits it, so it can be handed to the systems team without
sending them the whole repository:

```bash
bash install-satom.sh --print-sudoers            # default user: satominstall
bash install-satom.sh --print-sudoers opsuser    # or whatever name the systems team uses
```

(`--print-sudoers` does not require root and touches nothing.)

```bash
useradd -m -s /bin/bash satominstall
install -d -m 0755 /opt/staging
install -m 0755 install-satom.sh /opt/staging/install-satom.sh
chown root:root /opt/staging/install-satom.sh     # the operator CANNOT edit it
install -m 0440 deploy/satom-installer.sudoers /etc/sudoers.d/satom-installer
visudo -c                                          # validate before logging out
```

```
Cmnd_Alias SATOM_INSTALL = /usr/bin/bash /opt/staging/install-satom.sh, \
                           /usr/bin/bash /opt/staging/install-satom.sh --preflight, \
                           /usr/bin/bash /opt/staging/install-satom.sh --check, \
                           /usr/bin/bash /opt/staging/install-satom.sh --authorize-peer *

satominstall ALL=(root) NOPASSWD: SATOM_INSTALL
```

Then, as `satominstall` and without ever being root:
```bash
sudo /usr/bin/bash /opt/staging/install-satom.sh --preflight   # touches nothing
sudo /usr/bin/bash /opt/staging/install-satom.sh               # installs
```

> ⚠️ **The path has to be fixed and the file has to be owned by `root`.** If the
> operator could write to `/opt/staging/install-satom.sh`, the rule would be
> equivalent to `NOPASSWD: ALL`. Remove `/etc/sudoers.d/satom-installer` when
> the installation window closes.

**Option B: a full root/sudo session**, if the systems team would rather not
manage the rule:
```bash
sudo bash install-satom.sh
```

### Why the installer cannot run with any less than this

There is no honest subset: creating accounts, installing distribution packages,
writing systemd units and reconfiguring Postgres and nginx **are** root. A rule
granting `apt-get install` would be equivalent to root anyway — a `.deb` runs
its own maintainer scripts as root. The real risk reduction lies in (1) scoping
the privilege to **one specific binary**, (2) making it **temporary**, and (3)
making sure what keeps running afterwards is **not** root. That is exactly what
Option A and the runtime model below do.

These are the families of commands the installer runs as root:

```
apt-get update / apt-get install / dpkg -i          (packaging)
git clone | tar -x                                   (code in /opt/satom)
python3 -m venv | pip install                        (inside /opt/satom)
runuser -u postgres -- psql|createdb|pg_basebackup   (database)
openssl req|x509 | ssh-keygen                        (certificates and keys)
copy into /etc/systemd/system + systemctl daemon-reload/enable/start
write /etc/nginx/sites-available/satom.conf + nginx -t + reload
write /etc/postgresql/<v>/main/conf.d + pg_hba.conf (cluster only)
```

Auditing the installation window: `journalctl _COMM=sudo` records every
invocation with the named user, and the installer always writes
`/var/log/satom-install.log`.

### What the application needs at RUNTIME (the `satom` account)

**The application does NOT run as root.** The installer creates the service
account, gives it ownership of the tree and sets `User=` in a systemd
**drop-in**, so there is no path by which the web process ends up being root.

Full detail and rationale in [`privilege-model.md`](privilege-model.md).
Summary:

* A service account with no interactive shell (`satom` by default; a legacy
  installation may keep `satom` via `SATOM_APP_USER`). It owns `/opt/satom` and
  `/var/log/satom`.
* `sudo` scoped to **exactly two commands**, in `/etc/sudoers.d/satom`:

  ```
  Cmnd_Alias SATOM_CERT_RELOAD = /usr/sbin/nginx -t, /usr/bin/systemctl reload nginx
  satom ALL=(root) NOPASSWD: SATOM_CERT_RELOAD
  ```

  Those are what the certificate manager needs to validate and activate a new
  cert. **Package installation and generic `systemctl` are NOT granted**: both
  are equivalent to root (a `.deb` runs its own scripts as root), not a subset
  of it.
* Everything that does require root — installing units, `pip`, restarting the
  service itself — goes through `satom-updater.service`, a oneshot runner that
  runs as root, is triggered by `satom-updater.path` and **re-validates** every
  request against its own allowlist.
* In a cluster: the `fm_repl` replication role, and node-to-node SSH **from
  service account to service account** (no longer root→root) with a forced
  command.

To migrate a node installed with v1.1 or earlier, **one node at a time and the
standby first**:

```bash
sudo bash /opt/satom/deploy/migrate-deprivilege.sh
```

### The OPERATOR account — the console CLI (`satom`)

SATOM installs `/usr/local/sbin/satom`, a console CLI to diagnose, control and
**rebuild** the node when the web interface will not start (full reference in
[`cli.md`](cli.md)). This is the system's third account and it has to be
requested explicitly, because it is different from the previous two:

| account | lives | privilege |
|---|---|---|
| installer (`satominstall`) | only during the installation | `sudo` to **one** binary, temporary |
| service (`satom`) | permanent, it is the one running the app | `sudo` to **two** nginx commands |
| **operator (a person)** | permanent, a human at the console | `sudo` to **`/usr/local/sbin/satom`** |

**The rule to request** (`/etc/sudoers.d/satom-operator`, `0440`, validated with
`visudo -cf`). The CLI prints it itself without needing privilege, so that it
can be generated from the account that does not have it yet:

```bash
satom show sudoers <account>
```

```
<account> ALL=(root) /usr/local/sbin/satom
```

**What it grants:** service control, reinstallation of the venv and of the
units, queued code and package updates, `promote`, certificate operations.
**What it does NOT grant:** a shell — the CLI has no "run an arbitrary command"
verb at all, and package changes go through the curated allowlist, never
through a free-form `pip install`.

**Without that rule the CLI is still useful:** `get`, `show` and `diagnose`
work for **any** user and are the half that rescues an operator standing in
front of a dead node. Only `execute` requires root, and it refuses with an
explanation and the full command to repeat with `sudo` — never with a
traceback.

#### Two things you must NOT do

1. **Do not grant the CLI to the service account.** A
   `NOPASSWD: /usr/local/sbin/satom` for `satom`/`satom` is equivalent to
   `NOPASSWD: ALL` and would turn a compromised web worker into root, undoing
   the whole privilege model. `satom diagnose privilege` fails in red if it
   finds that line.
2. **Do not move the binary or relax its permissions.** The path has to be
   fixed and the target `root:root 0755`; the code lives in
   `/usr/local/lib/satom-cli/` (also `root:root`) and is **never** run from
   `/opt/satom`, because that tree is writable by the service account. It is
   the same trap as the installer-account rule (above, in this very section):
   if the target of `sudo` is writable by whoever invokes it, the rule is
   `NOPASSWD: ALL`.

Check after installing:

```bash
satom diagnose privilege     # integrity of the binary and of the sudo boundary
satom diagnose all           # the whole node, a single exit code
```

---

## 6. After installing

- Console: `https://<IP>:<port>/` — user `admin` + the chosen password.
- Health: `curl -k https://<IP>:<port>/healthz` → `200`.
- Services: `systemctl status satom satom-scheduler`.
- Logs: `/var/log/satom/` and `journalctl -u satom`.

### Mandatory post-installation hardening
1. **Withdraw the installation permission**: `rm /etc/sudoers.d/satom-installer`
   (and the copy of the script under `/opt/staging`). If a temporary root
   password was handed over instead of using Option A, change it.
2. Disable SSH password authentication (`PasswordAuthentication no`) and leave
   keys only.
3. Delete the join key from any note or chat.
4. Restrict the console port by firewall to the operations networks.
5. Check that the privilege model actually landed:

   ```bash
   # the web process must NOT be root
   ps -o user= -p $(systemctl show satom.service -p MainPID --value)

   # the allowlist permits two things and nothing else
   sudo -u satom sudo -n nginx -t                  # allowed
   sudo -u satom sudo -n apt-get install hello     # MUST fail
   sudo -u satom sudo -n systemctl restart satom   # MUST fail
   ```
6. **Check that the model survives an update.** The service account is set in a
   **drop-in** (`/etc/systemd/system/satom.service.d/10-app-user.conf`) exactly
   because the templates under `deploy/` declare `User=root` and every update
   copies them back. Detail in
   [`privilege-model.md`](privilege-model.md) §5b.

   ```bash
   systemctl show satom.service -p User --value      # must be the service account
   cat /etc/systemd/system/satom.service.d/10-app-user.conf
   ```

7. In a cluster, check that the peer key does not grant a shell:

   ```bash
   # from the standby — must be REJECTED
   sudo -u satom ssh -i /opt/satom/.ssh/id_ha_rsync satom@<primary-ip> id
   ```

### The day-one check, in a single command

```bash
satom diagnose install      # is it ARMED, or merely installed?
satom diagnose all          # all 24 checks, one single exit code
```

`diagnose install` separates two things that always get confused: the
**infrastructure** (units, privileged runner, `User=` drop-ins, sudoers,
certificate, venv, CLI) and the **protections**, which are data and which the
installer does not create. The latter are armed with:

```bash
sudo satom execute seed actions          # prints the plan, changes nothing
sudo satom execute seed actions --yes    # applies it
```

It is idempotent and **never touches an existing row**: the operator's edit
wins, this only fills the gaps. If something fails later on, every recovery
procedure lives inside the binary itself — `satom show runbook` lists them, and
they work with no web interface and no Internet egress.

### Protections you must arm (they do not ship enabled)

The guards' code travels in the installer and is live by the mere fact of
existing: the anti-`reset --hard` history guard, the pip allowlist, the drop-in
that pins the service account, the forced command on the peer key, the
certificate rollback. Online or offline installation makes no difference.

What is **not** armed out of the box is everything that lives in the database,
because the seeds are INSERT-ONLY and the operator's edit wins. A fresh
installation has **no scheduled action and no alert recipient**: the product
works, computes its signals and notifies nobody. It has to be armed by hand:

1. **Alerts** — Settings → Alerts: enable them, set the SMTP recipient and
   review the thresholds. Among them `git_ahead_max_hours` (6 h): it warns when
   a commit has gone too long without being pushed, which is the exact
   signature of a git server that is down — a case that previously fired
   nothing.
2. **Scheduled actions** — Automation → Scheduled actions. None is seeded. The
   recommended minimum set:

   | Action | Suggested cadence | What for |
   |---|---|---|
   | `device_sync` | hourly | refreshes each appliance's SoT under `data/reports/` + `data/sot/` |
   | `device_inspect` | 02:45 | deep nightly inspection; its result is versioned in `data/sot/` too |
   | `system_backup` | daily | database dump (bundle) |
   | `git_bundle` | 03:15 | repository backup (`git bundle --all`) |

   Without `git_bundle` none of the repository copies exists; without
   `device_sync` the devices' SoT stays frozen at the day of the installation.
3. **External backup server** — Settings → Backup Server. Without it, every copy
   lives inside the same pair of nodes. (Retention of the configuration SoT is a
   separate panel, Settings → Configuration SoT; the two were one tab until
   2026-08-29 and only one of them is a source of truth.)
4. **Update queue** — check that `satom-updater.path` is armed **on both
   nodes**: if the `.path` is stopped, queued updates stay `queued` forever.

   > There used to be an instruction here to arm the hourly git publisher for
   > the SoT. It was withdrawn on 2026-08-05 along with the mechanism itself:
   > the device SoT lives in `data/sot/`, is replicated by `satom-ha-datasync`
   > and travels in the backup bundles. Arming it on a new node turned green a
   > unit that published nothing.

How to verify they ended up armed, command by command:
[`safeguards.md`](safeguards.md) § *Verifying the guards are armed*.

### Uninstall / revert
```bash
systemctl disable --now satom satom-scheduler \
  satom-updater.path satom-cert-renew.timer satom-ha-datasync.timer 2>/dev/null
rm -f /etc/systemd/system/satom* /etc/systemd/system/fm-*
rm -f /etc/nginx/sites-enabled/satom.conf /etc/nginx/sites-available/satom.conf
systemctl daemon-reload && systemctl reload nginx
runuser -u postgres -- dropdb satom; runuser -u postgres -- dropuser satom
rm -rf /opt/satom /var/log/satom
```
The system packages (postgres, nginx…) are deliberately left installed; if they
have to be removed, that is the systems team's call (`apt-get remove`).

---

## 7. Support

- Installation log: `/var/log/satom-install.log` (always written).
- Public repository — source of record, tagged releases, installer and offline
  bundles: **`github.com/visionebc/SATOM`**. Development happens in a private
  repository that is never installed from directly; the internal `satom-prod`
  mirror that used to sit between the two was **retired on 2026-08-30** and is
  not a fallback.
- The application catalogue (apps.example.net → SATOM → web platform)
  publishes this installer and the offline bundle, and has the
  **Sync Prod with Git/GitHub** buttons to promote development code to
  production.
