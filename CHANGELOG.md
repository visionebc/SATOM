# Changelog

All notable changes to SATOM are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/). This is a public, open-source
project — see [NOTICE](NOTICE) for the trademark disclaimer.

## [1.2.1] - 2026-07-27

Documentation release. No application code changed; the offline bundles were
rebuilt so that the shipped tree matches the documentation set.

### Added
- **`docs/safeguards.md`** — single catalog of every protection in the product:
  what it prevents, where it lives, and **how to verify it is armed**. Covers
  git history, self-update and dependencies, the privilege boundary, node-to-node
  correctness, appliance writes, certificates, external files, sessions and
  alerts. Ends with the limits that are deliberately not covered.
- **`docs/INSTALL.md` §6 "Protections you must arm"** — scheduled actions,
  alert recipients and per-node timers are **database state**, not code, so a
  fresh install starts with none of them. The minimum set is now spelled out
  (`device_sync`, `device_inspect`, `system_backup`, `git_bundle`).
- **`docs/INSTALL.md` §2.2** — what the offline bundle actually contains
  (manuals readable from the console without a network, the ACME client, and
  since 1.2 `sudo` / `openssh-*`), plus how to read a bundle's VERSION before
  installing it.
- **`docs/safeguards.md` §10 "Fresh installs"** — which guards arrive armed by
  code versus which are database state the operator must create.
- Public site: `site/safeguards.html` (linked from the nav and footer of every
  page) and the matching notes on `site/install.html`.

### Changed
- In-app **Documentation** index now curates a title, order and description for
  all 18 manuals; half of them previously fell through to an auto-generated
  title with no description, so they existed but were not discoverable.
- **Rule recorded in `docs/overview.md`**: a new safeguard lands in
  `docs/safeguards.md` in the same commit that introduces it.

### Fixed
- Offline bundle checksums used an absolute path, so `sha256sum -c` failed in
  the directory the file was downloaded to. Now basename-only, as the RHEL
  builder already did.
- RHEL offline bundle: the ACME client (`lego`) was staged inside the wrong
  branch of the builder, so the documented build path (a `rockylinux:9`
  container with no `.git`) produced a bundle with no ACME support.

### Known gap closed
- The 1.2 bundles were built three minutes before the safeguards catalog was
  committed, so they shipped the guards but not the document describing them.
  1.2.1 exists to close exactly that.

## [1.2] - 2026-07-27

### Changed — privilege model (action required for existing installs)
- **The application no longer runs as root.** Web, scheduler, reconciler,
  alerts, cert-renew, git-publish and HA datasync all run as an unprivileged
  service account. Only the update runner (`satom-updater`) stays root, by
  design — it installs units, runs pip and restarts services.
- The account is pinned with a systemd **drop-in**
  (`/etc/systemd/system/<unit>.d/10-app-user.conf`), not by editing the unit:
  the self-update runner recopies unit templates on every update, so an edited
  unit silently reverted to root.
- `sudo` is limited to exactly two commands (`nginx -t`, `systemctl reload
  nginx`). Package-manager and unrestricted `systemctl` rules were rejected on
  purpose: a `.deb` runs its maintainer scripts as root, so permission to
  install any package **is** root.
- Existing installs: `sudo bash deploy/migrate-deprivilege.sh`, one node at a
  time, standby first. Rollback material is written to
  `/root/satom-units.pre-deprivilege-<ts>/`.
- HA trust was inverted: the secondary now generates its own key pair, the
  private key never travels in the join key, and the authorized key is pinned
  with `from=`, `restrict` and a forced command that can only serve
  `rsync --sender` over the data directory.

### Added
- **ACME / Let's Encrypt certificate issuance** with a DNS-provider catalog
  (30 providers seeded as data, editable by the operator) and per-provider
  credentials encrypted at rest. The signer receives a minimal, purpose-built
  environment — it does not inherit the application's secrets.
- **Certificate renewal journal** and a Renewals page: every attempt is
  recorded with its outcome and error text, per node, and a failed renewal is
  now its own alert signal instead of surfacing only as an expiry warning.
- **Repository backup and git-outage survival**: `git bundle --all` artifacts
  across four failure domains (node, standby, external backup server,
  download), a guard that parks unpushed commits on `refs/backup/*` before
  `git reset --hard` — aborting the update if it cannot — and a
  `git.ahead_unpushed` alert keyed on the **age** of the oldest unpushed
  commit. Docs: `docs/git-backup-and-outage.md`.
- **Installer preflight** (`install-satom.sh --preflight`): every blocker is
  collected and reported together before anything is touched — effective write
  access, systemd, package manager, Python >= 3.10, disk and memory, an
  existing installation, port conflicts, clock and outbound reachability.
- Fleet map device card now shows the **real interfaces** harvested from the
  devices, with MAC addresses fetched on demand over read-only CLI and
  per-port role badges derived from cached configuration.
- Product renamed to **SATOM — System Automation & Task Orchestration
  Manager**. Vendor names (FortiWeb, FortiADC, FortiAnalyzer) are untouched:
  the product manages those appliances and has to name them.

### Fixed
- **Scheduler and git-publish were silently dead** after the privilege drop:
  both guard scripts used `runuser`, which only works as root. The scheduler
  took the standby branch on every loop, so no scheduled action fired; git-publish
  failed and still exited 0, so systemd reported success while the git copy of
  the source of truth stopped being published. Both now use a shared role probe
  that works at any privilege level, and git-publish exits non-zero on failure.
- Offline bundles did not ship `sudo` or `openssh-*`. On a minimal image the
  preflight passed and the install died at the sudoers step, after creating the
  service account and taking ownership of the tree.
- Seven CVEs flagged by `pip-audit` (setuptools, markdown, python-dotenv);
  `setuptools` was unpinned, so a fresh install reintroduced the vulnerable
  version.
- Three bugs in the rename migration script, found running it live on the
  standby — one of them deleted the node-written HA units and stopped
  replication.

### Security
- SSRF blocklist in the device API proxy now also refuses loopback targets.
- Triaged an internal AI security audit (14 findings): 1 real and fixed, 13
  verified false-positive or stale.

## [1.1] - 2026-07-15

### Renamed — service & filesystem layout (breaking for existing installs)
- Project fully renamed from the legacy internal name to **SATOM** at the
  infrastructure level: app dir `/opt/satom`, log dir `/var/log/satom`,
  and all systemd units (`satom.service`, `satom-scheduler.service`,
  `satom-reconciler.service`, `satom-updater.{path,service}`,
  `satom-alerts`, `satom-cert-renew`, `satom-git-publish`,
  `satom-ha-datasync` timers/services).
- Existing installs: run `deploy/migrate-rename-satom.sh` (root, one node
  at a time, standby first). It stops the legacy units, moves the tree, fixes
  venv shebangs, installs the renamed units, updates nginx and re-verifies
  `/healthz`.
- Installers (online + offline bundles) regenerated with the new layout.
- Unchanged on purpose: Postgres DB name/user, the `backup-server` external backup
  server (appliance-side push config points at it), and `FM_*` env var names.

## [1.0] - 2026-07-14
### Added
- **DNS Records management (IPAM/DDI)**: "+DNS Records" CRUD in the DNS & LB
  lookup tool, backed by pluggable providers (EfficientIP SOLIDserver,
  phpIPAM, NetBox).
- **Alerts engine**: cert-expiry, git-divergence, device-unreachable and
  backup-freshness alerts with in-app + email dispatch and admin thresholds.
- **Certificate auto-renewal** modes (alert-only default, or auto-pull from
  the edge) via a nightly renew timer.
- **Configuration drift detection** against the git source of truth, with
  recursive volatility normalisation.
- **Preflight/postflight health-snapshot harness** for upgrades and restores.
- **Gated canary restore** for per-device config recovery.
- **Firmware manifest auto-generation** on upload / pull / delete.
- **Production release line**: Linux installer (Debian + RHEL offline
  bundles), generic package-manager support, public site (GitHub Pages),
  package registry artifacts.
### Fixed
- Upgrade-event timestamps now render in local time (`| localtime`) instead
  of raw UTC.

## [0.9] - 2026-07-13
### Added
- **Node TLS + node-to-node encryption**: internal CA, per-node leaf certs,
  mutually-authenticated Postgres replication, HTTPS peer probes, and
  "encryption in transit" monitoring cards (every badge backed by a live probe).

## [0.8] - 2026-07-12
### Added
- **FortiAnalyzer** integration (JSON-RPC, dual dialect) as a full ADOM, with
  its endpoints in the DB registry and a git source-of-truth harvest.
- **FortiADC** configuration added to the git source of truth (hourly sync +
  nightly inspect), matching FortiWeb.
- **Backup coverage page**, external backup server (SFTP) with firmware SoT,
  library update indicator + per-package pip upgrade/rollback.
