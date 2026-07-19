# Changelog

## v1.1 — 2026-07-15

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

All notable changes to SATOM are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/). This is a public, open-source
project — see [NOTICE](NOTICE) for the trademark disclaimer.

## [Unreleased]
### Added
- **Open-source governance**: Apache-2.0 `LICENSE`, `NOTICE` (Fortinet
  trademark disclaimer + scope), `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, GitHub issue templates.
- **`docs/release-pipeline.md`**: documents the sanitize -> secret-scan ->
  internal-AI vulnerability audit -> publish gate; also surfaced on the site.
### Changed
- Product name **"Fortinet Manager" -> "SATOM"** across docs, README and
  the public site. Scope clarified: manages FortiWeb / FortiADC / FortiAnalyzer
  (FortiAuthenticator planned) — **not** FortiManager or FortiGate/NGFW.
- Public site footer now shows Apache-2.0 + trademark disclaimer.
### Security
- SSRF blocklist in the device API proxy now also refuses loopback targets
  (was already blocking link-local / cloud-metadata).
- Triaged the internal DeepSeek-R1 security audit (14 findings): 1 real and
  fixed, 13 verified false-positive/stale.

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
