# Safeguards — what stops SATOM from hurting itself

SATOM writes to production firewalls, rewrites its own checkout, installs its own
dependencies and reloads its own web server. Every one of those is a way to lose
data or lock yourself out. This document is the catalog of the guards that make
those operations survivable: **what each one prevents, where it lives, and how to
verify it is actually armed** on your install.

It is deliberately a single page. A protection nobody can find is a protection
nobody trusts, and the failure mode this project keeps hitting is not a missing
guard — it is a guard that silently took the wrong branch.

## The six rules the guards follow

1. **Fail loud.** A guard that cannot do its job aborts the operation. The one
   bug class that has bitten this product repeatedly is a step that returns
   success while doing nothing (`git push` failing inside a timer that exits 0;
   an HA guard answering "not primary" because its probe needed root).
2. **Snapshot before anything destructive**, and make the snapshot survivable
   without the thing that was destroyed.
3. **Verify, then commit — auto-revert on failure.** Every self-mutation
   (code, dependency, certificate) is followed by a real check, and the failure
   path restores the previous state instead of leaving a half-applied one.
4. **Allowlist, never free-form.** Package names, provider fields, doc slugs,
   remote filenames, CLI verbs — all validated against a closed set, and
   re-validated at the privileged end.
5. **One writer.** On a cluster the primary owns every write that replicates;
   the standby refuses rather than producing state its own sync will undo.
6. **Operator edits outrank seeds.** Anything the operator can tune lives in the
   database, seeded INSERT-ONLY, so an upgrade never resurrects what they removed.

---

## 1. Git history and the source of truth

Full treatment in [`git-backup-and-outage.md`](git-backup-and-outage.md). The guards:

| Guard | Prevents | Where |
|---|---|---|
| `preserve_local_commits()` before `git reset --hard` | Losing commits that exist only here (the whole `reports/` history of a Gitea outage). Parks them on `refs/backup/pre-reset-<stamp>`; a dirty tree via `git stash create`. **Aborts the update if it cannot park them.** | `deploy/self_update_runner.py` |
| `git.ahead_unpushed` alert | A push that has been failing for days while every UI stays green. Keys off the **age** of the oldest unpushed commit, not the count | `app/services/alerts.py::_check_git` |
| `git bundle --all` | Total loss of the repo. One verifiable, clonable file carrying every ref — including the `refs/backup/*` above — replicated to the standby, pushed off-rack to backup-server, downloadable | `app/services/git_backup.py` |
| Bundle delete is primary-only | Deleting on the standby, where `satom-ha-datasync --delete` would restore it within 5 min and make the UI look broken | `app/views/system_backup.py` |
| INSERT-ONLY registry seeds | A deploy overwriting endpoint/provider rows the operator corrected. A vendor moving a REST URI stays a row edit, not a release | `app/registry/loader.py`, `app/services/acme_providers.py` |

## 2. Updating code and dependencies

The web worker **never** mutates the installation. It writes a request file; the
root runner (`satom-updater.path` → `.service`) does the work. See
[`privilege-model.md`](privilege-model.md).

* **Code update** — records the current revision, applies, runs an **import
  smoke** on the new tree, restarts, health-checks. On any failure it rolls back
  to the recorded revision and re-verifies, and says so if the rollback itself
  did not recover.
* **Dependencies** — `pip` from the web is **curated-only**: the allowlist is the
  app's own `system_info._LIBRARIES`, validated at the enqueue *and* re-validated
  inside the root runner, with name and version regex checks. There is no
  `pip install <arbitrary>` path, on purpose — that would be remote code
  execution as the service account. The runner snapshots the installed version,
  installs, import-smokes, restarts, health-checks, and **auto-reverts** to the
  snapshot on failure. Restore points live per node in `data/lib-versions/`.
* **Node-local by design** — the virtualenv is not in git and not in the HA rsync,
  so the button applies to *that* node only; the card says so. The
  `requirements.txt` pin is bumped and pushed **only from the primary** (single
  git writer), so the next code update does not revert the library.

## 3. The privilege boundary

Detail in [`privilege-model.md`](privilege-model.md); the short version of what
protects you:

* The app runs as an unprivileged service account. Its `sudo` grants are an
  explicit allowlist (`nginx -t`, `systemctl reload nginx`, …) — not `ALL`.
* `User=` is pinned in a **systemd drop-in**, not in the shipped unit, so a
  self-update that replaces unit files cannot silently hand the app root again.
* The root runner is reached through a **request directory watched by a `.path`
  unit** — a queue, not a callable. The web process has no way to pass a command.
* `deploy/satom-node-role.sh` exists because the obvious role probe
  (`runuser -u postgres -- psql`) needs root: unprivileged, it returns empty and
  every HA guard quietly takes the "not primary" branch while systemd reports
  success. The probe now uses the app's own credentials over TCP, so it answers
  correctly at any privilege level.

## 4. Two-node correctness

| Guard | Prevents |
|---|---|
| Self-update / promote endpoints refuse on the standby | Two nodes rewriting the checkout, or a split brain |
| Backup + bundle deletes refuse on the standby | Deletions that `rsync --delete` immediately undoes |
| `satom-ha-datasync` role guard | The sync running on the primary (it PULLS: it runs on the standby and is inert elsewhere) |
| Forced command on the peer SSH key | The sync key being usable as a shell |
| `data/ha_nodes.json` matched against the **hostname** | Falling back to the first entry and rsyncing the node against itself — a real incident after a hostname change |
| `_commit_quiet()` on login | A login failing on the read-only replica because it could not stamp `last_login` |
| Peer probes over HTTPS `:8443` + shared identity key | Cleartext and unauthenticated node-to-node calls (see [`encryption-and-node-tls.md`](encryption-and-node-tls.md)) |
| Postgres replication `hostssl … clientcert=verify-ca` | A downgraded or unauthenticated replication stream |

## 5. Writing to the appliances

This is the part that can take a customer offline, so it has the most gates.

* **Read-only means read-only.** `ssh_ops.assert_readonly()` validates **every
  line** of a command, not just the first — a pasted `get x` / `set y` cannot
  sneak a write past a legitimate first line. Allowed verbs: `get`, `show`,
  `diagnose`/`diag`.
* **Dry-run → approval → apply.** Writes are computed as a minimal diff and shown
  before anything is sent; see [`source-of-truth-spec.md`](source-of-truth-spec.md).
* **Lease locks.** `lock_service` gives one operator a lease per (appliance,
  resource), refreshed by heartbeat, re-entrant for the same user and expiring on
  its own (default 120 s) if a tab is abandoned — so an abandoned browser never
  blocks the object permanently.
* **Change requests gate the dangerous ones.** A firmware upgrade refuses to
  flash unless its CR is approved/scheduled **and the clock is inside the
  window** — and that is re-checked at fire time by `cr_runnable()`, not only when
  the action was scheduled. Every transition stamps a timeline event.
* **Device config restore is still dry-run only** — stated here as a limit, not a
  feature.

## 6. Certificates

* **Import** parses the PEM, enforces that the **private key matches the
  certificate**, installs, runs `nginx -t`, and **rolls the files back and
  reloads** if nginx rejects them. A bad paste cannot take the web UI down.
* **ACME signing runs in a minimal environment.** The app's own environment
  carries `FERNET_KEY` and the database URI; the signer is built a curated
  passthrough instead of inheriting it. Provider credentials arrive as
  environment variables, never on the command line, and every secret is redacted
  from the stored log and from the command preview.
* **The command is a plain argv**, never a shell pipeline — no injection surface.
  Raw templates (`custom` mode) are admin-only and labelled.
* **The renewal journal is node-local** (`state/cert-renew.jsonl`, not Postgres,
  not `data/`) precisely because the node that fails to renew may be the one with
  a read-only database and a `--delete` rsync pointed at it. Each node publishes
  its own journal on `/healthz/cert-renewals`; `/cert-manager/renewals` shows both.
* `cert.renew_failed` is its own alert signal — **critical after 3 consecutive
  failures** — instead of waiting for the T-14-days expiry mail to imply it.

## 7. Files coming from outside

* Every external read/download resolves through `_safe_names()` — device and
  filename are validated, so path traversal and forged names return 404 rather
  than a file.
* Firmware pulled from the backup server is **sha256-verified** on arrival;
  bundles carry a sha256 sidecar so a copy can be trusted before it is used.
* **backup-server is a separate failure domain on purpose.** Gitea and the standby
  both live on hypervisor03; the primary on hypervisor06; the external backup server on hypervisor04.
  A single host loss can never take out every copy.

## 8. Sessions and the web surface

| Guard | Detail |
|---|---|
| Content-Security-Policy | Per-request **nonce**; `script-src-attr 'none'` — inline `on*` handlers cannot run, so an injected attribute is inert |
| Frame / sniff / referrer | `X-Frame-Options: DENY`, `nosniff`, `strict-origin-when-cross-origin` |
| Authenticated HTML is `no-store` | A stale nav or page cannot survive a deploy in the browser cache |
| CSRF | `CSRFProtect` app-wide; JS reads the token from the meta tag |
| Per-IP rate limits | sign-in 5/min · 2FA challenge 10/min · password recovery 5 and 10 per 15 min · `/api/v1` 30/min |
| Per-account lockout | 10 failures → locked 15 min. Complements the IP limit, which cannot isolate a distributed attack on one account |
| Local accounts never fall through to the directory | An AD account with the same name cannot take over the seed admin |
| Anti-lockout on access admin | The guards refuse the change that would leave **zero** active admin-capable users |
| Docs / plugin routes | Slugs validated against an allowlist and the resolved path re-checked inside its directory |
| TOTP + backup codes | Second factor for local accounts; directory accounts do MFA at the directory |

## 9. The alert catalog

Everything above is only useful if silence means healthy. The signals that exist
today (`app/services/alerts.py`, thresholds under Settings → Alerts, per-signal
cooldown `alerts.cooldown_hours`):

| Signal | Fires when |
|---|---|
| `cert.expiry` / `cert.error` | The service certificate is inside `alerts.cert_days` / cannot be read |
| `cert.renew_failed` | A renewal attempt failed — critical from 3 consecutive |
| `git.ahead_unpushed` | Unpushed commits older than `alerts.git_ahead_max_hours` (critical at 8×) |
| `git.behind` / `git.diverged` / `git.error` | Behind past `alerts.git_behind_max`; both ahead and behind; repo unreadable |
| `backup.none` / `backup.stale` / `backup.error` | No bundle at all; none within `alerts.backup_max_hours`; the check itself failed |
| `device.error` | A registered appliance is unreachable or erroring |
| `drift.error` | The drift comparison could not run |
| `engine.error` | The alert engine itself failed — the guard on the guard |

## 10. Fresh installs, and what an offline bundle can promise

The guards travel with the code. A node installed from the online path or from an
offline bundle has, from first boot, the anti-`reset` history guard, the pip
allowlist, the service-account drop-in, the peer forced command, the certificate
validate-and-rollback and the read-only assertion on appliance CLI.

What does **not** ship armed is everything that lives in the database — seeds are
INSERT-ONLY and operator edits outrank them (rule 6), so nothing is created on the
operator's behalf. A brand-new install has **no scheduled actions and no alert
recipient**, which means:

* no periodic device sync — the source of truth in `reports/` freezes at install day;
* no `git_bundle` run — none of the repository backup copies is ever produced;
* no database bundles;
* every signal in §9 is computed and delivered nowhere.

This is a deliberate trade (the product never invents schedules against live
appliances) but it is also the most common way an install ends up unprotected.
The install manual carries the recommended minimum set; arm it before calling the
install finished.

An offline bundle carries one extra caveat: it is a **snapshot of the repository
at build time**, so the guards inside it are the ones that existed then. Check the
version it contains before assuming a fix is present —

```bash
tar xzOf satom-offline-<ver>-*.tar.gz --wildcards '*/bundle/app.tar.gz' | tar xzO VERSION
```

The bundle also carries the ACME client and the `sudo` / OpenSSH packages, because
an air-gapped host has no way to fetch them and a missing `sudo` used to abort the
install after the service account had already been created — a half-applied state,
which rule 3 exists to prevent.

## 11. Known gaps (kept honest, on purpose)

* Per-device configuration restore is dry-run gated — no live canary round-trip yet.
* The public wildcard certificate is not auto-renewable from the node; it is
  re-copied when the edge renews it. Internal-CA certificates *do* auto-renew.
* The firmware manifest in the SoT repository is maintained by hand.
* Gitea and the standby share a host (hypervisor03). The bundle to backup-server exists
  because of that, but it mitigates rather than fixes it.

## Verifying the guards are armed

```bash
# 1. HA guards answer correctly at the service account's privilege level
sudo -u <service-account> /usr/local/sbin/satom-node-role.sh   # f = primary, t = standby

# 2. The unit really runs as the service account (drop-in, not the shipped unit)
systemctl show satom.service -p User
systemctl cat satom.service | grep -A2 drop-in

# 3. The privileged runner is armed on BOTH nodes
systemctl is-enabled satom-updater.path && systemctl is-active satom-updater.path

# 4. Safety refs and bundles exist
git -C /opt/satom for-each-ref refs/backup/
ls -l /opt/satom/data/git-bundles/
git bundle verify /opt/satom/data/git-bundles/<latest>.bundle

# 5. Alerts are on and thresholds set — Settings → Alerts, or:
#    signals fire only if alerts.enabled is true and a recipient exists

# 6. The security headers are actually being sent
curl -sI https://<node>/ | grep -iE 'content-security-policy|x-frame|x-content-type'
```

## Related

* [`privilege-model.md`](privilege-model.md) — accounts, sudo, the runner boundary, HA trust
* [`git-backup-and-outage.md`](git-backup-and-outage.md) — the Gitea-outage scenario end to end
* [`encryption-and-node-tls.md`](encryption-and-node-tls.md) — TLS, node identity, Postgres SSL
* [`source-of-truth-spec.md`](source-of-truth-spec.md) — the write path and the local persistence layer
* [`INSTALL.md`](INSTALL.md) — what to request from systems, and the hardening checklist
