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
| `device.health.<name>.<status>` | A device is degraded or critical on the Fleet-health ladder — one finding per device, every failing signal listed |
| `device.error` / `device.error.<name>` | The appliance list, or one device's health roll-up, could not be read |
| `drift.error` | The drift comparison could not run |
| `engine.error` | The alert engine itself failed — the guard on the guard |

### 9b. A health badge that can never go red is not a guard

**What it prevents.** Monitoring → Fleet health scored each appliance card
*only* from capacity headroom. No appliance in this fleet has an admin cap, so
every headroom row graded `nocap`, the roll-up loop could never reach
warn/crit, and a device that was powered off, whose hourly harvest had been
failing for days, and that had no cached configuration at all still rendered
**healthy** (found 2026-07-28 on an appliance that had been off the network for
weeks). A page that is structurally incapable of delivering bad news trains the
operator to stop reading it.

**Where it lives.** `app/services/device_health.py`. The badge is now the worst
of four signals, and every non-ok signal is printed on the card so the state is
never unexplained:

| Signal | Warns | Critical |
|---|---|---|
| `sync` — last `SyncRun` rows | one failed harvest | `ERROR_STREAK_CRIT` (3) in a row |
| `cache` — newest `DeviceSnapshot` | nothing cached, or older than `monitoring.stale_hours` (6 h) | older than 4× that |
| `probe` — enabled deep monitors | a probe alerting, or *all* probes disabled | a probe critical |
| `capacity` — headroom | over `capacity.warn_pct` | over `capacity.crit_pct` |

Two design rules carry the guard:

* **`unknown` is its own state**, ranked below `ok`. A device we have measured
  nothing about renders `unknown`, never `healthy`. Uncapped object types and a
  device that has never been harvested produce `unknown`, not a free pass.
* **A disabled probe is not a passing probe.** Switching off a monitor that
  always fails removes coverage, and the card says so.

**The badge and the mailbox share this ladder.** A guard that only paints a
page is a guard nobody is watching at 03:00. `alerts._check_devices` grades
every appliance with `device_health.collect_for()` — the same four signals,
the same thresholds — and adds a fifth that the page structurally cannot have:
a live TCP probe. Before 2026-07-28 that probe was the *whole* device check,
which is why fw6 and fw7 could answer `:443` for a week with a dead harvest and
never produce a single mail.

Three rules keep the two surfaces honest:

* **One device, one finding.** Every failing signal is a line in the message,
  never a separate mail. Five signals about one dead box is noise that gets
  filtered, and a filtered alert is a disabled alert.
* **The severity is the badge.** `crit` on the page is `critical` in the mail.
  If they can disagree, the operator learns to trust neither.
* **The status is part of the cooldown key** (`device.health.<name>.<status>`).
  A device that degrades from warn to crit inside `alerts.cooldown_hours` still
  reaches the operator; a fixed key would suppress exactly the escalation the
  alert exists for.

The floor is operator-tunable (`alerts.device_min_status`: `warn` default,
`crit` to mail only on critical) — a volume knob, not an off switch, because
silencing warnings is a decision that should be visible in Settings rather than
achieved by ignoring mail.

**How to check it is armed.** `GET /monitoring/data` and confirm each device
row carries a `health` block with `signals` and `reasons`, and that
`worst == health.status`. For the alert side, Settings → Alerts → *Preview now
(no send)*, or:

```bash
flask shell -c "from app.services import alerts; print(alerts._check_devices())"
```

A device that renders red on the page and returns nothing here means the two
ladders have diverged. `tests/test_device_health.py` asserts the badge
regression (uncapped + unreachable + never cached must not be `ok`) and
`tests/test_alerts_device_health.py` asserts the alert one (a device whose port
answers but whose harvest is failing must still produce a finding).

### 9c. An ADOM shows its own product, and nothing about the manager

Monitoring (Fleet health · Metrics · Deep monitors) lives in every ADOM. What an
ADOM must NOT inherit is the manager's own diagnostics — HA peers, the Git SoT,
the external backup server, the local database, the systemd units, the
encryption posture. Those describe the SATOM installation, not FortiWeb or
FortiADC or FortiAnalyzer, and rendering them inside a product view puts node
hostnames and infrastructure addresses on a page whose whole promise is "this is
your product".

Three rules:

* **The template is not the enforcement point.** `{% if is_global %}` hides the
  sections; `/monitoring/data` also *omits* `system`/`services`/`db`/
  `redundancy` outside Global (the collection is skipped, not filtered), and
  `/monitoring/infra` and `/monitoring/encryption` answer **403**. A hidden card
  whose endpoint still answers is a hidden card, not a scoped one.
* **Scoping is by device kind, never by who created the row.** Every page
  filters through `visible_appliances()`, so a probe created from Global against
  a FortiWeb box appears in the FortiWeb ADOM with no extra bookkeeping.
* **Fleet-wide ACTIONS are scoped too, not just the views.** Both "Scan
  hardware (SSH)" and Deep monitors' "Probe now" default to *everything* when
  nothing is selected, and both then open an SSH session per device. The target
  list is resolved in the request (where the ADOM exists) and passed to the
  worker thread; an unscoped `Appliance.query` inside the worker would log into
  the FortiADC and FortiAnalyzer boxes from the FortiWeb ADOM. Global keeps
  `ids=None` so the scheduler's own due/force semantics are untouched.

**How to check it is armed.** From a product ADOM:

```bash
curl -sk -H 'X-ADOM: fortiweb' https://<node>/monitoring/infra        # expect 403
curl -sk -H 'X-ADOM: fortiweb' https://<node>/monitoring/data | \
  python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["scope"], \
    [k for k in ("system","services","db","redundancy") if k in d])'  # fortiweb []
```

`tests/test_adom_monitoring.py` pins all of it: the pages answer in all three
ADOMs, each sees only its own devices and probes, the manager sections and their
endpoints are Global-only, and neither fleet-wide action can reach out of its
ADOM.

### 9c-bis. An alert about a device belongs to that device's ADOM

`alerts.run()` executes in a background thread (`satom-alerts.timer`), so there
is no request context and `product_scope.stamp()` returns `''` for everything it
raises. An unscoped notification is visible in the FortiWeb ADOM **by
construction** (§9c: `''` predates stamping and is FortiWeb-era). The result:
every alert about `fadc` and `faz01` rang the FortiWeb bell. On 2026-07-28 that
was 132 of 145 rows on the primary, and the operator reported the FortiWeb ADOM
as flooded.

The rule: **a device finding's ADOM is the DEVICE's `kind`, never the session's.**
`alerts._product_of(appliance)` maps the kind, and `run()` forwards
`finding["product"]` to `notifications.push_many`. Applies to every per-device
check — `_check_devices` (health + roll-up error) and `_check_drift`. Findings
about the manager itself (cert, git, backup) keep the old behaviour and stay
unscoped on purpose: they concern the installation, not a product.

An unrecognised kind maps to `''`, not to a guess — failing open into the
catch-all is recoverable, filing a FortiWeb alert under FortiADC is not.

**How to check it is armed.**

```bash
psql -h 127.0.0.1 -U <db-user> <db> -c \
  "select coalesce(nullif(product,''),'(unscoped)'), count(*) \
     from notifications where title like 'Device %' group by 1;"
# expect one bucket per device kind, no '(unscoped)' for new rows
```

`tests/test_alerts_product_scope.py` pins the three kinds, the unknown-kind
fallback, and the end-to-end hand-off into the notification layer (a finding
that carries the ADOM but writes an unscoped row is the same bug).

### 9d. A scheduled run says whether it RAN, not whether it liked what it found

`_do_deep_monitor` used to return `ok = worst in ("ok", "unknown")`. One server
policy with every backend down therefore marked the *Deep monitors — probe
sweep* scheduled action **failed**, and kept it failed until somebody repaired
the backend. Two things break at once when a run status carries a finding:

* a sweep that genuinely could not execute becomes indistinguishable from a
  healthy sweep that found something real, and
* the action sits permanently red, which is precisely how an operator learns to
  stop reading it — the same failure mode as a probe left pointing at a
  powered-off appliance.

`ok` is now `True` whenever the sweep completed; the worst status and the
per-status counts go in the summary, and every finding keeps its own probe row,
page badge and alert. A sweep that truly fails still raises and `run_action`
catches it.

**Where:** `app/services/scheduled_actions.py::_do_deep_monitor`.
**Tests:** `tests/test_deep_monitor_api.py::test_sweep_action_stays_ok_when_a_probe_is_critical`
(verified by mutation — reverting the flag fails it).

### 9e. Runtime telemetry survives a licence lock, and never invents a number

The four REST-monitor probe kinds (`sessions`, `policy_sessions`, `throughput`,
`transactions`) read the appliance's monitor API and open no SSH session. Three
rules hold them honest:

* **A licence-locked device is still measurable.** Every *cmdb* read on fw6/fw7
  returns HTTP 423 `-20010`, which is why their hourly `device_sync` has been
  failing for days — yet `system/status.systemresource`, `policy/policystatus`
  and `policy/policytraffic` all answer 200. Discovery therefore reads the LIVE
  `policystatus` rather than the harvest cache; discovering from the cache would
  have created zero probes on exactly the devices that most need them.
* **Wrong product fails loudly.** FortiADC and FortiAnalyzer publish runtime
  telemetry under entirely different paths. `_api_client` refuses any device
  whose `kind` is not FortiWeb and returns `error` with the product named,
  because a shared client would have reported a confident **0 Mbps** instead.
* **Absent data is never health.** A disabled policy grades `warn`, not `ok`
  (a policy admitting no traffic *is* the outage); an empty transaction bucket
  list grades `error`, not `ok`, because the appliance answers `errcode 0` with
  no rows when the policy name is unknown; and throughput is graded on the
  window **peak**, not the mean, so a four-second burst is not averaged away.

* **A zero that cannot be a zero is not a zero.** VERIFIED on fortiweb08 under
  a measured load test (2026-07-28): a policy carrying **~2 700 req/s** reported
  **0** transactions in every bucket of `system/status.httptransactions`, and
  reported **417 059** the instant a `web-protection-profile` was attached to
  it. Nothing else changed, and enabling the global traffic log beforehand made
  no difference. [Probable] the per-policy counter is keyed off the protection
  profile. Whatever the mechanism, an all-zero result on a policy that
  `policystatus` shows carrying sessions or connections now grades **warn** and
  names the likely cause. The cross-check call is made **only when the count is
  zero**, so the healthy path costs nothing, and a failure of the cross-check is
  swallowed — a refinement of the grade must never turn a working probe into an
  error.

Known limit, stated rather than hidden: no endpoint in the appliance's entire
non-cmdb API surface exposes daemon or process state. The runtime `policy`
handle is carried in the policy fingerprint and *would* change if proxyd
rebuilt its policy table, but that is inference and is **not verified**. The CLI
`proxyd` probe watches the actual PID set and remains the authoritative restart
check.

**Where:** `app/services/deep_monitor.py` (`API_KINDS`, `_api_client`,
`discover_api_probes`, the `classify_*` graders), `app/clients/fortiweb.py`
(the monitor endpoint block).
**Tests:** `tests/test_deep_monitor_api.py` — 48 cases over payloads captured
verbatim from a live appliance; `tests/test_service_monitor.py` for the
silent-zero guard (mutation-tested: neutralising the check fails the suite).

### 9f. Two probe pages, one subsystem — the partition is server-side

**Service Monitor** (`/monitoring/services`) and **Deep monitors**
(`/monitoring/deep`) are two *views* over one probe table, one runner and one
scheduled action. Splitting the storage or the runner would double-schedule
every device: two sweeps, two SSH sessions, two sets of samples for the same
box. What is split is the set of `deep_monitor.KINDS` each page owns — the five
that reach INTO the appliance versus the four REST-telemetry kinds.

The partition is enforced on **every route**, not by hiding rows in a template:

* each page's `/data` filters on its own kinds;
* `apply_form` refuses a kind belonging to the other page, on create AND on
  edit — otherwise the form's `<select>` would be the only thing between an
  operator and a probe its owner page cannot display;
* a probe id belonging to the other page answers **404** (not 403: from this
  page's point of view it does not exist) on history, series, update, toggle and
  delete;
* *Probe now* with no selection is pinned to this page's kinds and this ADOM's
  devices. A button whose scope is wider than the table under it is a button
  that lies — and in a product ADOM the previous fleet-wide sweep would have
  opened SSH sessions to appliances of other products;
* *Discover from device* only accepts the steps the page owns, so asking the
  Service Monitor page for `baseline` cannot create CPU/memory/proxyd probes it
  will never show.

A kind can therefore land on exactly one page. It cannot land on both, and it
cannot land on neither without `test_the_two_pages_partition_every_probe_kind`
failing — which matters because a kind owned by no page would still be run by
the sweep while being invisible and uneditable in the UI.

ADOM scoping (§9c) stacks on top and is unchanged: every query still runs
through `visible_appliances()`.

**Where:** `app/views/monitor_probes.py` (the shared route set + `PageSpec`),
`app/views/deep_monitor.py` and `app/views/service_monitor.py` (the two specs),
`app/templates/monitoring/_probe_page.html` (one page, two mount points).
**Tests:** `tests/test_service_monitor.py`.

### 9g. Housekeeping is silent unless it breaks

A background job used to look exactly like a job someone was waiting on: the
toast dock opened a floating window with a progress bar and a **Stop** button
for a monitoring sweep nobody asked to watch, and the sweep pushed a bell
notification on **every** successful run. Two different channels both spending
the operator's attention on "the thing you told me to do is happening".

`jobs.create_job(..., background=True)` marks work no human is waiting on. Three
rules follow from it:

* **The dock never sees it.** `GET /jobs/?active=1` — the toast dock's only
  feed — filters background jobs out *server-side*. Hiding them in the client
  would leave the noise one cached script away from coming back, so
  `jobs.js` drops them too: two locks, not one.
* **The Jobs page still sees all of it.** Silent is not invisible. Progress,
  message, log, Stop and the full history stay on `/jobs/manager`, which is
  where someone goes when they actually want to watch.
* **Only a failure is pushed.** A sweep that ran is not news — the table under
  the button reloads itself, and a probe that turned crit is already carried by
  the device badge (§9b) and the alert engine, which owns escalation and
  cooldown. A sweep that **failed** is the one outcome the page cannot show:
  the numbers simply stay stale and look current. That, and only that, reaches
  the bell — carrying the ADOM stamped on the job, because the worker thread
  has no request context of its own (§9c-bis).

**Default is foreground.** `background` defaults to `False`, so a new job type
cannot go quiet by accident; going quiet has to be a decision someone wrote
down. Today the flag is on the two probe sweeps and the fleet hardware scan.
*Discover from device* deliberately stays foreground: it creates rows and the
operator is waiting to read "created 12 probes".

**Where:** `app/services/jobs.py` (`create_job(background=…)`),
`app/views/jobs.py::index` (the feed filter), `app/static/js/jobs.js`
(`reconnectJobs`), `app/views/monitor_probes.py::_run_sweep`,
`app/views/monitoring.py::_run_hw_scan`.
**Tests:** `tests/test_background_jobs.py`.

### 9h. A consolidated view never invents a number it did not measure

The Service Monitor table shows one row per probe. Two consolidated views sit
on top of it — a traffic card per appliance, and a drill-down per server policy
— and consolidation is exactly where a monitoring page learns to lie: the
moment several probes are merged into one headline figure, the ones that are
missing, disabled or hours old vanish into the ones that answered.

Three rules, enforced in `app/services/service_rollup.py`:

* **Absence is never a zero.** A probe that is missing, disabled or has never
  run reports `measured: False` and `status: unknown`, and its numeric fields
  are set to `None` — not carried over from the last sample, not defaulted to
  `0`. On screen, `0 Mbps` from an idle service and `0 Mbps` from a probe
  nobody enabled are the same pixels, and only one of them is good news. The
  card prints *"not measured"* instead. This one was caught by its own test
  during development: a disabled probe was still serving its last reading.
* **A disabled probe is not a passing probe.** It counts as a coverage gap and
  is named in the card's `coverage.gaps`, so a device cannot look monitored
  because someone paused the one check that mattered.
* **Stale is stated, not hidden.** A sample older than
  `service_rollup.STALE_AFTER` (16 min — two missed five-minute sweeps, so
  jitter does not trip it) keeps its values and gains a `stale` flag plus its
  age. An old reading is still a reading; an old reading that renders like a
  fresh one is not.

**Deliberately not built: a single rolled-up status badge per device.**
`deep_monitor.worst` ranks `unknown` at the *tail* of `STATUS_ORDER`, i.e. less
severe than `ok`, so one healthy probe beside three missing ones would roll up
green — the same failure the Fleet health badge had before §9b. Rather than
fork the fleet-wide severity ordering for one card, the module returns each
block's own status plus an explicit coverage summary and the template renders
both.

**And the views never touch an appliance.** Both are built entirely from stored
samples, so they open instantly, they answer with the box powered off, and they
keep answering on a device whose cmdb API is licence-locked. The test proves it
by replacing `FortiWebClient` with a function that raises.

**One page owns the rollup.** `PageSpec.rollup` is off by default; the
collection does not run and the key is *omitted* from `/data` on a page that
does not own it, and the policy endpoint is not registered there at all (404,
not 403 — from that page it does not exist). A page whose kinds never produce a
`policy`/`stats` payload would otherwise render a strip of empty cards reading
as "no traffic" rather than "not applicable".

**Where:** `app/services/service_rollup.py`,
`app/views/monitor_probes.py` (`PageSpec.rollup`, `payload()`, `policy_detail`),
`app/views/service_monitor.py` (`rollup=True`),
`app/templates/monitoring/_probe_page.html`.
**Tests:** `tests/test_service_rollup.py`.

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
### The REST monitor probes (§9d, §9e)

    # the sweep reports "ran", not "healthy" — a crit finding must not fail the run
    python3 - <<'PY'
    from app.services import scheduled_actions as sa, deep_monitor as dm
    dm.sweep = lambda **k: {"ran":1,"counts":{"crit":1},"worst":"crit","results":[]}
    assert sa._do_deep_monitor({}, False)["ok"] is True
    PY

    # the two pages partition every kind — none owned twice, none orphaned
    python3 -c "from app.views.deep_monitor import KINDS as D; \
      from app.views.service_monitor import KINDS as A; \
      from app.services.deep_monitor import KINDS as ALL; \
      assert not set(D)&set(A) and set(D)|set(A)==set(ALL); print('partition ok')"

    # a probe of the other page does not exist here (404, not 403)
    curl -sk -o /dev/null -w '%{http_code}\n' \
      https://<node>/monitoring/services/probe/<a-deep-probe-id>/history

    # a non-FortiWeb device is refused by name, never measured as zero
    python3 -c "from app.services import deep_monitor as dm; \
      print(dm._api_client(type('P',(),{'kind':'fortiadc','appliance':None})()))"

    # telemetry answers on a licence-locked box while its cmdb does not
    curl -sk -H "Authorization: $TOKEN" https://<fw>/api/v2.0/cmdb/system/interface   # 423 -20010
    curl -sk -H "Authorization: $TOKEN" https://<fw>/api/v2.0/policy/policystatus     # 200

### Consolidated views never invent a number (§9h)

    # a device with no throughput probe reports unknown, NOT 0 Mbps
    curl -sk -b <session> https://<node>/monitoring/services/data | python3 -c \
      'import json,sys; [print(d["name"], d["total_throughput"]["measured"], \
        d["total_throughput"]["avg_mbps"]) for d in json.load(sys.stdin)["device_rollup"]]'
    #   -> measured False must always come with avg_mbps None

    # the rollup belongs to ONE page
    curl -sk -b <session> https://<node>/monitoring/deep/data | grep -c device_rollup   # 0
    curl -sk -b <session> "https://<node>/monitoring/deep/policy/1?name=x"              # 404

    # an unmonitored policy is a 404, not an empty shell
    curl -sk -b <session> "https://<node>/monitoring/services/policy/<id>?name=ghost"   # 404

### Background jobs stay out of the dock (§9g)

    # the toast feed must not contain a background job; the Jobs page must
    curl -sk -b <session> https://<node>/jobs/?active=1 | python3 -c \
      'import json,sys; print([j["background"] for j in json.load(sys.stdin)["jobs"]])'   # all False
    curl -sk -b <session> https://<node>/jobs/all | python3 -c \
      'import json,sys; print(sum(1 for j in json.load(sys.stdin)["jobs"] if j.get("background")))'

    # a new job type is foreground unless it opts out
    python3 -c "from app.services import jobs; print(jobs.create_job('t','x')['background'])"   # False


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

# 6. The health badge is wired to reachability, not just capacity
curl -sk https://<node>/monitoring/data | python3 -c \
  'import json,sys; d=json.load(sys.stdin); print([(x["name"],x["worst"]) for x in d["devices"]])'

# 7. A product ADOM cannot see the manager's own infrastructure
curl -sk -H 'X-ADOM: fortiweb' https://<node>/monitoring/infra -o /dev/null -w '%{http_code}\n'   # 403

# 8. The security headers are actually being sent
curl -sI https://<node>/ | grep -iE 'content-security-policy|x-frame|x-content-type'
```

## Related

* [`privilege-model.md`](privilege-model.md) — accounts, sudo, the runner boundary, HA trust
* [`git-backup-and-outage.md`](git-backup-and-outage.md) — the Gitea-outage scenario end to end
* [`encryption-and-node-tls.md`](encryption-and-node-tls.md) — TLS, node identity, Postgres SSL
* [`source-of-truth-spec.md`](source-of-truth-spec.md) — the write path and the local persistence layer
* [`INSTALL.md`](INSTALL.md) — what to request from systems, and the hardening checklist
