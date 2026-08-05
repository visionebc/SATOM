# Metrics and the device source of truth

This document explains where SATOM keeps operational data, why it keeps it
there, and what the numbers were that forced the design. Two subsystems changed
on 2026-08-05, together:

* the **device source of truth** left git for a local content-addressed store;
* **fleet metrics** left Postgres for a local time-series store, and collection
  changed from one probe per series to one scrape per (device, collector).

Both changes have the same root cause: the original designs were correct for a
handful of appliances and structurally impossible for a hundred.

---

## 1. The measurement

Taken against a live node and a live appliance, not estimated.

| measurement | value |
|---|---|
| `policy_status` — every policy's counters, ONE call | **14 ms** |
| `policy_traffic` — ONE policy | 13 ms |
| `http_transactions` — ONE policy | 55 ms |
| `system_resource` — one device | 514 ms |
| cost of one sample row in Postgres (row + indexes) | **875 B** |
| manager node | 4 vCPU · 4 GB RAM · ~12 GB free |

Extrapolated to the stated target fleet — 60 FortiWeb + 30 FortiADC +
10 FortiAnalyzer, ~750 server policies each:

| consequence of the OLD design | value |
|---|---|
| probe rows an operator would "manage" | **~180,000** |
| samples per day | 86.4 M (~1,000 inserts/s sustained) |
| Postgres footprint (raw 2 d + hourly 90 d + daily 730 d) | **~450 GB** |
| device I/O per 3-minute collection window | **~56 min** — 18.7x over budget |

The I/O number is the one that matters most: **no database fixes it.** It comes
from asking the appliance for one policy at a time when a single call returns
them all.

---

## 2. Collection: the unit is (device, collector)

`services/metrics_collect.py`. One row in `scrape_target` per appliance per
collector — **~100 rows for the whole fleet**, not 180,000 — and each collector
turns one device call into many series. Series identity lives in *labels*
(`device`, `policy`, `iface`), not in configuration.

| collector | call cost | default | what it yields |
|---|---|---|---|
| `box` | 1 per device | 3 min | CPU, memory, disk, sessions, connection rate |
| `policies` | **1 per device** | 3 min | sessions / conn-rate / RTT for EVERY policy |
| `interfaces` | 1 per device | 3 min | link state + cumulative byte counters |
| `traffic` | 1 per policy | 15 min | throughput, device total + top-N policies |
| `transactions` | 1 per policy | 60 min | HTTP transaction counts, top-N policies |

The two expensive collectors are bounded twice: a longer interval **and** a
top-N selection by live connection rate. Full fidelity where the traffic is,
bounded cost where it is not. The device-wide total is always collected, so
"how much is this box doing" never depends on the top-N cut.

Every interval and every top-N is editable per target in
**Monitoring → Collection**. Nothing about cadence is implied by code.

### Rules that are load-bearing

* **`maintenance` suppresses scheduled collection.** An appliance parked for
  work is not scraped at all — the deep monitors once kept probing recycled IP
  addresses every three minutes because their sweep did not consult the flag.
* **A retired host (`*.invalid`) is structurally unreachable.** Neutralising a
  decommissioned appliance's hostname is a guard the code honours, not a note.
* **A failed collector writes `satom_scrape_up 0`.** Absence of data is never
  health; a broken collector is visible *in the store* rather than an absence
  someone has to notice.
* **`ok` on the scheduled action means THE SWEEP RAN.** Device failures live on
  the target rows. An action that goes permanently red over a dead appliance is
  an action the operator learns to skip.

---

## 3. Storage: VictoriaMetrics, single node, loopback

`deploy/satom-metrics.service` → `/usr/local/bin/victoria-metrics`,
`127.0.0.1:8428`, data in `/var/lib/satom-metrics`.

| | Postgres (old) | this store |
|---|---|---|
| cost per sample | 875 B | **< 1 B** (compressed) |
| 3 months at fleet scale | ~450 GB, and only hourly averages past 2 days | **~8 GB, full resolution throughout** |
| retention | rollups, because raw could not survive | 396 days raw |

Why this and not the alternatives:

* **Not Grafana + Prometheus.** SATOM ships offline installers for isolated
  management networks and has a strict privilege model. A second full stack
  means another ~300 MB in every bundle, another auth surface outside the
  product's RBAC, and another thing to replicate.
* **Not TimescaleDB.** A Postgres extension is a packaging problem across four
  distribution families, and adds a licence dimension to an ELv2 product.
* **Not a narrower Postgres table.** Partitioned, numeric, BRIN-indexed, no
  JSONB gets to ~50 B/sample — 390 GB at 90 days. Better; still impossible.

VictoriaMetrics is a single static Go binary (~15 MB), Apache-2.0, no
dependencies — it fits the offline bundles without per-family packaging.

### What this costs, stated plainly

* **No streaming replication.** Postgres gives HA replication for free; this
  does not. Each node keeps its own store. The data lives OUTSIDE `data/`
  deliberately: `satom-ha-datasync` rsyncs `data/` with `--delete`, and a
  time-series store must never be rsynced under a running process.
* **A second store to operate** — its own liveness check and its own unit.
* **Configuration stays in Postgres.** Boards, panels, targets, reports.

### It has no authentication

That is why the unit binds loopback only and every query goes through the
console (session auth + ADOM scoping). Changing that bind address is a
fleet-wide data exposure, and a test asserts it.

---

## 4. Dashboards: selectors, not enumerated series

Analytics panels have three selection modes. The first two enumerate probe
rows and were adequate at five appliances:

* `probes` — an explicit id list;
* `rule` — a metric kind plus optional device filter;
* **`metricsql`** — an expression evaluated by the store.

Only the third scales. At 100 devices there are no probe rows to enumerate for
the per-policy series; the store holds them and answers by selector:

```
satom_box_cpu_pct                              # every device, one line each
topk(10, satom_policy_conn_per_sec)            # the busiest ten, fleet-wide
sum by (device) (satom_policy_up == 0)         # policies with all backends down
rate(satom_iface_rx_bytes_total[5m]) * 8       # interface bandwidth
```

The built-in board **Fleet metrics (store)** ships six such panels.

Rules that hold the panels honest:

* **An expression is validated by EXECUTING it** against the store before it is
  saved. The store is the only authority on its own query language; a regex
  would reject valid queries as the language grows.
* **A failed query renders as an error, never as an empty chart.** The two look
  identical on a canvas and mean opposite things.
* **Gaps stay gaps.** A series with no sample at a timestamp gets `null`, not
  the previous value; a straight line across an outage is a lie no legend fixes.
* **The step bounds the point count (~600).** 43,200 points on a 900 px canvas
  is not more detail, it is a slower query and a thicker line. The step is
  printed in the panel footer.

---

## 5. Reports

`services/monitor_reports.py` builds daily / weekly / monthly summaries over a
**closed** period and persists them (the raw probe samples expire; a summary
recomputed later would answer from coarser data while looking identical).

Each report now carries a **fleet section computed from the store** — min / avg
/ max per device per metric, policies that were down, collectors that failed —
because the probe tables only describe what someone explicitly asked to watch,
which at fleet scale is a small minority of what exists.

`params.push_server=1` uploads the summary to the external backup server as
**both JSON and text**: JSON so a future console can re-render it, text so a
human with nothing but an SFTP client can read it. A report exists to describe
a window after it closed — which is exactly when the node holding it may be the
thing that failed.

A mail failure and a push failure are both recorded and neither fails the
action: the report is already stored.

---

## 6. The device source of truth

`services/sot_store.py` + `models_sot.SotVersion`.

**What was wrong with git.** The `reports/<device>/_config.json` tree was
committed hourly. One FortiAnalyzer snapshot is ~8.4 MB; ten of them plus
ninety FortiWeb/ADC is 90+ MB *per hour*, and git keeps every byte of every
revision forever. The repository outgrows the node in weeks. (The availability
argument often given for this change is weaker than the volume one and worth
stating accurately: with Gitea down, harvest, monitoring and the web app all
kept working — only publishing and code updates stopped.)

**What replaced it.** Content-addressed, gzip-compressed snapshots under
`data/sot/objects/`, indexed by a Postgres table:

* the **hash is the identity** — an unchanged config writes zero bytes and
  mints no row, only advancing `last_seen_at`. At fleet scale ~95 % of cycles
  are unchanged, so the store grows with *change*, not with *time*;
* **volatile fields are excluded from the identity** (`generated_at`, the
  per-sweep `errors` list) — hashing them would defeat the dedup entirely and
  quietly restore unbounded growth;
* blobs live under `data/`, so the existing standby rsync replicates them and
  the backup bundles include them — **no new replication mechanism**;
* **retention is a policy, not "forever"**: newest N versions per device plus
  anything younger than D days; unreferenced blobs are deleted.

Diff, history and restore are preserved in **System Backup & Restore**; the
diff is structural (added / removed / changed objects with field-level detail)
rather than a text diff of a 600 KB JSON file.

### What is retired

* `satom-git-publish.timer` — no longer installed or armed.
* The scheduled `git_bundle` action — the spec survives for manual runs, since
  a bundle of the CODE repo is still a valid recovery artifact, but new
  installs do not seed it and `diagnose install` no longer demands it.

**Git still carries application code**, and the reconciler and self-update path
are unchanged. A git-free code channel already exists (signed offline update
packages, `docs/offline-update-packages.md`).

### The four copies, after the change

| # | copy | mechanism | RPO |
|---|---|---|---|
| 1 | this node | harvest writes `data/reports/` + `data/sot/` | — |
| 2 | standby | Postgres streaming + `satom-ha-datasync` rsync of `data/` | seconds / ≤ 5 min |
| 3 | external backup server | SFTP push of SoT blobs and DB bundles | ≤ 24 h |
| 4 | downloadable bundle | pg_dump + reports + SoT store in one tar.gz | on demand |

No copy depends on an external service being reachable.

---

## 7. Operating it

```bash
satom get system health          # includes the metrics store
satom diagnose all               # collection targets and store liveness
```

* **Monitoring → Collection** — every target, its cadence, its last outcome,
  and store liveness. This is where collection frequency is changed.
* **Monitoring → Analytics → Fleet metrics (store)** — the selector board.
* **System Backup & Restore** — SoT versions, structural diff, bundles.

Arming a fresh install (nothing seeds `ScheduledAction` rows by design — see
`safeguards.md` §10):

```bash
sudo satom execute seed actions --yes
```

Restoring the metrics store is deliberately NOT part of the bundle: it is
node-local operational history, and a node that lost it keeps its
configuration, its source of truth and its reports. Losing metrics history
costs graphs, not state.
