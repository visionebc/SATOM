# Sizing a SATOM node — the formula

Every other requirements table in this manual states a *floor*: what the
installer needs to finish. This document answers the question that actually
decides whether a node survives its second year — **how big must it be for the
fleet you are pointing it at** — and it answers it with one formula per
resource, built from constants measured on a running node rather than
estimated.

Read §1 if you only want a number. Read §2 if you have to defend it.

> **Why this exists.** On 2026-08-22 a node built to the old flat
> recommendation (20 GB) filled its disk. The web console kept answering
> `/healthz` 200 while PostgreSQL spent **five hours** in a
> crash → recovery → PANIC loop, unable to write its checkpoint; the alert
> engine, the certificate renewal and the Sentinel runner were down that whole
> time. Nothing in the product had told anyone how big the disk *should* have
> been, and nothing was watching the one number that mattered. §5 is the rule
> that came out of it.

---

## 1. The short answer

Pick the row that covers your fleet. `P̄` is the **average number of server
policies per device**, which matters far more than the device count.

| Tier | Devices | P̄ | vCPU | RAM | Disk |
|---|---|---|---|---|---|
| Lab / PoC | ≤ 10 | ≤ 100 | 2 | 4 GB | **20 GB** |
| Small | ≤ 25 | ≤ 250 | 4 | 4 GB | **30 GB** |
| Medium | ≤ 60 | ≤ 250 | 4 | 8 GB | **40 GB** |
| Large | ≤ 110 | ≤ 750 | 8 | 8 GB | **120 GB** |
| Beyond | > 110 | — | *split the fleet across nodes — see §3.1* | | |

Two things this table will not do for you:

* **It does not scale by device count alone.** A single FortiWeb carrying 750
  server policies costs more disk than fifteen carrying twenty. Every term in
  §2 that grows is driven by `D × P̄`, not by `D`.
* **It has no opinion about your retention.** The disk column assumes the
  shipped defaults (396 days of metrics, 46 nightly bundles). Halve either and
  the largest row loses tens of gigabytes; §3.2 lists the dials.

---

## 2. The formulas, and where the constants come from

All constants below were **measured on a production node** (4 vCPU / 4 GB /
20 GB, Debian 12, PostgreSQL 15, VictoriaMetrics 1.148.0) on **2026-08-22**,
against FortiWeb 7.6.8 appliances over a LAN. §4 is the recipe to re-measure
them on your own node — do that before trusting these numbers on a fleet that
differs from ours (WAN latency, in particular, changes the CPU formula and
nothing else).

### 2.0 Symbols

| | |
|---|---|
| `D` | managed devices being collected from |
| `P̄` | average server policies per device |
| `A` | ADOMs per device (1 when ADOMs are off) |
| `R` | metrics retention, days (default **396**) |
| `N_b` | nightly bundles kept (default **46**) |
| `W` | collection window, seconds (default **180** — the 3-minute sweep) |

### 2.1 The binding constraint is device I/O, not disk

The ceiling on a node is **not** its CPU or its RAM. It is how much of each
collection window is spent waiting on appliances, because a collector that has
not finished when the next window opens is a collector that will never catch
up.

Measured, per device, per 3-minute window:

| Collector | Calls | Measured | Cost per window |
|---|---|---|---|
| `box` (`system_resource`) | 1 / device | 596 ms | 596 ms |
| `policies` (`policy_status`) | **1 / device, all policies** | 70 ms | 70 ms |
| `interfaces` | 1 / device | 97 ms | 97 ms |
| `traffic` | 1 / policy, **top-10**, every 15 min | 13 ms | 26 ms |
| `transactions` | 1 / policy, **top-10**, hourly | 55 ms | 27 ms |
| | | **total** | **≈ 0.82 s** |

```
    t_dev  = 0.82 s          (device I/O per device per window, LAN, 7.6.8)
    D_max  = (W × u) / t_dev            u = duty cycle you will tolerate
```

* at `u = 0.5` (half the window spent collecting): **D_max ≈ 110 devices**
* at `u = 0.8` (no headroom for a slow box): **D_max ≈ 176 devices**

Use `u = 0.5`. The margin is not decoration: one unreachable appliance burns
its full connect timeout inside the window, and the top-N caps only bound the
*expensive* collectors, not the ones that answer per device.

**This is the number that made the design what it is.** `policy_status` returns
**every** policy in one call, so `P̄` does not appear in `t_dev` at all. A
per-policy design would have put `P̄ × 13 ms` in that row — 9.75 s per device
for a 750-policy box, or **56 minutes of device I/O per 3-minute window** for a
100-device fleet. No database fixes that; only the shape of the call does.
(Full reasoning: [`metrics-architecture.md`](metrics-architecture.md).)

### 2.2 Disk

```
    DISK = BASE + CONFIG + METRICS + SOT + BUNDLES + FIRMWARE
    plan for  DISK × 1.3        (30 % headroom — see §5)
```

| Term | Formula | Measured constant | Provenance |
|---|---|---|---|
| `BASE` | **5 GB** | OS + venv (213 MB) + code + PostgreSQL cluster & WAL (721 MB) + logs | `du` on the node |
| `CONFIG` | `D × P̄ × 270 × 1.66 KB` | **≈ 0.45 MB per server policy** | `device_objects`: 35,330 rows / 56 MB → 1.66 KB per row incl. indexes; 12,867 rows for 40 policies on one device |
| `METRICS` | `D × [(14 + P̄) × 480 + 1704] × 1.08 B × R` | **1.08 bytes per stored sample** | 1,571,997 samples in 1.70 MB of `/var/lib/satom-metrics` |
| `SOT` | `D × V × s` | **≈ 70 KB per retained version** (small device); budget **1 MB** for a FortiAnalyzer-class snapshot | 17 MB holding 259 versions, content-addressed + gzip |
| `BUNDLES` | `N_b × b` | **b ≈ 25 MB**, and `b` grows with `CONFIG` | 46 bundles = 420 MB, newest 27 MB |
| `FIRMWARE` | images you stage × ~1 GB | 578 MB for the current set | only if you use hypervisor provisioning |

Series count, which is what the metrics term really tracks:

```
    series/device ≈ 14 + P̄        (box 5 + interfaces 9 + one per policy)
    samples/day/device ≈ (14 + P̄) × 480  +  1,704
                          ^ 3-min collectors     ^ 15-min and hourly top-10
```

Worked out, at the shipped 396-day retention:

| `D` | `P̄` | series | metrics | config index | disk incl. 30 % |
|---:|---:|---:|---:|---:|---:|
| 5 | 40 | 270 | 0.06 GB | 0.09 GB | **6.7 GB** |
| 10 | 100 | 1,140 | 0.24 GB | 0.45 GB | **7.4 GB** |
| 25 | 250 | 6,600 | 1.37 GB | 2.80 GB | **11.9 GB** |
| 60 | 250 | 15,840 | 3.30 GB | 6.72 GB | **19.5 GB** |
| 100 | 750 | 76,400 | 15.76 GB | 33.62 GB | **70.7 GB** |

(The tier table in §1 rounds these **up**, and adds room for bundles and
firmware, which the arithmetic above excludes.)

Two observations worth carrying:

* **The config index outgrows the metrics store**, roughly 2:1 at scale. The
  intuition that time-series data is the expensive one is wrong here, because
  the store keeps 1.08 bytes per sample while a config object row costs 1.66 KB
  — a factor of ~1,500. Storing samples in PostgreSQL instead would cost
  **875 bytes each**, which is how the design arrived at a separate store.
* **The source-of-truth store barely grows**, because it is content-addressed:
  a device whose configuration did not change writes **zero bytes** and creates
  no row. Budget for churn, not for device count.

### 2.3 RAM

```
    RAM = 1.5 GB  +  0.13 GB × gunicorn workers  +  0.2 GB (scheduler)
                  +  0.4 GB (PostgreSQL)  +  0.1 GB (metrics store)
```

Measured at rest on the reference node: **1,132 MB used** of 4 GB, with 4
gunicorn workers at 110–128 MB each, `app.scheduler_runtime` at 190 MB,
PostgreSQL at ~400 MB of RSS across its backends and the metrics store below
100 MB.

* PostgreSQL's RSS **double-counts shared buffers** across backends; the true
  figure is lower than the sum of its processes. Size for the sum anyway.
* **4 GB is comfortable up to ~25 devices.** Go to 8 GB past that, not because
  the steady state needs it but because a bulk clone, a bundle build and a
  firmware upload can land in the same minute.
* Parallel analysis (`analyse_workers`) is bounded work inside the web worker,
  not a new process per job: measured 51.45 s → 20.99 s for 10 policies at 4
  workers, with an identical plan.

### 2.4 CPU

CPU is almost never the constraint — the sweep is I/O-bound (§2.1) — but two
things are genuinely CPU-hungry and both are bursts, not steady state: bundle
creation (gzip over the whole `data/` tree) and structural diffs of large
snapshots. 2 vCPU is enough to run a lab; give a production node 4, and 8 once
you are past 60 devices so a bundle build cannot starve the sweep.

---

## 3. When you outgrow the node

### 3.1 Past `D_max` (§2.1) — split, do not stretch

Two nodes each collecting half the fleet is the supported answer. The HA pair
described in [`INSTALL.md`](install.html) §4 is **not** that: the standby exists
to survive the primary failing, and its metrics store is per-node by design
(a TSDB cannot be rsynced under a live process). Splitting means two
independent installations, each with its own device inventory.

### 3.2 Before you buy disk, spend these dials

In descending order of effect, and every one of them is a **product setting**,
not a config file edit:

1. **Metrics retention** (`R`, default 396 days). Halving it halves the whole
   metrics term. `Monitoring → Collection` shows the live store size.
2. **Collector intervals, per target.** The `box` collector at 3 minutes is
   what makes `t_dev` 0.82 s; at 5 minutes the same fleet costs 40 % less
   device I/O and 40 % fewer samples.
3. **Top-N** on `traffic` and `transactions` (default 10). These bound the only
   collectors whose call count scales with `P̄`.
4. **Bundles kept** (`N_b`). 46 nightly copies of a growing database is the
   default; 14 is usually the honest requirement.
5. **SoT version retention** (N versions + D days, per policy).

Raising an interval is reversible and loses no history. Lowering retention
**deletes** history — decide in that order.

### 3.3 What breaks first, in order

Measured, not theorised — this is the sequence observed on 2026-08-22:

1. **PostgreSQL stops** when it cannot write a checkpoint. It does not degrade;
   it PANICs and restarts, forever, and every service that talks to it fails
   with `the database system is in recovery mode`.
2. **`/healthz` keeps answering 200**, because the web worker serves it without
   touching the database. A node can be five hours dead by this measure and
   still look alive.
3. The **collectors stop writing** and their gaps are correctly rendered as
   gaps — which is the one thing that behaved well.

The alert engine cannot save you here, and it is worth understanding why: it
records and dispatches every finding *through the database*, so the one
condition it can never report is the condition that took the database down.
Disk thresholds (warn 80 %, crit 92 %) existed and were useless. Since
**1.12.0** the wrapper prints the machine's own numbers — `df`, `free`,
`/proc/loadavg`, no database, no network — to the journal when a run fails, so
a failed `satom-alerts` unit now says *filesystem 100 % used* instead of an
SQLAlchemy trace. That is a legible failure, not a fix: **watch free space from
outside the node.**

---

## 4. Re-measuring the constants on your own node

Nothing here is a secret formula; all six constants come out of five commands.

```bash
# 1. per-sample cost of the metrics store
curl -s 127.0.0.1:8428/metrics | grep -E '^vm_(rows|data_size_bytes)\{type="storage'
#    bytes_per_sample = sum(data_size_bytes) / rows

# 2. per-row cost of the config index
sudo -u satom psql satom -c "select relname, n_live_tup,
     pg_size_pretty(pg_total_relation_size(relid)) from pg_stat_user_tables
     order by pg_total_relation_size(relid) desc limit 5;"

# 3. what the fleet actually costs on disk, term by term
du -sh /opt/satom/data/* /var/lib/satom-metrics /var/lib/postgresql

# 4. device I/O per window — the number that sets D_max
#    Monitoring -> Collection shows every target's interval, top-N and last
#    sweep; `satom diagnose all` folds the same store health into one exit code
satom diagnose all | sed -n '/checks/,$p'

# 5. free space, which is the only one that has to be watched continuously
df -h /
```

If your appliances are across a WAN, **only `t_dev` changes** — and it changes a
lot. Re-run (4) before sizing; the disk formula is unaffected.

---

## 5. The free-space floor (non-negotiable)

> **Keep at least `max(15 % of the volume, 3 GB)` free at all times, and alert
> on it.**

The margin is not for growth — the formulas above cover growth. It is for the
three things that need room *at the moment they run*:

* a bundle build writes a full compressed copy of `data/` before it prunes;
* PostgreSQL needs room for WAL and for a checkpoint it cannot defer;
* an offline update package is staged, verified and only then applied.

A node that is 100 % full is not "a bit slow": per §3.3 it is a database in a
crash loop behind a health check that says 200.

**On a shared/development node**, add the sweep that stops test scratch from
being the thing that fills the disk — pytest basetemps and mutation mirrors are
never cleaned by Debian's stock `/tmp` rule, which carries no age:

```
# /etc/tmpfiles.d/satom-scratch.conf
e /tmp/pytest-of-*    - - - 2d
e /tmp/pt-*           - - - 2d
e /tmp/mut_*          - - - 2d
e /tmp/satom_mirror*  - - - 2d
```

---

## 6. Provenance

| | |
|---|---|
| Measured on | 2026-08-22 / 23, primary production node |
| Node | 4 vCPU · 4 GB RAM · 20 GB disk · Debian 12 |
| Software | PostgreSQL 15, VictoriaMetrics 1.148.0 OSS, Python 3.11 |
| Fleet at measurement | 12 registered appliances (5 collected), 808 series, 1.57 M samples over 12.7 days |
| Appliance firmware | FortiWeb 7.6.8, LAN |

Every number in §2 is reproducible with §4. Where a figure is extrapolated
rather than measured — the 100-device row of the disk table, and the
FortiAnalyzer snapshot size — it is labelled as such in the row it appears in.
