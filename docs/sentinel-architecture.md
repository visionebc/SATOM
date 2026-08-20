# SATOM Sentinel — security correlation and autonomous response

Sentinel answers a question the rest of SATOM cannot: **what is actually
happening right now, across every layer at once?** It correlates attack
signatures, HTTP outcomes, appliance internals, the VM the appliance runs in,
the hypervisor under that, the backend behind it and vulnerability
intelligence — into single incidents that explain themselves.

The console lives at `/sentinel`. Its in-product documentation page
(`/sentinel/docs`) renders the weight table, the action catalog and the
settings list **from the running code**, so those numbers cannot go stale the
way a hand-written copy does.

---

## 1. Two paths, and why the model is not in the middle

```
 SOURCES   FortiWeb attack log (GUI session)  ·  traffic log (HTTP status)
           fleet metrics collectors           ·  Proxmox / ESXi provider
     │
     ▼
╔═══ HOT PATH — deterministic, always runs ══════════════════════════════════╗
║ normalize ─► enrich ─► correlate ─► baseline ─► score ─► incident ─► policy ║
║    raw       context    window     median/MAD  integer   absorb     gates   ║
╚════════════════════════════════════════════════════════════════════════════╝
     │                                                    │
     │                                                    ▼
     │                                       proposals (never executed here)
     ▼
╔═══ COLD PATH — AI, asynchronous, optional ═════════════════════════════════╗
║ incident ─► local model ─► JSON opinion (closed enum) ─► incident.ai_json   ║
║ no tools · no network of its own · no credentials · cannot change a score   ║
╚════════════════════════════════════════════════════════════════════════════╝
```

The obvious design puts the language model in the middle, where it would
"help". It is not there, for one reason: the number produced by this pipeline
gates changes to a production firewall, and that number has to be reproducible
line by line during the post-mortem that follows the one time it was wrong. A
component whose output is sampled from a distribution cannot be. It also fails
in the worst possible moment — a flood, a saturated node — which is exactly
when the hot path must still work.

**What survives an AI outage:** detection, correlation, scoring, evidence,
gating, history. **What is lost:** the narrative. That asymmetry is the design.

---

## 2. Correlation

The unit of correlation is the **topology**, not the log. `sentinel_topology`
binds `appliance ↔ hypervisor target ↔ VM id ↔ node ↔ backends`, and with that
row in place resolving a window is a label join against the node's local
VictoriaMetrics.

A trigger opens a window `[T0 − pre, T0 + post]` (default 60 s / 300 s) and
every layer is read over loopback — **zero appliance calls**. During an
incident the device is by hypothesis already loaded, and a monitor that adds
round-trips then becomes part of the outage.

Each layer contributes its delta against its own hour-of-week baseline **plus
the lag** between T0 and the moment it moved. The lag is what carries
causality:

```
attack(SQLi) T0 ─► appliance CPU +2s ─► VM CPU +3s ─► disk I/O +3s ─► backend p95 +8s
```

That ordering is a chain. The same five readings with no ordering are five
coincidences, and `causal_chain` only scores when at least two layers moved in
sequence after T0.

> **A window extends into the future.** At the moment an incident opens, the
> `T0 + 300 s` half has not happened yet, so the first score is deliberately
> provisional. Every sweep re-correlates open incidents, which is what fills
> it in. An incident's score is expected to move for the first few minutes.

**Layers with no topology row report `unknown`, never `no impact`.** Those two
drive opposite operator decisions, and collapsing them is precisely how a
saturated hypervisor reads as a quiet one. `None` survives from the correlator
through the score into the incident's impact flags and onto the page.

---

## 3. Behavioural baseline — median and MAD, per hour of week

A security baseline is trained on data that *contains attacks*. With mean plus
standard deviation, one 8,500 req/s flood raises the centre and inflates the
spread, so the **next identical flood scores as less anomalous than the first**
— the detector desensitises itself with every incident it sees. The median is
unmoved by a minority of extreme samples and the MAD inherits that immunity.
This is the property that makes the number usable without a human curating the
training set.

168 buckets, one per hour of the week: 8,000 req/s at Tuesday noon may be a
sale; the same figure at Sunday 03:00 is not. It also keeps the output
arguable — *"17× the Tuesday-12h median"* is a sentence someone can dispute,
which is the point.

* MAD is scaled by 1.4826 so `k` keeps its sigma-multiple intuition on
  well-behaved series while staying robust on the rest.
* A **flat series** (MAD = 0) cannot produce an infinite deviation: the
  fallback is sign-preserving and capped, so an idle series can report "this
  changed" and never "this is the most anomalous event in the fleet".
* Buckets below the sample floor stay `learning` and **never fire**. An
  immature baseline that fires is a false-positive generator wearing
  statistics as a costume.
* A maintenance window with `freeze_baseline` **drops** its samples rather than
  learning them — otherwise an authorised pentest teaches the detector that a
  flood is normal.

Machine learning was considered and rejected for v1: an isolation forest
produces a score nobody can defend in a review, needs its own retraining and
drift monitoring, and would be a second non-deterministic component in a system
whose entire safety argument is reproducibility. Median/MAD costs one nightly
pass over a store that already holds 396 days raw, and every number it emits
can be recomputed by hand.

---

## 4. HTTP outcomes

**An HTTP status is not a vulnerability**, and nothing here pretends otherwise.
A 500 is a symptom that may come from an RCE, from a backend saturated by
volume, or from an ordinary bug. What the status carries is the *outcome* of
each attack request, and the two outcomes are opposites:

| pattern vs baseline | reading |
|---|---|
| 401 / 403 burst from one source | authentication attack — brute force, credential stuffing |
| many 404s over many distinct URIs | enumeration; reconnaissance, not exploitation |
| 403 dominant, from the WAF | **lowers** the score — the attacker is being stopped |
| 2xx on a request carrying an attack signature | **raises** it sharply — evasion suspected |
| 5xx surge behind the policy | backend impact: a crashed worker, or exhaustion |

A design that only counts attack events treats the third and fourth rows
identically. Telling them apart is what lets one evaded request outrank a wall
of successfully-blocked noise.

### Where the data comes from — measured, not assumed

The obvious source, `policy_status`, was probed live against **fortiweb12
(7.6.8) on 2026-08-20** and carries **no** response-class counters. Its full
field set is:

```
_id, app_response_time, client_rtt, connCntPerSec, httpPort, id, mode,
name, policy, protocol, server_rtt, sessionCount, status, vserver
```

An earlier draft of the collector read `http_2xx` / `http_5xx` from those rows.
Those names do not exist. The collector would have raised on every run — or,
had it defaulted them, published a flat line of zeros that reads on a chart
exactly like a quiet service.

The real source is the **traffic log**, reached by the same GUI-session path
`app.services.attack_log` recovered for the attack log:
`GET /api/v2.0/log/logaccess.traffic?log=tlog.log`. Probed live on the same
device: **HTTP 200, correct `results.payload` envelope**.

> ⚠ **Known limit.** fortiweb12/13 are a laboratory with no live traffic, so
> all three log endpoints returned **zero rows**. The endpoint is verified; the
> individual field names inside a traffic-log row are **not** — there was no
> row to read them from. The collector therefore accepts several spellings and
> **raises a message naming the keys it actually saw** when none match. It does
> not invent a value.

---

## 5. Vulnerability intelligence

Keyed on the signature, and **first on the CVE the device itself attached to
the entry** (`signature_cve_id` on a FortiWeb attack-log row). That is the
vendor's own statement about its own signature and is better evidence than any
local mapping table; `sentinel_signature_cve` is the fallback for entries that
carry none, kept as data so a wrong mapping is fixable without a release.

**EPSS and CISA KEV outrank CVSS.** CVSS scores how bad a vulnerability would
be if exploited; EPSS estimates whether it will be; KEV records that it already
has been. A 9.8 nobody exploits is a worse use of an on-call night than a 7.5
with a Metasploit module.

**The cross-check that reduces the most false positives** is CVE ∩ the product
the target actually runs (the `cpe` on a topology backend entry). An exploit
aimed at software nobody is running is noise, however severe the CVE — and when
no product is recorded the answer is *"could not check"*, never *"not
affected"*.

### The wall

Enrichment reads `sentinel_vuln` **and nothing else**. There is no HTTP client
reachable from the incident path, and a test asserts it rather than a comment
promising it.

A live per-incident lookup would tell a third party, in real time, exactly
which CVEs and signatures this fleet is seeing — a continuously updated map of
the customer's attack surface, exported as a side effect of defending it. The
latency argument is real but secondary; the disclosure argument decides.

`sentinel.vuln_sync_enabled` is a **separate switch** from
`sentinel.vuln_enabled`, and off by default, so "use vulnerability
intelligence" and "talk to the internet" stay two different decisions.
A mirror older than the configured horizon still enriches — old intelligence
beats none — and every incident it touches says it is stale.

---

## 6. Scoring

Deterministic arithmetic over measured evidence. The AI layer may disagree with
the result in prose; that disagreement is displayed, not resolved in the
model's favour.

Weights live in `scoring.WEIGHTS` as data, so a change is a one-line diff a
reviewer can see and the published table is *rendered from the same dict*. Each
factor applies **at most once per incident** — enforced structurally, because
an "add points per matching event" loop is how a flood scores 4,000 and every
incident collapses into the same band.

### Negative factors are half the value

Most scoring designs only add. These subtract, and the subtractions are what
make the number usable:

| factor | why it subtracts |
|---|---|
| `waf_blocked` | The appliance stopped it. A thousand blocked SQLi attempts is a WAF doing its job; paging someone for it teaches them to ignore the console. |
| `not_vulnerable` | The CVE does not affect what the backend runs. |
| `trusted_source` | An authorised scanner produces a **byte-identical** log to an intruder. Only context separates them, so context outweighs any single positive factor. |
| `maintenance_window` | Surprise was expected here. |
| `baseline_immature` | Behaviour could not be judged, so claim less. |

Bands: `< 40` observe · `40–69` investigate · `70–84` recommend · `85+`
eligible for a pre-authorised action.

---

## 7. Incidents

Identity is `(device, source, attack family)`, not a timestamp. While its
window is live an incident **absorbs** matching events instead of opening a
sibling. Without that a 60-second flood produces thousands of incidents and the
console becomes the log it was built to replace.

* **Evidence is rebuilt, never appended** on a re-score — the first
  correlation's numbers sitting beside the fifth's leave an operator unable to
  tell which sentence describes now. The timeline is the opposite,
  append-only, because a history that is rewritten is not one.
* **Every evidence row carries the value AND the baseline.** "CPU is high" is
  an assertion; "CPU 91% against a Tuesday-12h median of 22% (4.1×)" is
  evidence, and only the second can be argued with.
* **`false_positive` is a terminal state of its own**, not a flavour of
  `closed`, and the reason is mandatory. Closing a real incident and dismissing
  a false one are different facts about the detector; folding them together
  destroys the only signal available for tuning it, and a dismissal with no
  cause is a silent vote to keep generating the same alert forever.
* The false-positive **rate is computed over closed incidents only** —
  including open ones would make the metric improve whenever an operator falls
  behind.
* Historical similarity is **structural** (family, source, device, policy), not
  text similarity over an AI narrative: matching on prose would make history a
  function of what a model happened to write, which is not a property of the
  attack.

---

## 8. Response

Ships as **proposals**. Every entry in the catalog carries `verified=False`,
and the last gate refuses any action whose transport has not been executed and
re-read on a live appliance of this product.

That is not caution theatre. A live sweep of this product's own configuration
surface on 2026-08-20 found **22 of 237 documented FortiWeb routes answer
`-20001 "invalid URL"`** — written from the reference manual and never
validated against a device. A blocking rule built the same way fails at the
moment it is most needed, or succeeds against the wrong object.

### Gate order, and why it is this order

1. **Global kill switch** — one setting disables everything, everywhere.
2. **Protected network** — before anything about confidence, so a correlation
   bug concluding our own monitoring host is an attacker is *structurally*
   unable to act on it. An unparseable address counts as protected: cannot
   parse ⇒ cannot prove it is safe to block.
3. **Trusted source / maintenance window.**
4. **Policy exists, is enabled, and its level permits acting.**
5. **Score meets that action's own floor.**
6. **Reversibility and TTL.**
7. **Circuit breaker** — a fleet-wide hourly ceiling, so a correlation bug
   during a flood exhausts a budget rather than a firewall.
8. **Mechanism verified.**

Every gate returns a **reason**, and the reasons are shown on the incident.
"Sentinel did nothing" is not an acceptable console state; "did nothing because
the source is inside 10.0.0.0/8" is. Refused proposals are recorded too —
*"Sentinel wanted to do X and was refused because Y"* is exactly the record
needed to tune autonomy, and it is invisible if only permitted actions are kept.

**TTL is the rollback.** An undo that must itself succeed is not a rollback; it
is a second operation that can fail, attempted at the moment the first already
has. Expiry needs nothing to work.

`block_country` is capped at *recommend* forever: one mis-attributed source
address would take an entire market offline.

---

## 9. The AI wall

`reason(incident) -> opinion`. The model receives a finished incident that
already has a score and evidence, and returns prose plus a recommendation drawn
from a **closed enum**. It has no tools, no network access of its own, no
credentials, and no writer to any field an operator reads as a measurement.

Its output lands in `SentinelIncident.ai_json`, stamped with the model name and
a **hash of the prompt**, so months later it is answerable: *what exactly was
this model shown when it said that?*

* Timeout, refused connection, malformed JSON, an out-of-enum recommendation:
  all produce `{"ok": False, "error": …}` and the incident carries on intact.
* A rejected value is stored **as the model literally wrote it** — tidying it
  up would misrepresent the one thing that field exists to record.
* `think: False` is sent on every call: qwen3 thinking models otherwise return
  an empty `content` with the answer in `thinking`, which turns a working model
  into a silent empty reply.
* When model and policy engine disagree, both are shown and **the policy engine
  stands**.

---

## 10. Data model

| table | holds |
|---|---|
| `sentinel_topology` | appliance ↔ hypervisor ↔ VM ↔ node ↔ backends (with CPE) |
| `sentinel_event` | normalised security events (raw), deduplicated by content |
| `sentinel_baseline` | median / MAD / p95 per series per hour-of-week |
| `sentinel_anomaly` | measured deviations |
| `sentinel_incident` | the correlated scenario, its score breakdown and impact |
| `sentinel_incident_event` | append-only timeline |
| `sentinel_evidence` | one measured claim per row, with its baseline |
| `sentinel_policy` | what each action type is allowed to do |
| `sentinel_action` / `sentinel_action_result` | proposals, approvals, verification |
| `sentinel_trusted_source` | authorised scanners/monitors, **with expiry** |
| `sentinel_maintenance_window` | when surprise is expected |
| `sentinel_vuln` / `sentinel_signature_cve` | the local CVE mirror and its bridge |

Time-series data is **not** here. Rates, CPU, memory, throughput and HTTP
status counts live in the node's VictoriaMetrics; Sentinel queries them by
label at correlation time. A second copy per incident would re-open a decision
this product already paid for with a measurement (~875 B/sample in Postgres →
~450 GB at fleet scale).

> **Naming:** every table carries the `sentinel_` prefix because `baselines`
> was **already taken** in this product by an unrelated concept — a "combo"
> binding approved templates to a zone/line/department permutation
> (`app/services/baselines.py`). A behavioural baseline and a configuration
> combo share nothing but a word.

---

## 11. Collection

Sentinel adds two collectors to the existing fleet registry, so their cadence
is edited on the **same page** as every other collector — a second collection
settings page is how two cadence models drift apart.

| collector | reads | default |
|---|---|---|
| `http_status` | traffic log → response-class counts per policy | 5 min |
| `infra` | hypervisor API → VM + host metrics, via the topology map | 3 min |

`infra` talks to the hypervisor, never to the appliance. Cumulative counters
(`*_bytes_total`) are published **as counters**; the rate is derived by the
store, which handles the reset a VM restart causes — a collector-side delta
goes negative across that restart and becomes a nonsense spike exactly while
someone is reading the graph.

The hypervisor abstraction gained `vm_metrics()` / `node_metrics()` as an
**optional capability**: a backend that cannot answer raises, and the caller
reports the layer as *unknown*. Proxmox is implemented (`cpu` arrives as a
fraction 0–1 and is scaled — forwarding it unscaled would put `0.88` on an axis
labelled `%`, and 0.88% reads as an idle machine at the moment it saturates).

---

## 12. Running it

| scheduled action | cadence | cost |
|---|---|---|
| `sentinel_sweep` | every 3 minutes | reads appliances; skips maintenance |
| `sentinel_baseline` | nightly | reads the local TSDB only — no device |
| `sentinel_vuln_sync` | daily | the only outbound component; inert until switched on |

Three actions rather than one, because folding them together would mean an
operator who wants nightly baselines also gets a daily outbound call — exactly
the coupling the separate switch exists to prevent.

A sweep that **ran** is `ok` even when devices errored; failures ride in the
log. An action that goes permanently red because one appliance is unreachable
teaches operators to ignore the colour, which is worse than the outage. Every
sweep writes `satom_sentinel_up` and per-stage counters, so "the pipeline
stopped" and "the pipeline ran and found nothing" are different pictures on a
graph rather than the same flat line.

### Bringing a new installation up

1. Map each appliance to its VM and hypervisor node under
   **Sentinel → Context**. Until then the VM and host layers report *unknown*.
2. Let collection run, then recompute baselines. The console shows how many
   buckets are usable; behavioural factors mean nothing before that.
3. Register scanners and monitors as trusted sources, **with expiry dates**.
4. Populate the CVE mirror — sync if outbound is permitted, otherwise by hand.
5. Leave the response engine disarmed until the incident stream has been
   reviewed by a human for long enough to trust it, and until at least one
   action transport has been verified on a real device.

---

## 13. Verification

* `tests/test_sentinel_scenarios.py` — the ten scenarios from the design brief
  as reproducible fixtures, plus the claims they rest on.
* `tests/test_sentinel_pages.py` — every page renders with real data, and says
  the right thing: an unknown layer as *unknown*, a refusal with its reason,
  the model's output labelled as opinion.
* **25 mutations, 25 kills.** Each breaks one load-bearing claim — the kill
  switch, the protected-network gate, the mechanism-verified gate, MAD
  robustness, trust expiry, the `false_positive` reason requirement, KEV over
  CVSS, the settings clamp, the docs page rendering live weights. A guard that
  does not bite is decoration.

Two of those mutations survived the first pass, and **both were holes in the
tests rather than in the code** — both on the negative-factor claims. Scenario
10 asserted only "score below the band", which a weight flipped from −12 to
+12 still satisfied; and the evasion test compared a 200 against *denied*
requests, so it passed on the strength of `waf_blocked` alone and stayed green
with the evasion weight deleted entirely. Both were rewritten to isolate the
claim they are actually making.
