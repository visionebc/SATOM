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

---

## 2. Flow diagrams

The same four drawings are rendered as scalable SVG on `/sentinel/docs` §2, and
the decision ladder there is **generated from `actions.GATE_ORDER`** rather than
drawn beside it. A picture of a decision chain is the easiest artefact in a
repository to leave behind: nothing fails when it and the code disagree, and the
person reading the picture is the one who finds out.

### 2.1 Reference architecture

```
 SOURCES (read-only)          ┌──────────────────────────────────────────────┐
 ┌───────────────────┐        │ HOT PATH — deterministic, always runs        │
 │ FortiWeb attack   │        │                                              │
 │   log (GUI sess.) │        │ normalize → enrich → correlate → baseline    │
 │ FortiWeb traffic  │  ┌───┐ │            → score → incident                │
 │   log (HTTP class)│─►│col│►│                                              │
 │ fleet metrics     │  │lec│ │ no model · no credential that writes         │
 │ Proxmox / ESXi    │  │tor│ └───────────────┬──────────────────┬───────────┘
 └───────────────────┘  └───┘                 │                  │
                                              ▼                  ▼
                              ┌───────────────────────┐  ┌────────────────────┐
                              │ PostgreSQL            │  │ VictoriaMetrics    │
                              │ 14 sentinel_* tables  │  │ 127.0.0.1:8428     │
                              │ events · incidents ·  │  │ 396 days raw       │
                              │ evidence · actions ·  │  │ loopback only      │
                              │ policies · trust ·    │  │ baselines and the  │
                              │ windows · CVE mirror  │  │ evidence windows   │
                              └───────────┬───────────┘  └────────────────────┘
                                          │
                 ┌────────────────────────┴───────────────────────┐
                 ▼                                                ▼
   ┌───────────────────────────┐              ┌────────────────────────────────┐
   │ CONSOLE /sentinel         │              │ COLD PATH — the model          │
   │ web worker may only move  │              │ incident → local LLM → JSON    │
   │ a row to "queued"; it     │              │ opinion (closed enum)          │
   │ never touches an appliance│              │ no tools · no credentials      │
   └────────────┬──────────────┘              └────────────────────────────────┘
                ▼
   ┌──────────────────────────────────────┐        ┌────────────────────────┐
   │ RESPONSE RUNNER                      │        │ FortiWeb               │
   │ satom-responder.timer, every 60 s    │───────►│ ip-list member         │
   │ gates → preflight → apply → re-read  │        │ geo country-list member│
   │       → judge → expire               │        │ policy → profile       │
   │ the ONLY component with a credential │        └────────────────────────┘
   │ that writes enforcement              │
   └──────────────────────────────────────┘
```

### 2.2 Processing — one attack-log row to one proposal

```
COLLECT ─► NORMALIZE ─► ENRICH ─► STORE ─► CORRELATE ─► BASELINE ─► SCORE
  rows      one shape    trust     event    5 layers     vs median   0…100
                         window             T-60s…T+5m   and MAD
                         asset                  ▲            ▲
                                                └── reads ───┘
                                                 VictoriaMetrics
                                                      │
                                    ─► INCIDENT ─► PROPOSE (closed catalog)
                                       absorb or     never executed here
                                       open new
```

A layer that could not be measured stays **`unknown`**. It never becomes
"no impact": on a page the two look identical and they mean opposite things.

### 2.3 Decision — the gate chain

```
                    proposed action + live incident
                                  │
   1 catalog ─────────────────────┼──► refuse: no blast radius, no ceiling, no undo
   2 kill_switch ─────────────────┼──► refuse: response engine disarmed
   3 protected_network ───────────┼──► refuse: our own address space
   4 trusted_source ──────────────┼──► refuse: authorised activity
   5 maintenance_window ──────────┼──► refuse: work we scheduled
   6 policy_exists ───────────────┼──► refuse: nobody decided anything here
   7 policy_enabled ──────────────┼──► refuse: disabled means stopped
   8 level ───────────────────────┼──► refuse: proposal for a person (valid outcome)
   9 confidence ──────────────────┼──► refuse: below THIS action's own floor
  10 ttl ─────────────────────────┼──► refuse: it would not expire on its own
  11 circuit_breaker ─────────────┼──► refuse: hourly budget spent
  12 executable_mechanism ────────┼──► refuse: hand-off — a person applies it
  13 mechanism_verified ──────────┼──► refuse: specification, not a transport
                                  ▼
                    queued for the response runner
                                  │
              ... and all thirteen again, at execution time,
                  in a different process, under that moment's state
```

### 2.4 Response, verification and rollback

```
 queued ─► gates re-evaluated ─► preflight (ask the DEVICE) ─► apply ─► re-read
                                          │                              │
                          "the profile does not reference the            ▼
                           Sentinel list" ⇒ refuse. A member      wait the effect
                           on an unreferenced list returns 200,   window, compare
                           counts up, and blocks nothing.         source volume
                                                                        │
                        ┌───────────────┬────────────────┬──────────────┘
                        ▼               ▼                ▼
                   effective        unknown         ineffective
                   → mitigated    no prior data     escalate — and
                                  → never "success"  never retry

 ROLLBACK — two independent timers, redundant on purpose
   appliance  : action=block-period   lifts even if SATOM is dead
   Sentinel   : TTL deletes the member, and runs even with the kill switch off
```

## 3. Correlation

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

## 4. Behavioural baseline — median and MAD, per hour of week

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

## 5. HTTP outcomes

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

## 6. Vulnerability intelligence

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

## 7. Scoring

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

## 8. Incidents

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

## 9. Response

**Three mechanisms execute, one is a hand-off.** Every one of them was
captured from fortiweb12 (FortiWeb 7.6.8) on 2026-08-20 by running it against
the appliance and reading the result back — not from the reference manual.

| action | mechanism | captured |
|---|---|---|
| `block_ip` | `POST waf/ip-list/members?mkey=…` `{type: black-ip, ip}` | create list, add member, re-read (`sz_members` 0→1), delete member, delete list, zero residue |
| `block_country` | `POST waf/geo-block-list/country-list?mkey=…` `{country-name}` | create list, add `Andorra` → id 1, re-read row present, delete, delete list, zero residue |
| `raise_protection` | `PUT server-policy/policy?mkey=…` `{web-protection-profile}` | read the original off `pol-root-wiki`, PUT a hardened profile, re-read matched, PUT the **captured original** back, re-read matched |
| `tune_signature` | hands the incident to `app.services.attack_carveout` | **no appliance write** — the draft lands in the existing exception flow and a person applies it |

The hand-off is labelled as one rather than counted among the unverified,
because the two answer different questions: *does the mechanism work* and *does
this engine execute it*. Collapsing them would either park a working hand-off
behind an appliance test it will never take, or let the runner try to perform a
device write that does not exist. Gate 12 refuses it by name, and the refusal
says where the work actually happens.

That distinction is not caution theatre. A sweep of this product's own
configuration surface on 2026-08-20 found **22 of 237 documented FortiWeb
routes answer `-20001 "invalid URL"`** — written from the reference manual,
never validated against a device. This module's own first draft was one of
them: it named `waf/http-access-limit` as the mechanism for `rate_limit_ip`,
and that route does not exist on this firmware.

### `rate_limit_ip` was withdrawn, not left pending

FortiWeb has no per-address rate limit. What it offers is flood-prevention
rules whose thresholds apply to **every client of a profile**. Keeping the
entry would have advertised a blast radius of one source while the only
available mechanism has a blast radius of every client. An action that cannot
be built is not a roadmap item on a live console — it is a lie with a button
next to it. The orphan policy row an earlier release created is pruned, unless
actions reference it, in which case it stays so its audit trail survives.

### The chain, and the precondition that decides everything

A server policy does not name an IP list. It names a profile, and the profile
names the list:

```
server-policy/policy .web-protection-profile
  -> waf/web-protection-profile.inline-protection .ip-list-policy
       -> waf/ip-list
            -> waf/ip-list/members?mkey=<list>
```

So **adding a member to a list no profile references blocks nothing.** The POST
returns 200, `sz_members` counts up, and the console would show a green
"applied" badge while the attacker carried on. That is the `ca-group` defect
this product already shipped once — an object created, valid, and bound to
nothing — one level further up.

Therefore the transport **re-reads the profile off the device before every
apply** and refuses with an actionable reason if the reference is absent. And
the incident path never creates or binds anything: arming a policy is a
separate, human-triggered operation on the Context page. An agent that binds
its own enforcement point is an agent that can widen its own authority.

### Two traps the geo capture exposed

**A wrong child path is not an error.** `GET waf/geo-block-list/members?mkey=X`
answers **HTTP 200 with the parent object** — the list record itself, complete
and successful-looking — instead of 404. Code that checked only the status code
would "verify" a write against an endpoint incapable of holding it. The real
child collection is `country-list`, and `_child_rows()` treats anything that is
not a list as no rows.

**This appliance does not take ISO country codes.** The member key is
`country-name` and it wants a full name: `{"country": "Andorra"}` and
`{"country": "AD"}` both answer `errcode -7950 "The country name is empty or
wrong."` So the source country is stored **verbatim** as the device reported it
(`srccountry`, in a 64-character column — it was 8, which both mislabelled the
source as `United S` and destroyed the only value the block mechanism accepts),
and the transport refuses a value that is three characters or shorter with a
reason instead of guessing an expansion. Sentinel does not invent the string it
is about to hand back to a firewall.

**`raise_protection` has no device-side timer.** A blocked address expires by
itself because the list carries `block-period`; a profile binding does not. So
its undo is a *write*, the previous profile is read off the device before the
change and carried in the handle, and rollback **refuses an empty binding** —
unbinding the profile would strip protection from every client of that policy,
which is worse than the state being undone. The target must be named by a
person in Settings → Sentinel → *Hardened web protection profiles* and must
already exist on the appliance. Sentinel does not author protection profiles,
and it does not choose which one your clients sit behind.

### Applied is proved by re-reading, never by the status code

`policy.scripting.text` on this product answers **200** with
`"Scripting doesn't contain any event."` A 200 is a receipt, not an outcome. So
every write is followed by a read of the object it claimed to change, and a
device that accepts a member and stores nothing is recorded as a **failure**.

### Two separate verdicts: applied, and effective

`applied` means the rule is on the appliance, re-read from it. `effective`
means the attack volume from that source actually fell. They fail differently,
and a rule that is present and useless is exactly the case that must escalate —
invisible to a check that only confirms the write. An action judged
`ineffective` moves its incident back out of `mitigated` (an incident marked
mitigated on an action that changed nothing is making a false claim) and is
**never retried**. Retrying the thing that just did not work, harder, is how an
automation turns a bad minute into a bad hour.

With no events in the window before the action there is nothing to compare
against, and the verdict is `unknown` — never `success`. "We do not know" must
not render as a win.

### Gate order, and why it is this order

Thirteen checks, in this order, from `actions.GATE_ORDER` — the tuple the test
suite asserts a full pass through `evaluate()` emits:

1. **`catalog`** — an action type outside the catalog has no blast radius, no
   ceiling and no undo. There is nothing to reason about.
2. **`kill_switch`** — one setting disables everything, everywhere.
3. **`protected_network`** — *before* trust, so our own address space stays
   unblockable even if somebody empties the trust list. An unparseable address
   counts as protected: cannot parse ⇒ cannot prove it is safe to block.
4. **`trusted_source`** — an authorised scanner produces a log byte-for-byte
   identical to an intruder's. Only context separates them.
5. **`maintenance_window`** — work we scheduled must not be answered by a
   firewall rule.
6. **`policy_exists`** — no row means nobody decided anything here.
7. **`policy_enabled`** — disabling has to stop the thing, not hide it.
8. **`level`** — below semi-automatic the action is a proposal for a person,
   which is a valid outcome and not a failure.
9. **`confidence`** — the floor belongs to the action: a country block does not
   borrow an address block's threshold.
10. **`ttl`** — the primary rollback is expiry.
11. **`circuit_breaker`** — a fleet-wide hourly ceiling, so a correlation bug
    during a flood exhausts a budget rather than a firewall.
12. **`executable_mechanism`** — a hand-off is drafted here and applied
    elsewhere; refusing it here lets the refusal name where.
13. **`mechanism_verified`** — 22 of 237 documented routes on this product
    answer `invalid URL`. A mechanism read from a manual is a specification.

Then, at execution time and in a different process, both again:

**Every gate re-run.** An action approved at 12:00 executes under 12:03's
state. In between somebody may have thrown the kill switch, opened a
maintenance window, or added the source to the trust list — each of which is a
person deciding *not this*. Trusting the verdict recorded at enqueue time
carries out a decision the world has since reversed.

**Transport preflight** — the appliance itself is asked whether it can enforce,
before anything is written.

Every gate returns a **reason**, and the reasons are shown on the incident.
"Sentinel did nothing" is not an acceptable console state; "did nothing because
the source is inside 10.0.0.0/8" is. Refused proposals are recorded too —
*"Sentinel wanted to do X and was refused because Y"* is exactly the record
needed to tune autonomy, and it is invisible if only permitted actions are kept.

**TTL is the rollback.** An undo that must itself succeed is not a rollback; it
is a second operation that can fail, attempted at the moment the first already
has. Expiry needs nothing to work.

`block_country` is capped at *recommend* forever: one mis-attributed source
address would take an entire market offline. An operator may set its policy to
autonomous; the engine still caps the effective level at the catalog ceiling.
Level 3 means *skip the approval step for a decision that was already
permitted* — never *permit more*.

### Where execution lives

The web tier can only move an action row to `queued`. `satom-responder.timer`
runs `satom-responder.service` once a minute, which re-checks the gates,
preflights, applies, expires and judges. A bug in a view — a double submit, a
crawler, a stray retry — can therefore at worst enqueue a request the runner
refuses on its own merits.

**It acts from one node only.** `tick()` reads
`pg_is_in_recovery()` and refuses on anything that is not the primary — with
`unknown` counted as not-primary, because a node that cannot say what it is
must not be the one writing enforcement rules. The read-only replica is *not*
the guard: leaning on it would turn a design error into a database error inside
the component that changes firewalls, and it would disappear the moment a
standby were promoted. A refusal that turns out to be a process bound to SQLite
(the config binds at import, before wsgi loads the `.env`, so a run from a bare
shell falls back to the development database) says so in those words, because
that tick would otherwise find nothing to expire and look like a clean pass.

**Expiry runs even when the kill switch is off.** This is the one asymmetry and
it is deliberate: disarming must stop *new* blocks, but if it also stopped
expiry, throwing the kill switch mid-incident would strand every live block
permanently — the safety control would cause the outage. Stopping is not
freezing.

TTL is enforced **twice**. The Sentinel IP list carries
`action=block-period`, so the appliance lifts the block by itself; Sentinel
also deletes the member when its own TTL comes due. The device-side expiry is
the one that matters, because it survives Sentinel being dead — precisely the
moment a stuck block would otherwise never be lifted.

One decision produces one row. The sweep re-proposes for every open incident
every three minutes; without deduplication on the live statuses, an incident
open for an hour would accumulate twenty identical proposals — harmless while
nothing executed, twenty firewall writes for one decision once something does.

---

## 10. The AI wall

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

## 11. Data model

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

## 12. Collection

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

## 13. Running it

| scheduled action | cadence | cost |
|---|---|---|
| `sentinel_sweep` | every 3 minutes | reads appliances; skips maintenance |
| `sentinel_baseline` | nightly | reads the local TSDB only — no device |
| `sentinel_vuln_sync` | daily | the only outbound component; inert until switched on |

Three actions rather than one, because folding them together would mean an
operator who wants nightly baselines also gets a daily outbound call — exactly
the coupling the separate switch exists to prevent.

All three are part of `satom execute seed actions`, so a fresh install gets
them and `satom diagnose install` reports their absence rather than leaving a
module that has every table, page and gate and silently never opens an
incident.

Two systemd units carry the rest:

| unit | cadence | what it does |
|---|---|---|
| `satom-responder.timer` | every 60 s | applies queued actions, judges effectiveness, **expires TTLs** |
| `satom-metrics.service` | continuous | the local VictoriaMetrics the baselines read |

`satom-responder.timer` is **not optional once anything has been armed**. It is
inert while the kill switch is off — a tick with nothing to do prints
`{"expired": [], "applied": [], "judged": [], "armed": false}` — but expiry
lives in that tick, so a node without it can hold a live block that nothing
will ever lift. The console reports its absence rather than leaving it for
someone to discover when a block never comes off.

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
5. If you intend to enforce, arm the specific policies under
   **Sentinel → Context** — separately for address blocking and for country
   blocking, because those are decisions about one attacker and about a whole
   market. For `raise_protection`, name the permitted hardened profiles in
   **Settings → Sentinel**; with that field empty the action can never run,
   which is the correct default.
6. Enable `satom-responder.timer`. Without it nothing expires.
7. Leave the response engine disarmed (Settings → Sentinel → *Response engine
   armed*) until the incident stream has been reviewed by a human for long
   enough to trust it. The roadmap gate for level 3 is thirty days of
   supervised level-2 operation without an incorrect action — a date, not an
   opinion, and not something a release can shorten.

---

## 14. Verification

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
