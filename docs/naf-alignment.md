# SATOM and the NAF Framework

> **Audience:** architects, auditors and integrators who need to place SATOM
> in a vendor-neutral reference model, and the team that keeps this mapping
> honest. The matrix in §6 is the **only** place the conformance state is
> recorded; every other document links here instead of repeating it.
>
> **Status line (generated from the matrix, checked by a test):**
>
> <!-- naf-verdict:begin -->
> SATOM is conformant to the NAF Framework (commit da82b12): every MUST requirement is met.
> <!-- naf-verdict:end -->

---

## 1. Source, version pin and licence

- **Source:** Network Automation Forum, *The NAF Framework* —
  https://reference.networkautomation.forum/Framework/Framework/
- **Repository:** https://github.com/Network-Automation-Forum/reference,
  file `docs/Framework/Framework.md`.
- **Pinned commit: `da82b12` (2026-04-28)** — the last change to that file
  when this mapping was written. The framework carries **no version number**,
  so every SATOM surface that names it names this commit; a later rewrite of
  the framework cannot silently invalidate the matrix below. The release
  checklist ([release pipeline](release-pipeline.md)) diffs the upstream file
  against the pin on every cut.
- **Licence:** the reference repository is published under **CC0 1.0**. The
  diagram and the block icons on this page are reproduced from it unchanged
  (see `NOTICE`); their use follows the project's brand guidelines (block icon
  to the left of the block title).
- **There is no NAF certification.** The conformance recorded here is a
  self-assessment against the pinned commit, checked by a test in this
  repository; the wording is *conformant (self-assessed)* or *mapped to*,
  never *certified*.

## 2. Why SATOM aligns with it

1. **Vendor-neutral and community-maintained.** The framework is not a
   product's architecture rebranded as a standard.
2. **MUST / SHOULD / MAY makes conformance checkable.** Each requirement is a
   sentence that is either met, partly met or not met — a matrix, not an
   opinion.
3. **A shared vocabulary.** Customers, auditors and integrators who know the
   framework can read SATOM's architecture without learning SATOM's names
   first (§4 translates them).
4. **SATOM as one block in a customer's stack.** A customer's NetBox can be
   the Intent block and their SIEM part of Observability; the framework's
   block boundaries are where SATOM plugs in.
5. **A yardstick for the roadmap.** Every open row in §6 is a dated piece of
   work, and the status line at the top moves only when a row does.

## 3. The framework in one picture

![The NAF Framework — six functional blocks around the network infrastructure](img/naf-automation-framework-v1-minimal-white.svg)

The framework defines **six functional blocks** — Intent, Executor,
Collector, Observability, Orchestrator and Presentation — "besides the actual
network infrastructure" (its own wording). Infrastructure is drawn in the
diagram and gets a row in the naming table, but it is the thing being
automated, not a block of the automation system. Two cross-cutting
expectations apply to every block: version control with CI/CD, and
machine-friendly APIs documented by schema.

## 4. What SATOM calls each block

SATOM's names predate the mapping. This table is the translation; the product
keeps its names (renaming "Source of Truth" would touch four language
catalogs and dozens of pages for no functional gain), and the documentation
says "in NAF terms this is …" where the two differ.

| NAF block | What SATOM calls it | Read this when the names differ |
|---|---|---|
| <img src="img/naf-icon-intent-colored.svg" width="18" alt=""> **Intent** — desired state | Templates, Template bindings, Baselines (template combos), the Exception Library, Change types, the secret vault | SATOM calls the desired state *Templates* and *Baselines*; the NAF Framework calls this block *Intent*. |
| <img src="img/naf-icon-observability-colored.svg" width="18" alt=""> **Observability** — actual state, kept and processed | **Source of Truth** (configuration history), Monitoring (the time-series store), the health engine and alerts, Drift, Sentinel, Scout, Release Advisor | **The main collision.** SATOM's *Source of Truth* is the history of the **actual** configuration of each appliance. In NAF terms that is **Observability**, not Intent. |
| <img src="img/naf-icon-collector-colored.svg" width="18" alt=""> **Collector** — reading the network | Device sync, Deep capture, Metrics collection (scrape targets), Log collection, the FortiAnalyzer log view | *satom-harvester* is **not** the NAF Collector: it harvests vendor knowledge (API schemas, release notes), not network state. |
| <img src="img/naf-icon-executor-colored.svg" width="18" alt=""> **Executor** — writing the network | The CLI writer, Policy operations and Clone, Provisioning, write actions, Firmware upgrade, Observatory fix | The code calls a Process node's handler an "executor". That is a Process-engine term, not the NAF Executor. |
| <img src="img/naf-icon-orchestration-colored.svg" width="18" alt=""> **Orchestrator** — coordinating the blocks | Plugin Studio apps (runbooks), Triggers and automations, Scheduled Actions, Change Requests and the CR orchestrator, Integration hooks | The SATOM *reconciler* is deployment and HA machinery (it brings a node to the released commit); it is not the NAF Orchestrator. |
| <img src="img/naf-icon-presentation-colored.svg" width="18" alt=""> **Presentation** — people and other systems | The web console, the `satom` CLI, API v1, the Documentation Center, notifications (bell, e-mail, webhook, syslog/CEF) | — |
| <img src="img/naf-icon-infrastructure-colored.svg" width="18" alt=""> **Infrastructure** — the network itself | The managed appliances: FortiWeb, FortiADC, FortiGate, FortiAnalyzer, FortiAuthenticator | Not a block of the automation system. |

A second collision lives inside SATOM itself: **"Baselines"** names both the
template combos of System provisioning (Intent) and Sentinel's behavioural
baselines (Observability). The user guide says which one it means each time.

## 5. How to read the matrix

- One row per requirement sentence of the framework, grouped by block, with
  the level the framework gives it (**MUST**, **SHOULD**, **MAY**) and two
  cross-cutting rows for the expectations that apply to every block.
- **Status** is one of `met`, `partial`, `gap`, `accepted-gap`, `n/a`. An
  `accepted-gap` row states its reason after the dash: the requirement is
  understood and deliberately not pursued at this time.
- **Evidence** is a file in this repository (a test checks that each one
  exists), so a rename cannot leave the matrix pointing at nothing.
- The status line at the top of this page is derived from the matrix: the
  number of *documented deviations* is the number of **MUST** rows whose
  status is not `met`. A test fails when the sentence and the matrix
  disagree.
- **"Conformant" is a word the test owns.** No published document may claim
  conformance with the framework while any MUST row is not `met`; when every
  MUST row is `met`, the status line changes and the word becomes available.

## 6. Conformance matrix — state at v3.4.0

<!-- naf-matrix:begin -->
| Block | Level | Requirement | Status | Evidence |
|---|---|---|---|---|
| Intent | MUST | Represent any network-related aspect in a structured form | met | `app/models.py` (Template, Baseline), `app/models_tpl_binding.py`, `app/services/baselines.py` |
| Intent | MUST | Create, read, update and delete the desired state | met | The console (`app/views/templates.py`, `app/services/templates.py`) and API v1 (`app/api_v1/intent.py`: templates, versions, bindings and baselines; versions are immutable, so an update is a new version, as in the console) |
| Intent | MUST | Expose that data through a standardized, documented API | met | `app/api_v1/intent.py` (read with scope `read`; write with the explicit `template_draft` / `template_apply` capabilities), documented in `docs/api_v1.md` §11–§12 and in the OpenAPI document of `app/api_v1/openapi.py` |
| Intent | SHOULD | Model in a neutral representation derived into vendor artefacts | accepted-gap — SATOM is a Fortinet-specific product by design; `app/services/template_compat.py` translates between firmware builds, not between vendors | `app/services/template_compat.py` |
| Intent | SHOULD | A unified view of the desired state across sources | partial | Templates and baselines are unified; IP addressing is delegated to NetBox through `app/services/netbox_client.py` |
| Intent | SHOULD | Governance metadata, validation, versioned access | met | `app/services/templates.py` (versions, approval, author, source firmware), `app/services/template_compat.py` |
| Intent | MAY | Rendering, decomposition and artefact generation | met | `app/services/template_bindings.py` (render), the dry-run → canary apply path |
| Executor | MUST | Interact with the supported write interfaces | met | REST clients in `app/clients/`, SSH in `app/services/cli_writer.py` (NETCONF and gNMI are not offered by the managed products) |
| Executor | SHOULD | Deploy full or partial configuration, reboots, software updates | met | Templates, `app/services/policy_ops.py`, the upgrade flow, `app/services/provision_runner.py` |
| Executor | SHOULD | Task input from the intended state or derived through Observability | met | Baselines and templates; `app/services/observatory_fix.py` applies from observed findings |
| Executor | SHOULD | Dry-run before executing | met | Every device write previews its diff first (`app/services/fortiweb_ops.py`) |
| Executor | SHOULD | Transactional execution | met | CLI sessions abort on the first error and re-read (`app/services/cli_writer.py`); REST writes are verified by `app/services/device_verify.py` |
| Executor | MAY | Imperative and declarative, idempotent operations | partial | Declarative templates (`app/services/template_bindings.py`) next to imperative actions; idempotence is not measured as a property |
| Collector | MUST | Retrieve live data over the read interfaces | met | REST clients, read-only SSH (`app/services/ssh_ops.py`), FortiAnalyzer JSON-RPC (`app/services/faz_logs.py`), `app/services/metrics_collect.py` |
| Collector | MUST | Extend beyond device APIs to SNMP, syslog, flow telemetry and packet capture | met | SNMP v2c polling per appliance (`app/services/snmp_client.py`, `app/services/snmp_collect.py`) and a syslog receiver in the scheduler sidecar (`app/services/syslog_receiver.py`), both under the `satom_scrape_up` contract; logs also arrive through FortiAnalyzer (`app/services/faz_logs.py`). Scope stated in `docs/metrics-architecture.md`: SNMPv3, traps, NetFlow/sFlow and packet capture are out of scope |
| Collector | SHOULD | Normalise values across vendors and methods | partial | Normalised across firmware builds and channels (`app/services/api_library.py`), single vendor by design |
| Observability | MUST | Persist historical data | met | `app/services/sot_store.py` (content-addressed configuration history), `app/services/metrics_collect.py` (time-series store), the audit log |
| Observability | MUST | Powerful programmatic access to that history | met | `app/api_v1/observability.py`: configuration history and diff per appliance over the Source of Truth, current findings, and a read-only MetricsQL query route over SATOM's own series (the time-series store itself stays on loopback) |
| Observability | SHOULD | A capable query language | met | MetricsQL dashboards (`app/services/vm_store.py`), internal to the console |
| Observability | SHOULD | Events when the actual state differs from the intended state | met | `app/services/intent_compliance.py` compares each bound device with its rendered template (key-subset diff); the *Intent deviation* check in `app/services/alerts.py` raises the finding and the typed hook event `intent.deviation`; `Config drift` (previous snapshot) remains a separate check |
| Observability | MAY | Enrichment with contextual and third-party information | met | `app/services/release_advisor.py`, `app/services/drift_attribution.py`, Sentinel (`app/services/sentinel/`) |
| Orchestrator | MUST | Coordinate processes across the blocks without touching the network directly | met | `app/services/studio_flow.py` (a Plugin Studio app's diagram walks checks, scripts, SATOM steps and change requests; device writes go through each block's own path), `app/services/cr_orchestrator.py` |
| Orchestrator | SHOULD | Event-driven execution (synchronous, asynchronous, scheduled) | met | `app/services/trigger_engine.py` starts a *Run a Plugin Studio app* automation as a background job (never inside the scheduler tick), with cooldown and a 3-hop chain limit; an *Ask a person* step parks the run and `app/services/studio_apps.py` resumes it on the answer; hooks (`app/services/integration_hooks.py`), the console and `app/api_v1/apps.py` are the other doors |
| Orchestrator | SHOULD | Reverse or compensating actions on error | partial | A SATOM step that fails half-way undoes exactly what it created (`app/services/studio_satom.py`); there is no step that reverses the earlier steps of a run (the Process *Compensate* step was removed in 4.0.0) |
| Orchestrator | SHOULD | Dry-run of a workflow | met | Rehearsal runs and *Simulate* in the app editor (`app/services/studio_apps.py`, `app/services/studio_flow.py`): steps that write are recorded as not executed |
| Orchestrator | SHOULD | Scheduled execution of a workflow | partial | Script apps run on a cron schedule (`app/services/script_schedules.py`); a flow app runs from an event, the console or the API, not on a schedule (the `run_process` action was removed in 4.0.0) |
| Orchestrator | SHOULD | Logging and traceability of past and current workflows | met | `app/models_studio.py` (StudioAppRun with its steps, inputs and outputs), `app/models_triggers.py` (EventAutomationRun), `app/models_cr_types.py`, the audit log |
| Orchestrator | MAY | Correlate events and infer the course of action | partial | Cooldown and `app/services/drift_attribution.py` only |
| Presentation | MUST | Robust and flexible authentication and authorization | met | Local accounts with TOTP, LDAP and RADIUS (`app/services/directory_auth.py`), RBAC with ADOM scoping (`app/services/access.py`), owner-capped API tokens (`app/models_api_token.py`) |
| Presentation | MAY | Many forms: GUI, ITSM, messaging, documentation, dashboards | met | The console, NetBox and ticket integrations (`app/services/change_requests.py`), hooks, the Documentation Center (`app/views/manual.py`) |
| Cross-cutting | SHOULD | Version control and CI/CD for every component | met | Signed releases (`docs/release-pipeline.md`), the audit runner, the reconciler |
| Cross-cutting | SHOULD | Machine-friendly APIs documented via schema | met | `app/api_v1/openapi.py` builds an OpenAPI 3.0 document from the live routes, served as openapi.json under the API root; `tests/test_api_v1_openapi.py` fails on any undocumented route; `docs/api_v1.md` remains the prose manual |
<!-- naf-matrix:end -->

Infrastructure has no rows: the framework places no requirement on the
network itself.

## 7. What the status line counts, and what remains partial

The status line counts no MUST rows that are not `met`: with release 3.4.0
every MUST requirement of the framework is met, and the test that owns the
word now allows *conformant*. This is a **self-assessment** against the
pinned commit — the Network Automation Forum issues no certification — and
it is only as good as the matrix above, which is why every row names its
evidence and a test checks the file exists.

These rows are deliberately not `met`, all SHOULD or MAY:

1. **Intent — a neutral model derived into vendor artefacts** (`accepted-gap`).
   SATOM is a Fortinet-specific product; its templates are the vendor's own
   objects. The row stays open on purpose.
2. **Intent — a unified view across sources** and **Collector — normalise
   across vendors** (`partial`). Both are single-vendor by the same decision;
   IP addressing is delegated to NetBox rather than modelled twice.
3. **Executor — idempotent operations** and **Orchestrator — correlate events**
   (`partial`). Idempotence is designed for but not measured as a property;
   correlation is limited to cooldowns and drift attribution.
4. **Orchestrator — compensating actions** and **Orchestrator — scheduled
   execution** (`partial`, since 4.0.0). With the Process section removed, a
   Plugin Studio step undoes only its own writes, and only script apps run on
   a schedule.

Scope statements that keep the MUST rows honest: the Collector row is met by
SNMP v2c polling and a syslog receiver — SNMPv3, traps, flow telemetry and
packet capture are out of scope and `docs/metrics-architecture.md` says so;
the Intent write API never writes to a device directly (a push is the
console's own canary-gated job); the metrics query route is the only way to
the time-series store from outside, which stays bound to loopback.

## 8. Keeping this page honest

- **One matrix.** The Documentation Center article and every other manual
  link here; none repeats the status table.
- **A test owns the wording.** `tests/test_naf_alignment_doc.py` parses the
  matrix, recomputes the number of deviations, checks that every evidence
  file exists, that the pinned commit and source URL are identical on every
  surface, that no document claims conformance while a MUST row is open, and
  that the release checklist still carries the upstream-diff item.
- **Update the matrix in the release that changes a row** — not before (a
  claim without code) and not after (code without a claim).
- **Upstream drift.** At every release cut, diff the upstream
  `Framework.md` against the pinned commit. If it changed, re-run the
  mapping and bump the pin on every surface. The check is a release-checklist
  step, never a network call inside a test.
