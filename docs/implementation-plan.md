# Implementation plan

> Also in the Documentation Center as `internal-implementation-plan` (internal category, LAN only). Links of the form `[text](slug)` point at Documentation Center articles; `:::` blocks are Documentation Center callouts. When this changes, both copies change in the same round.

:::important Not public yet
Internal to Vision EBC. This section documents tools that are still being built; it is not published and nothing here is offered to customers for now.
:::

## Overview

This page describes how SATOM 4.12.0 is developed: one developer working with an AI coding agent,
changes broken into small verified steps, and a written plan for anything with more than one step.
It has four parts: the workflow, the shape of a plan, the register of the plans already in the
repository, and the open work today. The rules a change must respect live in
[Product rules](product-rules) and [Design system](design-system). This page links to them
rather than copying them.

:::note Statuses come from the CHANGELOG
A plan is marked as shipped only when `CHANGELOG.md` names the release. The checkboxes inside
a plan file are **not** a status: most early plans still show every `- [ ]` unticked although
their code is on `main`. When the CHANGELOG does not confirm a status, this page says
"not confirmed in CHANGELOG".
:::

## 1. How work is planned and executed

Every change follows the same sequence, whether a person or the agent does the typing.

:::flow
Understand the intent | Restate what was asked and what "done" looks like before touching code
Read the governing doc | Product rules for any device-write flow, Design system for any UI change
Plan (multi-step work) | Write `docs/superpowers/plans/<date>-<topic>.md` before the first edit
Implement in small steps | One task at a time; each step leaves the tree working
Targeted tests | Run only the test files of the touched modules, on the audit runner
Mutation check | For logic changes: break the invariant, watch the guard fail, restore
Document in the same round | CHANGELOG `[Unreleased]`, `docs/user-guide.md`, the Docs Center article
Commit and push to main | The standby converges to the primary by itself
Release only on request | A release carries everything; branches and worktrees are integrated or discarded first
:::

### Definition of done per step

| Step | Done when |
|---|---|
| Understand the intent | The goal fits in one sentence, and you know which screens, services and devices it touches. |
| Read the governing doc | You know which rules apply, for example the [six steps of a device write](product-rules#12-writing-to-a-device-is-six-steps) or the [UI checklist](design-system#10-checklist-for-a-ui-change). |
| Plan | A plan file exists with a goal, an architecture note, a file map and numbered tasks. Single-step fixes skip this. |
| Implement | Each task ends with the tree importable and the app booting, and the task's own test written first. |
| Targeted tests | The selected files pass. The result is judged by the pytest exit code: only `rc == 1` is a failure, `rc == 4` is a usage error and `rc == 5` means no tests were collected (`docs/engineering.md` §10). |
| Mutation check | Every new guard has been seen to fail against the defect it protects against. A guard that survives its own mutation is rewritten or deleted. |
| Document | The CHANGELOG entry, the user guide section and the Docs Center article describe the same behaviour ([Product rules §7](product-rules#7-documentation-and-tests-travel-with-the-change)). |
| Commit and push | The commit is on `main` and the standby reports the same HEAD. Its fast gate is `/healthz` returning `200` and no failed units (`docs/engineering.md` §10). |
| Release | Done only when someone asks for one. The [release pipeline](internal-release-pipeline) then runs its version, CHANGELOG and docs guards on the test platform; the full suite runs only when the release is started with `with_suite`. |

:::tip Why targeted and not the full suite
The full suite has about 24,000 tests and never runs on a node ([Testing guide](internal-testing-guide)). It runs
nightly on the audit runner against `main`, and on demand only when someone explicitly asks for it. The
nightly run covers the breadth that targeted runs skip. The mutation check covers the depth.
:::

### Working with the agent

- Point the agent at `CLAUDE.md` first. It sends every change through `docs/product-rules.md`
  and `docs/design-system.md` and treats `docs/superpowers/plans/*` as historical.
- Never run two pytest processes on one checkout, and never edit the tree while a suite runs.
  Both results become invalid (`docs/engineering.md` §10).
- Write every user-facing string in English and wrap it for translation
  ([Product rules §5](product-rules#5-language)).
- The public GitHub repository is a sanitised, read-only mirror (`CONTRIBUTING.md`). Work happens
  on the private `main`. Nothing is developed against the mirror.

## 2. The plan template

The twelve plans in `docs/superpowers/plans/` share one shape. Write a new plan in the same
shape so that the agent can run it task by task.

| Part | What it holds | Example in the repository |
|---|---|---|
| Title | `# <Feature> Implementation Plan` | `2026-06-29-template-approval-workflow.md` |
| Worker note | A blockquote telling the agent to execute task by task with checkbox steps | Every plan dated 2026-06-28 to 2026-07-01 |
| Goal | One paragraph: what the user gets | All plans |
| Architecture | The approach, the existing pieces it reuses and what stays unchanged | `2026-06-30-deep-fleet-analytics.md` (no storage schema change) |
| Tech stack | Libraries and storage involved | All plans |
| Conventions / ground truth | Facts verified before planning, which are not re-derived during execution | `2026-07-01-cert-inventory-dashboard.md` ("Grounded facts") |
| File map | Files to create, modify and test, each with one responsibility | `2026-06-29-template-approval-workflow.md` |
| Tasks | `## Task N` with **Files**, then steps: write the failing test, run it and see it fail, implement, run it and see it pass, commit | `2026-06-28-firmware-repository.md` |
| Phases | For large work: phases ordered by device risk (no device risk first, device writes last, dry-run first) | `2026-06-27-settings-parity.md` |
| Verification | A final task: full or targeted suite, restart, smoke test | `2026-06-30-template-catalog-baseline.md` Task 7 |
| Self-review | A checklist run before handing the plan over | Most plans |
| Status note | Added at the top once executed: release, phases done, mutation count | `2026-10-20-naf-alignment.md`, `2026-10-30-app-scoped-access.md` |

Rules for plans:

- **Plans are history.** `CLAUDE.md` lists `docs/superpowers/plans/*` as historical execution
  plans that are never rewritten. You may add a status note at the top. You do not edit the body.
- **A roadmap is not an executable plan.** The NAF plan is a master roadmap. Each phase got its
  own small TDD plan when it was executed.
- **A spec comes first when the design needs a decision.** `docs/superpowers/specs/` holds three
  designs (firmware repository, monitoring analytics and reports, app-scoped access). Each spec
  has a date, a status line and a *Problem* section. The app-scoped access spec ends with an
  *As built* section.
- **The environment sections of old plans are out of date.** The June plans assume SQLite and
  `db.create_all()` with no Alembic. The current convention is an Alembic migration plus the
  idempotent `_ensure_columns()` helper (`docs/engineering.md` §12). Check `docs/engineering.md`,
  not an old plan.
- **Write hosts as placeholders** (`<primary>`, `<app-user>`), as `docs/engineering.md` does.

## 3. Plan register

Status key: **Shipped in X**, where the CHANGELOG names the release. **Not confirmed in
CHANGELOG** means no entry introduces the feature: plans dated before 2026-07-12 predate the
oldest entry (0.8). The *Evidence* column lists what exists at HEAD, so you can follow the
trail.

| # | Plan file | Topic | Status | Evidence |
|---|---|---|---|---|
| 1 | `2026-06-27-settings-parity.md` | Desktop Settings parity, plus the Automation subsystem (scheduled actions, change requests, system provisioning) | Not confirmed in CHANGELOG | `app/views/scheduled_actions.py`, `change_requests.py` and `provisioning.py` exist. Which of the 7 phases were completed is not recorded. |
| 2 | `2026-06-28-firmware-repository.md` | Admin firmware image store (upload, list, download, delete) | Not confirmed in CHANGELOG | `app/views/firmware.py`, `app/models_firmware.py`, spec of the same date. 1.0 adds manifest generation "on upload / pull / delete". |
| 3 | `2026-06-28-provisioning-guided-forms.md` | Schema-driven typed provisioning forms (field catalog per product and line) | Partially shipped: the plan header says it was implemented and is pending review | `app/services/field_catalog.py`. 1.10.0 adds six missing field schemas. 2.13.0 removes the unused documentation-enrichment stub. The plan's review checklist is still open. |
| 4 | `2026-06-29-template-approval-workflow.md` | Save / apply / approve / fleet-rollout as separate permissions | Not confirmed in CHANGELOG | `Template.STATUS_PENDING` / `STATUS_APPROVED` in `app/models.py`. Later rules in 3.2.0 (an author cannot approve their own template) and 3.4.0 (four-eyes). |
| 5 | `2026-06-30-deep-fleet-analytics.md` | Deep capture of the WPP subtree and the Server Policy graph, plus Analysis charts | Not confirmed in CHANGELOG | `app/services/deep_capture.py`, `deep_jobs.py`, `analysis_deep.py`. Deep capture changes appear in 2.11.0, 2.12.0 and 3.1.0. |
| 6 | `2026-06-30-ha-clusters.md` | HA (A-P) clusters as a node 0 with member appliances | Not confirmed in CHANGELOG | `is_cluster` / `is_cluster_member` / `parent_id` on `Appliance`. HA cluster fixes in 4.11.1, 4.11.2 and 4.12.0. |
| 7 | `2026-06-30-template-catalog-baseline.md` | Approved-template catalog by section, baselines composed from it | Not confirmed in CHANGELOG | `app/services/baselines.py`, `section_taxonomy.py`, `app/views/section_catalog.py`. Baseline changes in 3.1.0 and 4.6.0. |
| 8 | `2026-07-01-bug-report-notifications.md` | Bug report button, admin inbox, resolve and notify | Not confirmed in CHANGELOG | `app/views/reports.py`, `app/services/bug_reports.py` (opt-in key `bug_reports.notify`). Mentioned in 2.11.0 and 4.11.0. |
| 9 | `2026-07-01-certificate-lifecycle.md` | Key and CSR generation, CA submission, deployment to FortiWeb, expiry monitoring | Not confirmed in CHANGELOG | `app/services/cert_manager.py`. Certificate Manager additions in 3.2.0 (CSR for another CA, import, staged rotation). |
| 10 | `2026-07-01-cert-inventory-dashboard.md` | Unified certificate inventory, TLS probe, swap and remove across bindings | Not confirmed in CHANGELOG | `app/services/cert_probe.py`, `sub_mkey` in `app/services/fortiweb_ops.py`. On-device swap and remove are referenced in 3.2.0. |
| 11 | `2026-10-20-naf-alignment.md` | Map SATOM to the NAF Framework and close every MUST | Shipped in 3.4.0 | The plan's own banner says phases 1–6 shipped together in 3.4.0, and the 3.4.0 entries cite each phase. See [NAF Framework](naf-framework). |
| 12 | `2026-10-30-app-scoped-access.md` | Apps-only profiles, directory connections, per-app sign-in | Shipped in 4.7.0 | Phases 1–3 ticked, 14 mutations recorded. See [App sign-in](app-sign-in) and [SATOM 4.7.0](satom-4-7-0). |

:::note Read "not confirmed" literally
For rows 1–10 the code is on `main`. What is missing is a CHANGELOG entry that dates the
feature. Do not turn these rows into "shipped in 0.8" or any other version.
:::

## 4. Open work (as of 4.12.0)

Ordered by risk to a running installation first, then by how much other work each item blocks.
Nothing below is done unless a CHANGELOG entry says so.

| Priority | Item | Why it matters | Next concrete step | Blocker |
|---|---|---|---|---|
| 1 | No total per-request timeout in the device HTTP clients (`app/clients/base.py`) | The client builds `httpx.Timeout(timeout, connect=min(10, timeout))`. httpx applies that limit to each connect, read, write and pool wait, not to the request as a whole. A socket that trickles data, or stalls between reads, can keep a job, and the plan it belongs to, running indefinitely. | Write a plan. Add a wall-clock deadline per request in `base.py`, with a test that uses a fake slow transport. Run a mutation check: remove the deadline and the test must hang until the guard fails. | None recorded |
| 2 | Servers ADOM (Linux and Windows hosts), stages 1–5 | Only stage 0 has shipped: the ingestion gate in [4.11.0](satom-4-11-0). The 4.11.0 entry itself says "No collector uses the gate yet". | Write a plan for stage 1 in `docs/superpowers/plans/` before any code. No Servers ADOM plan exists among the twelve. Every collector must pass through the stage 0 gate. | None recorded |
| 3 | The Docs Center is not part of the public site deploy | Articles reach the copy on each node (`/manual/docs-center/`), but not the public site. | Add the Docs Center build to the site publication step of the [release pipeline](internal-release-pipeline), then confirm the result on the public site. | None recorded |
| 4 | SVG and canvas colour literals (design-system debt) | A literal colour does not follow the active theme. The status tints are also still literal, so no dark canvas can be offered (`docs/design-system.md` §1, `docs/theming.md` §8). | List the remaining literal `fill`/`stroke` values in templates and scripts. Keep categorical palettes, which [Design system §3](design-system#3-tokens) allows, and move the accent and status colours to tokens. | None recorded |
| 5 | Selector lists that cannot be filled without lab devices or licences (Advanced Bot Protection, pages that exist only on 8.0.6) | Without a device that exposes these objects, their choices cannot be harvested or verified. [Product rules §1.3](product-rules#13-truth-per-build-not-from-memory) forbids filling them from memory. | Keep these selectors marked as not yet harvested. Harvest them once a device or licence is available. | A lab device or licence for each affected feature |
| 6 | ADOM "Based on" inheritance | It would let an ADOM inherit from another one. | None until it is confirmed. No code for it was found at HEAD. | **On hold**, waiting for confirmation |

:::tip Also open, from a plan file
`2026-06-28-provisioning-guided-forms.md` still carries its "PENDING TASK — Review provisioning"
checklist: a UI walkthrough of the typed fields, a real dry-run of a multi-object profile, and a
UX review for non-technical users. The documentation-enrichment question in that checklist was
settled in 2.13.0, when the stub was removed.
:::

## 5. Rules that constrain implementation

These rules are not copied here, so the copies cannot drift. Read the source before you plan:

| When the change… | Read |
|---|---|
| writes to a device (clone, deploy, provisioning, restore) | [Product rules §1.2](product-rules#12-writing-to-a-device-is-six-steps): pre-check, versioned backup, dry-run diff, minimal change in dependency order, post-check by re-reading, compensation |
| trusts a device response | [Product rules §1.4](product-rules#14-http-200-is-not-success): HTTP 200 is not success |
| shows device data | [Product rules §1.6](product-rules#16-every-field-the-device-has-is-visible): every field the device has is visible |
| adds a page or a menu entry | [Product rules §4](product-rules#4-navigation-and-information-architecture): Settings configures, Operations operates; plugins and basic elements are kept apart |
| touches the UI | [Design system §10](design-system#10-checklist-for-a-ui-change): the checklist. [§3](design-system#3-tokens): tokens, never their values |
| adds a third-party browser asset | [Design system §10](design-system#10-checklist-for-a-ui-change): vendored and listed in `MANIFEST.json` |
| changes visible behaviour | [Product rules §7](product-rules#7-documentation-and-tests-travel-with-the-change): documentation and tests travel with the change |
| is ready to release | [Release pipeline](internal-release-pipeline), only when explicitly requested |
