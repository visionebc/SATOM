# Testing guide

> Also in the Documentation Center as `internal-testing-guide` (internal category, LAN only). Links of the form `[text](slug)` point at Documentation Center articles; `:::` blocks are Documentation Center callouts. When this changes, both copies change in the same round.

:::important Not public yet
Internal to Vision EBC. This section documents tools that are still being built; it is not published and nothing here is offered to customers for now.
:::

## The short version

:::cards
::card Never on a node | Rule
Tests do not run on the primary node or the standby. The audit runner runs them. You start a targeted run from your session with `satom-audit-run`.
::card Targeted by default | Rule
Run only the test files of the modules you touched, normally 1–3 files. The full suite (about 24,000 tests, roughly 100 minutes on the audit runner) runs only when someone explicitly asks for it.
::card Green before push | Rule
A red test is never pushed. A test enters the nightly audit when it reaches `main`.
::card A guard must bite | Rule
For logic and evidence changes, break the code on purpose and confirm that the new test fails. A guard that survives its own mutation is decoration.
::card Done means verified | Rule
HTTP 200 is not success. You verify a device write by reading it back, and a UI change by rendering it in a real browser.
:::

## How the suite is organised

Everything lives under `tests/`. `pytest.ini` sets `testpaths = tests`,
`pythonpath = .` and `addopts = -q`. The tree has 775 `test_*.py` modules plus
shared helpers, fixtures and one JavaScript test.

| Kind | What it proves | Real examples |
|---|---|---|
| Service unit tests | One `app/services/` module, with the device or the dependency faked | `test_calendar_plan.py`, `test_ha_failover.py`, `test_adc_firmware.py` |
| Route and render tests | A blueprint answers, renders and enforces its gate, through the Flask test client | `test_render_smoke.py`, `test_access_gates_audit.py`, `test_form_csrf.py` |
| RBAC contract | Granular profiles still project onto the five coarse keys | `test_permissions.py` |
| Anti-drift guards | A promise that must hold for the whole tree (every POST of a device blueprint runs as a job, every inline script carries the CSP nonce, every field is visible) | `test_device_jobs.py`, `test_csp_nonce.py`, `test_not_in_gui.py`, `test_product_separation.py` |
| Lab-capture tests | Parsers and walkers against real responses captured from lab appliances | `test_cli_writer.py`, `test_apilib_fac.py`, `test_migration_report.py` |
| Plugin and package tests | Package format, signatures, trust rules and the import gates | `test_plugin_packages.py`, `test_package_check.py`, `test_rules_pack.py` |
| Docs, site and release guards | Version, changelog, release notes, public site and in-product doc links agree | `test_version_and_changelog.py`, `test_changelog_sections.py`, `test_release_notes.py`, `test_site_links.py`, `test_docs_links.py`, `test_manual_local.py` |
| Locale guards | Catalogues compiled from the committed `.po` files | `test_ui_locale.py`, `test_catalog_delivery.py` |
| Suite self-tests | The conftest guards themselves work | `test_context_leak_guard.py`, `test_suite_overhead.py` |
| JavaScript | Browser-side logic, with `node:test` | `tests/js/test_policy_filter_worker.js` |

Shared helpers start with an underscore or have no `test_` prefix, so pytest
does not collect them: `_builder_fakes.py`, `_diag_fakes.py`, `_js_guard.py`,
`_nav_render.py`, `observability_lab_support.py`, `package_corpus.py` and
`leak_samples.py`. The two `mutants_*.py` files are mutation harnesses (see
[Mutation checks](#mutation-checks)).

## Writing a test

### The fixtures you get from conftest

`tests/conftest.py` builds the app against a throwaway database. You never touch
the live data.

| Fixture or helper | What it gives you |
|---|---|
| `app` | A fresh app from `create_app()` with its own SQLite file per test. CSRF and rate limiting are off. |
| `client` | `app.test_client()` |
| `session` | The SQLAlchemy session inside an app context |
| `login(client, user_id, product="fortiweb")` | Signs a user in without the login form. It also sets `session['product']`, without which every page redirects to `/product/select`. |
| `admin_user_id(app)`, `profile_id(app, name)`, `make_user(app, …)` | The seeded admin, a seeded profile (`readonly`, `operator`, `admin`), or a new user |
| `compiled_catalogues` (session, autouse) | The language catalogues compiled from the committed `.po` files |

Three autouse fixtures run around every test. One invalidates the thresholds
cache, one fails any test that leaves a Flask context pushed, and one compiles
the catalogues once per session.

### Database requirements

You need no PostgreSQL, Redis or network. Every test gets its own SQLite file
under the session temp root (`fmw-test-*`), which is deleted when the
interpreter exits. To test a PostgreSQL-only code path, pass a fake engine or
dialect named `postgresql` (see `test_boot_lock.py` and
`test_migration_lock.py`). Do not try to reach a real database.

Before the app is imported, conftest also points every on-disk store at the temp
root: `SATOM_JOBS_DIR`, `SATOM_SOT_DIR`, `SATOM_BACKUPS_DIR`, `SATOM_VAULT_DIR`,
`SATOM_TRUST_DIR`, `SATOM_REDISCOVERY_DIR`, `SATOM_API_MATRIX_DIR`,
`SATOM_HSTS_PRELOAD_DIR`, `FORTINET_DIAG_DIR` and `FORTINET_REPORTS_DIR`.

:::warning A new on-disk store needs its redirect in conftest
Every variable in that list exists because a test once wrote to the
production tree. One example: the job ledger filled with jobs that never
finished, and the toast dock replayed them. Another: on 2026-09-15 a
rediscovery test emptied the live API matrix, and the page showed "no
differences" instead of an error. When you add a store that writes to disk, add
its environment redirect to `tests/conftest.py` in the same change.
:::

### Simulate the device, never call a live appliance

Tests never call a live appliance. Choose the lightest fake that exercises your
code path:

- **Subclass or replace the client.** `test_adc_firmware.py` subclasses
  `FortiADCClient` and overrides `login`, `platform_version` and `_api`. Many
  tests use `monkeypatch` to swap a function or a module-level client.
- **Use `httpx.MockTransport` with real captures.**
  `observability_lab_support.fortiweb_transport()` maps API paths to JSON
  captured from a lab appliance under `tests/fixtures/observability_lab/`. It
  answers any other path with an "absent" probe, and it accepts per-path
  overrides so you can inject an error.
- **Use fake sessions for interactive CLIs.** `_diag_fakes.FixtureSession`
  answers `?` help from `tests/fixtures/diag_help/lab_help.json`. It still sends
  every path through the real `ssh_ops.assert_help_path` gate, so a blocked
  command fails in the test, not on a device.
- **Use fixture trees.** `cli_tree/`, `cli_writer/`, `schema_adapters/`,
  `gui_templates/` and `migration/` hold real, sanitised captures, keyed by
  product and build.

Make your fakes return the failure shapes too, not only the happy path: HTTP 200
with an error in the body, a licence refusal, an empty list. The product rule
"HTTP 200 is not success" applies to the code under test, so the test has to
send those answers.

### Signed fixtures for plugins

`tests/fixtures/plugins/` holds two real `.satomplugin` packages,
`plugin-hello` and `fleet-inventory`, built by the internal generator with the
production signing key. They are samples, not product plugins: they prove that
the generator and the reader agree on the format and the signature. A product
plugin (DNS Lookup, VM Inventory, the Troubleshooting apps...) is never kept or
tested here: its tests live with the plugin. For your own packages:

- `test_plugin_packages.py`: the `key` fixture generates an Ed25519 key and
  uses `monkeypatch` to put it in `plugin_package.TRUSTED_KEYS`. `_pack()` then
  writes `plugin.json` and a `plugin.sig` signed with that key.
- `package_corpus.py`: `publisher_key()` is a fixed Ed25519 key that stands for
  a registered Builder publisher. The corpus is built with SATOM's own writer, so
  every entry is exactly what an export would produce.

Never commit a real private key as a fixture. The release secret scan aborts on
PEM key material anywhere in the history.

## Running tests

### Targeted runs on the audit runner

From your session, send the files you touched to the audit runner:

```bash
satom-audit-run tests/test_calendar_plan.py
```

- The runner tests the HEAD of `main`. Uncommitted work travels as a patch
  applied over that HEAD, through the client's `--patch` and
  `--patch-from-host` options.
- The client waits up to about 110 seconds. If the run takes longer, the client
  exits with code `3` and the run keeps going. Check it with
  `satom-audit-run --status <id>`.
- To pick files, list `tests/` and filter by the module names you changed, as
  `docs/engineering.md` §10 does (`ls tests/ | grep -iE '<modules you touched>'`).

:::warning Older instructions that call pytest directly on a node are out of date
`docs/engineering.md` §10 and `CLAUDE.md` §2 used to show `pytest` invoked
directly on a node; copies of them you meet elsewhere may still do so.
Production nodes no longer run pytest. A suite run on the
primary node once used about 4.9 GB of temporary files and competed with the
live service, and release 12 failed with `ENOSPC` that way. Use the audit runner.
:::

### The full suite

The full suite has about 24,000 tests and takes roughly 100 minutes on the audit runner. Outside the
nightly review, run it only when someone explicitly asks for it. A targeted run
takes seconds to a couple of minutes.

### Reading the result

- **Judge by the exit code.** Only `rc == 1` means a test failed. `rc == 4` is a
  usage error, and `rc == 5` means pytest collected nothing. With `-q`, the
  summary line does not always reach the log. A harness that grepped the
  output for `failed` reported false survivors twice; once because pytest
  prints `FAILED` in upper case.
- **A skip is not a pass.** Some tests skip when local data is missing, for
  example "lab dump not on this node" or "no data/field_schemas on this node".
  The leak-corpus tests skip on a published mirror by design.

### One pytest per tree

Never run two pytest processes on the same tree. They contend for the same
files, and editing the tree under a running suite makes both results worthless.
If a pytest process is stuck, find it and kill it by PID:

```bash
pgrep -af 'venv/bin/python -m py[t]est'
```

Never use `pkill -f pytest`. That pattern also matches the shell that started
the run, so it kills your own session. Clear `__pycache__` before you start a
new run.

## The lifecycle into audit

:::flow
Write or change | the test next to the code it guards
Targeted run | satom-audit-run on the files you touched
Mutation check | logic or evidence change: break, see red, restore
Commit and push | only when green; the push to main puts it in audit
Nightly review | 02:00 Swiss time, all of tests/ at the HEAD of main
:::

A pushed test is "in audit": every night the review runs it with everything
else. Because a red test is never pushed, a red nightly always means one of two
things. Either a change broke something that its targeted run did not cover,
or two concurrent authors broke each other. Targeted runs cannot catch either
case. Treat a nightly failure as a defect to fix on top, not as a reason to run
broader targeted runs.

:::note Guards rot when refactors skip them
The nightly review was once red for days, with 86 failed tests. Most were guards
that had not been updated after a refactor, and a few pointed at real defects.
The fix was to check each promise where it is actually kept: the sidebar as it
renders in every ADOM (`_nav_render.py`), not include lines in `base.html`; the
catalogues compiled from `.po`, not a node's `.mo`.
:::

## Mutation checks

Mutation checks are mandatory for every logic or evidence change. They are not
required for pure UI iteration.

1. Undo the fix, or break the invariant that the new test claims to protect.
2. Run that test and confirm that it fails (`rc == 1`).
3. Restore the code and confirm that the test is green again.

If the test still passes against the broken code, rewrite it or delete it.

`tests/mutants_calendar.py` and `tests/mutants_ha_failover.py` show the full
pattern. Each mutation is `(name, file, old, new)`, and each breaks exactly one
rule. A mutation counts as a bite only on `rc == 1`. An anchor that does not
match exactly once counts as a survivor. The harness requires a green baseline
first, restores each file and checks it by SHA-256, and finally re-runs the
tests green.

:::warning Do not run the harness scripts as they are
The harnesses hard-code the install path and call pytest themselves, so on a
node they would break the "never on a node" rule. Apply the same break, red,
restore cycle through the audit runner instead.
:::

**Assert on code with its comments stripped.** A guard that forbids a substring
also matches the comment that explains the guard, so it passes on a tree that
still has the defect. End the window at the next function, not after a
character count.

## Live verification

A green suite proves the code. Live verification proves the deployment. A
change is done only when it is verified:

| Change | Not proof | Proof |
|---|---|---|
| Device write | HTTP 200 | Read the object back and compare it with what you sent. FortiWeb silently ignores fields of a PUT. |
| UI change | "The template has it" | Render the page with the test client and an admin session, then take a screenshot in a headless browser. |
| Background work | A flash message | The job in the Job Manager (`/jobs/manager`) ends in `success`, with real steps. |
| Any device action | No error | An entry in the audit log (`/audit`): every device action is a job step and an audit line. |
| Service restart | `systemctl` says active | `/healthz` answers 200, and the error log under `/var/log/satom/` is clean. |

### Render, then look

Server-side tests read the markup. Some defects exist only in the browser:

- **The CSP nonce.** The app serves `script-src-elem 'self' 'nonce-…'`. An inline
  script without the nonce is blocked by the browser, while the template
  compiles, the route returns 200 and every server-side test passes. On
  2026-08-23 this broke the whole Admin Console menu, and a sweep found ten more
  blocks that had never run in a browser. A headless render *without* the CSP
  header passes too. To reproduce the bug, serve the page with the same header
  and the nonce copied from the render. `test_csp_nonce.py` now guards this.
- **Layout.** A badge with `white-space: nowrap` overflowed its card with
  correct markup and a correct grid rule. To catch this, render with the
  authenticated test client, rewrite the asset paths to absolute ones, and take a
  screenshot with chromium (`docs/safeguards.md` shows the
  `chromium --headless=new … --dump-dom` probes).

For a write flow, check every step of the six-step rule in
`docs/product-rules.md` §1.2: pre-check, backup, dry-run diff, minimal change,
read-back, compensation. A flow is idempotent, so a second run must make zero
changes.

## Bug triage

:::flow
Reproduce | on the real page or with the real capture, note the exact error text
Failing test | the smallest test that shows the bug, red on the current code
Fix | the minimal change that turns that test green
Mutation | revert the fix, the test goes red; restore
Docs | CHANGELOG entry, user guide or engineering notes, same change
:::

- Write the test **before** the fix, and keep it. The test proves that you
  reproduced the right defect. The mutation step proves that the test tracks
  the fix and not something incidental.
- When a test fails far from the code that caused it, suspect shared state
  first: a leaked context, a module-level cache, or a store that is not
  isolated. Run the failing file on its own to confirm.
- Treat automated findings, including those of the AI vulnerability audit, as
  leads, not verdicts. Verify each one against the real source before you fix
  or dismiss it.

## Release guards

At release time the gate is the set of guards that protect the release
surfaces: version, CHANGELOG, release notes, the public site and the docs. It
is not the full suite. The guards that cover those surfaces include
`test_version_and_changelog.py`, `test_changelog_sections.py`,
`test_release_notes*.py`, `test_site_*.py`, `test_docs_links.py`,
`test_docs_publication.py`, `test_public_docs.py` and `test_manual_local.py`.
The pipeline sends the exact release commit to the test platform, and **only
`passed` passes**. Failed, error, cancelled, over budget and wrong-commit
results all stop the release. See
[Release pipeline](internal-release-pipeline) for the step order. Cutting a
version means editing `VERSION` and `CHANGELOG.md`; the guards fail if either
is stale.

## Traps that have already happened

:::cards
::card A leaked Flask context | 2026-09-22
Release run 28 went red because one test pushed an app context and never popped it. The failure appeared dozens of files later, in an innocent test. The conftest now pops the leak and fails the test that caused it. Use `with app.app_context():`.
::card A cache that outlives its database | 2026-10-21
`services.thresholds` kept settings rows from the previous test's database, so `test_node_metrics` went red only after `test_thresholds` ran. An autouse fixture now invalidates the cache. Any module-level cache needs the same treatment.
::card Importing a constant from conftest
`from tests.conftest import TRANSLATIONS_DIR` runs the conftest a second time with a different temp root, so the constant points at a directory nobody compiled. Take the `compiled_catalogues` fixture instead.
::card The product gate
A test client without `session['product']` is redirected to `/product/select` on every page. Use the `login()` helper, which sets the product.
::card Orphaned temp directories | 2026-08-17
A week of runs left 2,837 `fmw-test-*` directories behind. Conftest now deletes its temp root at exit. Cleanup must never turn a green run red.
::card Grepping for "failed"
Mutation harnesses reported biting mutations as survivors because they searched the output case-sensitively. Read the exit code.
:::

## Related

- [Release pipeline](internal-release-pipeline): where the release guards run during a release cut
- [Safeguards and guard rails](safeguards): the product's safety rules and the tests that enforce them
- [Jobs and the Job Manager](jobs) and [Audit log](audit-log): where live verification looks
- [Test and publish](plugin-studio-test-publish): the plugin side of testing
