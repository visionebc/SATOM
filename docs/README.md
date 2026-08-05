# SATOM documentation

Twenty-two reference documents with no front door is not a manual — it is a
directory listing. This page is the front door: what exists, in what order to
read it, and **which surface to read it on**.

---

## 1. The three surfaces, and why there are three

The same Markdown files in this directory are published three ways. They are
not redundant — each one survives a different failure.

| Surface | Where | Audience | Survives |
|---|---|---|---|
| **Repository** | `docs/*.md` | whoever edits it | everything; this is the source |
| **Public site** | `site/docs/*.html` → GitHub Pages | operators, evaluators, integrators, auditors | the whole installation being down |
| **Console** | `satom show docs`, `show runbook`, `show privilege`, `show paths` | an operator on a broken or isolated node | no browser, no network, no database |

**The application does not serve documentation.** It used to, at `/docs`, and
that was a fourth place for the same words to live and a fourth place to forget.
The manual now has exactly one published home; the sign-in page links straight
to it.

That trade has a cost, and it is paid by the console. A management network is
deliberately built with no route to the public internet, so on the node that
most needs the manual the published copy is unreachable. `satom show docs`
prints these files from the tree — the same files, unredacted, because whoever
runs it is already on the machine. It derives its catalogue by listing this
directory, so a document added here appears there with no second edit.

Two rules follow and both are enforced by `tests/test_docs_publication.py`:

- **The repository is the only place anyone edits.** The site pages are
  generated (`deploy/gen_site_docs.py`) and the command reference inside
  `cli.md` is generated (`deploy/gen_cli_reference.py`). Editing the generated
  HTML by hand creates a second copy, and the second copy is the one that goes
  stale in public.
- **The published copy is redacted, from one registry.** Eleven of these files
  carry real internal addresses, management hostnames, hypervisor names and an
  administrator's e-mail. `app/services/doc_publication.py` owns the
  publishable list, the redaction table and the scanner. The output is
  **re-scanned** and a survivor aborts the site build. It does not warn and
  continue: a warning in a publication pipeline is a leak with a paper trail.

Regenerating is three commands, and the test tells you when you owe them:

```bash
python3 deploy/gen_cli_reference.py    # docs/cli.md command table
python3 deploy/gen_site_docs.py        # site/docs/*.html + site/docs.html
python3 deploy/stamp_site_assets.py    # cache-busting hashes + version pill
```

---

## 2. Reading paths

### I have to run this thing
1. [`management-overview.md`](management-overview.md) — what it is, without jargon.
2. [`user-guide.md`](user-guide.md) — the interface, screen by screen.
3. [`cli.md`](cli.md) — the console for when the interface is not there.
4. [`safeguards.md`](safeguards.md) §10 — **what a fresh install does NOT arm by
   itself.** No scheduled action is ever seeded; a new node has every capability
   and zero coverage, and looks healthy while having none.

### I have to install it
1. [`INSTALL.md`](INSTALL.md) §1 — requirements and the exact package list per
   distribution; this is the section you hand to whoever approves the change.
2. `install-satom.sh --preflight` — run it before anything else; it accumulates
   *all* blockers and reports them together.
3. [`privilege-model.md`](privilege-model.md) — the installer account, the
   service account and the operator account are three different things.
4. [`INSTALL.md`](INSTALL.md) §5 — hardening, and the two `sudoers` rules.

### Something is broken
1. `satom diagnose all` — 24 checks, one exit code, works unprivileged.
2. [`safeguards.md`](safeguards.md) — *"Verifying the guards are armed"* has a
   command per protection.
3. [`git-backup-and-outage.md`](git-backup-and-outage.md) — repository history,
   the anti-reset guard and the four-copy recovery runbook.
4. `satom show runbook` — the same procedures, printed by the node itself.

### I am extending it
1. [`engineering.md`](engineering.md) — layers, the endpoint registry, device
   clients, jobs, testing.
2. [`device-api.md`](device-api.md) — the endpoint registry: why no code
   hardcodes a device path, and how a new endpoint is added.
3. [`source-of-truth-spec.md`](source-of-truth-spec.md) — the authoritative
   behavioural spec for harvesting and versioning.
4. [`overview.md`](overview.md) — the operating rules the codebase is held to.
5. [`cli.md`](cli.md) §5 — adding a console command is **one entry** in
   `deploy/satom_cli/tree.py`; the parser, help, completion and privilege gate
   all read that structure.

### I am integrating with it
1. [`api_v1.md`](api_v1.md) — token authentication and the endpoints. Also
   published on the public site and linked from the sign-in page, so an
   integrator can read it before they have an account. The rest of the manual
   is beside it.
2. [`device-api.md`](device-api.md) — the OTHER API. `api_v1.md` is how someone
   drives this platform; this is how the platform drives an appliance, plus the
   endpoint registry that turns a firmware URI change into a row edit.

---

## 3. Every document

### Product & operation
| Document | What it is for |
|---|---|
| [`management-overview.md`](management-overview.md) | The system without jargon: problem, maturity, risk, cost. |
| [`overview.md`](overview.md) | Architecture, deployment, security posture, and the rules the team works by. |
| [`user-guide.md`](user-guide.md) | Day-to-day operation, screen by screen. |
| [`cli.md`](cli.md) | The operator console: diagnose, control, rebuild — and the sudo rule to request. |

### Deployment & protection
| Document | What it is for |
|---|---|
| [`INSTALL.md`](INSTALL.md) | Requirements, per-distribution packages, preflight, clustering, hardening, uninstall. |
| [`privilege-model.md`](privilege-model.md) | Which account runs what, the two-command sudo allowlist, the privileged-runner boundary, node trust. |
| [`safeguards.md`](safeguards.md) | Every protection: what it prevents, where it lives, how to prove it is armed. |
| [`metrics-architecture.md`](metrics-architecture.md) | Where operational data lives and why: the fleet-scale measurement, aggregated collection, the time-series store, selector dashboards, and the content-addressed source-of-truth store. |
| [`git-backup-and-outage.md`](git-backup-and-outage.md) | Anti-reset guard, unpushed-commit alert, repository bundles, four-copy recovery. |
| [`release-pipeline.md`](release-pipeline.md) | How a release is sanitized, secret-scanned, audited and published. |
| [`release_notes.md`](release_notes.md) | The known/resolved issue corpus behind the upgrade advisor. |

### Security
| Document | What it is for |
|---|---|
| [`encryption-and-node-tls.md`](encryption-and-node-tls.md) | Service certificates, node-to-node encryption, enforced database TLS, live probes. |
| [`acme-certificate-manager.md`](acme-certificate-manager.md) | ACME issuance, the DNS-provider catalog, and how credentials reach the signer without leaking. |

### Development & integration
| Document | What it is for |
|---|---|
| [`engineering.md`](engineering.md) | Internal architecture: layers, registry, device clients, jobs, testing. |
| [`source-of-truth-spec.md`](source-of-truth-spec.md) | The authoritative behavioural specification. |
| [`api_v1.md`](api_v1.md) | Token authentication and the public API surface. |
| [`device-api.md`](device-api.md) | The device API consoles and the endpoint registry behind them. |

### Managed-device reference
| Document | What it is for |
|---|---|
| [`server_policy.md`](server_policy.md) | Field-level reference for the server policy object graph. |
| [`web_protection_profile.md`](web_protection_profile.md) | The ~40 sub-policy WAF bundle, field by field. |
| [`wpp_exceptions.md`](wpp_exceptions.md) | Authoring and injecting WAF exceptions and signature carve-outs. |
| [`fortiadc.md`](fortiadc.md) | REST conventions, object map and current coverage for FortiADC. |

---

## 4. Rules for changing documentation

These are not style preferences; each one exists because its absence cost
something.

1. **A new guard is documented in [`safeguards.md`](safeguards.md) in the same
   commit that introduces it.** A protection nobody can find is a protection
   nobody verifies. (Rule recorded in [`overview.md`](overview.md).)
2. **A new document appears on the console for free.** `satom show docs`
   lists this directory; there is no second list to update and therefore no way
   to add a document the console cannot print.
3. **A document meant for the public is added to `PUBLIC_DOCS` in
   `app/services/doc_publication.py`** — plus its group in `GROUPS` — and the
   site generator is re-run. Publication is **opt-in**: a document absent from
   that list is simply not published, which is the correct default for anything
   describing internal topology. It still ships in the tree and still prints
   from the console.
4. **Never hand-edit generated output** — `site/docs/*.html`, `site/docs.html`,
   or the block between the `GENERATED COMMAND REFERENCE` markers in
   `cli.md`. The test will revert your work by failing.
5. **Verify a command before documenting it.** The manual is read by someone who
   cannot check. A command that does not exist is worse than a missing section:
   the missing section makes them look elsewhere, the wrong command makes them
   trust the page.
