# Release & publication pipeline

SATOM is developed privately and published publicly through an
automated, deterministic gate. Nothing reaches the public mirror by hand.
This document is the source of truth for that process and is intentionally
public so users can see exactly how releases are produced and vetted.

```
   INTERNAL (private)                    GATE                     PUBLIC
  ┌──────────────────┐   ┌───────────────────────────────┐   ┌──────────────┐
  │ Gitea dev repo   │──▶│ 1. Sanitize (git-filter-repo) │──▶│ Gitea prod   │
  │ satom-dev    │   │ 2. Secret scan (gitleaks-like) │   │ GitHub mirror│
  │ (full history)   │   │ 3. Internal AI vuln audit      │   │ GitHub Pages │
  └──────────────────┘   └───────────────────────────────┘   └──────────────┘
```

## Stage 0 — the promotion order

Publication is the **last** hop of a chain. Each hop reaches a wider audience
than the one before it and nothing downstream can be un-published, so each has
a gate that must be green before the next one runs.

| # | Hop | What it is | Gate before moving on |
|---|---|---|---|
| 1 | **Primary node** | the only node where code is written | targeted tests for the zone touched; every new guard mutation-tested; service restarted if Python or templates changed; `/healthz` 200 |
| 2 | **Standby node** | pulls straight from the primary — no remote involved | converged to the primary's HEAD; unit up; `/healthz` 200 on the app port and through the TLS edge; zero failed units |
| 3 | **The suite** | the full run, on the primary | exit code 0 |
| 4 | **Dev remote** | the private repository, full history | derived pages regenerated (below); push accepted |
| 5 | **Documentation site** | its web root **is** a checkout of the repository | `git fetch && git reset --hard origin/<branch>`; there is no build step, the pull *is* the deploy |
| 6 | **Public mirror** | sanitised history, release artefacts | stages 1–4 of this document |
| 7 | **Product site** | a separate repository, deployed with `rsync --delete` | the checkout diffed against the live node first |

Two hops carry a trap worth stating outright.

**Step 2 is a pull, not a push.** The standby fetches from the primary's
checkout over a restricted, read-only SSH key (`engineering.md` §2). Wiring it
that way is what makes the sentence *"validated on both nodes before it reaches
the remote"* true; with the standby following the remote instead, the code
cannot exist on it until after the push, and the promise is unachievable no
matter how carefully it is followed.

**Step 7 deploys with `--delete`, onto a node that is edited by hand.** A file
that exists only on the live node is destroyed by the next deploy — published
today, `404` tomorrow. Before running it, diff both sides (ignoring the asset
cache-busting stamp) and list the downloads directory on each. When the node is
**ahead**, the correct repair is to bring the checkout forward; never publish
over it to make the two agree.

---

## Stage 1 — Sanitization
The full internal history is rewritten into a clean mirror with
`git-filter-repo`:
- **Removed from all history:** `.env` and `.env.*`, `CLAUDE.md`,
  `GEMINI.md`, `AGENTS.md`, `.claude/`, `docs/superpowers/`, and internal
  `reports/` device data.
- **Commit messages** are filtered to drop any AI-assistant references.
- The rewrite is **deterministic**: the same internal history always
  produces the same public commit SHAs.

## Stage 2 — Secret scan
Every blob in the sanitized history is scanned with a gitleaks-style
detector (high-confidence patterns: PEM private keys, GitHub/AWS/Slack/
Google tokens, and `fernet`/`secret_key`/`encryption_key` assignments).
**A single hit aborts the publish** and reports the pattern -> path. Large
and binary blobs are skipped. This is a hard gate, not advisory.

## Stage 3 — Internal AI vulnerability audit
Before a release is blessed, the code is audited by **fleet-internal LLMs**
(no third-party/cloud AI, no code leaves the LAN): DeepSeek-R1 and
Qwen2.5-Coder running on local Ollama nodes, orchestrated by the Project
Index `/audit` service. The audit combines:
- static secret detection,
- dependency review,
- LLM-driven source review (auth gaps, injection, SSRF, deserialization,
  path traversal, crypto misuse).

Findings are triaged in a control plane (`fixed` / `dismissed` with a
written verdict). **Auditor output is treated as a lead, not a verdict:**
every finding is verified against the real source before it is fixed or
dismissed — automated scanners over-report (stale snapshots, hallucinated
files), so human/maintainer verification is mandatory.

## Before any of it — regenerate the derived pages

The public site carries two generated trees, and both are derived from files a
release necessarily touches:

```bash
python3 deploy/gen_site_docs.py        # site/docs/*.html   <- docs/*.md
python3 deploy/gen_release_notes.py    # site/releases/*.html <- CHANGELOG.md
python3 deploy/stamp_site_assets.py    # asset hashes, hero pill, installer banner
```

Cutting a version means editing `VERSION` and `CHANGELOG.md`; both feed the
site. The suite fails if they are stale, so this is a reminder rather than a
rule you can forget — but running it after the tests and before the sync saves
a round trip.

---

## Stage 4 — Publish
On a clean gate the sanitized history is force-pushed to the public Gitea
prod repo and the GitHub mirror, the `gh-pages` site is regenerated from
`site/`, and the release artifacts (installer + offline bundles + SHA256)
are published to the package registry / GitHub Release.

## Why publish this
Users of a security tool deserve to know how its releases are vetted.
Publishing the pipeline is part of the trust model: reproducible
sanitization, a hard secret gate, and an internal audit that runs on
every release.
