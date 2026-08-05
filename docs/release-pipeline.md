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
