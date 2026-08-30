# Release & publication pipeline

SATOM is developed privately and published publicly through an
automated, deterministic gate. Nothing reaches the public mirror by hand.
This document is the source of truth for that process and is intentionally
public so users can see exactly how releases are produced and vetted.

**There are exactly two repositories, and they are not peers.** Development is
private and holds the full history; the public mirror is derived from it by the
gate below and is the only thing anyone installs from. A third, intermediate
mirror existed until 2026-08-30 and was **retired**: it was always pinned to the
same commit as the public mirror, so it added a hop that could fail without
adding a copy that could be restored from — and its package registry was the
undeclared source of the public release assets, which made an ordinary cleanup
into an outage waiting to happen. Release assets are now taken from the build
output directly.

The public **documentation and product site is not GitHub Pages.** Pages is
switched off for this project; `satom.visionebc.com` is served from its own
repository and its own node (Stage 0, hop 7).

```
   INTERNAL (private)                    GATE                     PUBLIC
  ┌──────────────────┐   ┌───────────────────────────────┐   ┌──────────────┐
  │ Gitea dev repo   │──▶│ 1. Sanitize (git-filter-repo) │──▶│ GitHub mirror│
  │ satom-dev        │   │ 2. Secret scan (gitleaks-like) │   │ + Releases   │
  │ (full history)   │   │ 3. Internal AI vuln audit      │   │ (public)     │
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
| 6 | **Public mirror** | sanitised history, release artefacts, tagged releases | stages 1–4 of this document |
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

**The PEM rule matches key MATERIAL, not the label** (2026-08-30). It used to
fire on a bare `-----BEGIN … PRIVATE KEY-----` header, so an HTML `placeholder=`
attribute, a test fixture whose body is the letter `B` repeated, and a design
note in Markdown all aborted the publish exactly as a real key would. The
practical cost was not noise: the scan runs over the **whole** history of the
mirror, so neutralising the files at `HEAD` unblocked nothing, and the public
repository sat frozen for twelve days before anyone attempted a publish and
found out. The header must now be followed by **at least 40 base64 characters
within the next 200 bytes**. The window is deliberately narrow — widen it and
the header starts pairing with unrelated base64 further down the file (a
data-URI, a CSP nonce) and the false positive returns through another door.

Narrowing a scanner that guards a public repository is only defensible with
evidence that it still bites. `tools_check_secret_patterns.py` **generates**
eight real key encodings — PKCS#8, traditional RSA, EC, ED25519, OpenSSH, a
`DEK-Info` encrypted PEM, a JSON-escaped one-liner and a YAML block scalar —
and asserts every one still aborts, alongside seven labels that must not.

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
On a clean gate the sanitized history is force-pushed to the **public GitHub
mirror** — one destination, with every version tag repointed at the sanitized
commit that carries the same tree — and the release artefacts (installer +
offline bundles + `SHA256`) are attached to the matching **GitHub Release**.

Three properties of this stage are worth stating because none of them announces
itself when it breaks:

- **The artefacts come from the build output.** They used to be copied out of
  the intermediate mirror's package registry, which quietly made a repository
  nobody looked at into a mandatory link in the chain of custody for every
  public download. The source of a published artefact is now the artefact.
- **A release refuses to carry a filename that disagrees with `VERSION`.** If
  the built bundles are `…-1.10.1-…` and `VERSION` says `1.20.0`, the publish
  **aborts** rather than creating a `v1.20.0` release whose assets are named
  after a different build. That mismatch is invisible after the fact — the
  release is created, the files upload, and every step reports success — so the
  only place it can be caught is before the upload.
- **Every commit on the mirror is attributable.** The rewrite stamps a single
  public identity, and the address it stamps is the account's `noreply` form
  (`<id>+<login>@users.noreply.github.com`), not the contact address published
  in the source. GitHub only links a commit to an account through a **verified**
  address; the contact address is not one, so the entire public history read as
  authored by nobody — no account, no avatar, no link — while every check
  passed, because "all identities are identical" and "the identity is
  attributable" are different claims. The numeric account id is used rather
  than the login because a login can be renamed and the id cannot.

## Why publish this
Users of a security tool deserve to know how its releases are vetted.
Publishing the pipeline is part of the trust model: reproducible
sanitization, a hard secret gate, and an internal audit that runs on
every release.
