# Release Notes & Upgrade Planning

A searchable corpus of **known** and **resolved** issues (plus the prose
sections) across firmware versions of FortiWeb, FortiADC, FortiAuthenticator,
FortiAnalyzer and FortiGate, **imported from signed packs** — built to **plan
upgrades**: diff your current firmware against a target and see what you
*gain* (issues fixed) and *inherit* (issues still open).

> **Since SATOM 3.0** the corpus has exactly one source: the `docs` section of a
> signed pack. SATOM performs no HTTP to any vendor documentation site; the
> docs.fortinet.com crawler, its HTML parsers and the *Scan from Fortinet* panel
> left the product and live only in the separate
> [Knowledge Harvester](knowledge-harvester.md). This document is maintained in
> this repository.

- **Service:** `app/services/release_notes.py` (pure — no DB, no network)
- **Store:** the JSON corpus `reports/_release_notes.json` — read with
  `load_db()`, merged with `merge_db()`, written with `save_db()`. There are
  **no** release-notes DB tables. `reports/` is a **symlink into the gitignored
  `data/reports/`**: the corpus is local to each node and reaches the standby
  through `satom-ha-datasync`, never through git (§3).
- **UI:** account menu (top right) → **Release Notes** — a modal
  (`app/templates/partials/release_notes_modal.html`,
  `app/static/js/release_notes.js`) served by `app/views/release_notes.py`
  (blueprint `release_notes`, url prefix `/release-notes`), offered in the
  FortiWeb, FortiADC, FortiAuthenticator, FortiAnalyzer and FortiGate ADOMs
- **Source:** the `docs` / `release-notes` items of an API pack or a knowledge
  pack ([api-library.md](api-library.md) §12), written by
  `services.api_pack` on import; online nodes receive knowledge packs from the
  knowledge feed (`services.knowledge_fetch`, user guide §22.4), air-gapped
  nodes by upload

## 1. Where the data comes from

Fortinet publishes a *Release Notes* document per product and version. The
knowledge harvester reads them, parses the Bug-ID tables and the prose
sections, and ships the result as one `release-notes` item per product:
`{product, generated_at, versions, issues[], sections[]}`. SATOM imports it per
(product, version):

- a version this node does not hold is **added**;
- a version a pack wrote earlier is **replaced** when an outranking pack (the
  newer snapshot) carries a different copy — that is how a corrected parse
  reaches a node (API library §12.5);
- a version this node scanned **itself** before 3.0 is local data and is never
  replaced.

Every row is tagged with its product, and every read is filtered by the ADOM
the user is in — a FortiADC workspace never shows FortiWeb rows.

### Sections

| Key | Title | Title elsewhere | Products | Kind |
|---|---|---|---|---|
| `known` | Known issues | — | all | Bug-ID table |
| `resolved` | Resolved issues | — | all | Bug-ID table |
| `whats_new` | What's new | *New features or enhancements* (FortiGate) | all but FortiAnalyzer | prose |
| `upgrade_notes` | Upgrade notes & important information | *Special notices* (FAC, FAZ, FortiGate) | all | prose (advisor) |
| `upgrading_from` | Upgrading from previous releases | *Upgrade instructions* (FAC), *Upgrade information* (FAZ, FortiGate) | all | prose (advisor) |
| `repartitioning` | Repartitioning the hard disk | — | FortiWeb | prose (advisor) |
| `ha_upgrade` | Upgrading an HA cluster | — | FortiWeb | prose (advisor) |
| `downgrading` | Downgrading to a previous release | *Downgrading to previous firmware versions* (FAZ, FortiGate) | FortiWeb, FAZ, FortiGate | prose (advisor) |
| `image_checksums` | Image checksums | *Firmware image checksums* (FAZ, FortiGate) | all but FortiADC | prose |
| `vm_license` | FortiWeb-VM license validation | — | FortiWeb | prose (advisor) |
| `product_integration` | Product integration & support | — | all | prose |
| `introduction` | Introduction | — | all | prose (stored; not offered in the Notes tab) |

`SECTIONS_BY_PRODUCT` decides which prose sections the Notes tab offers for a
product, `SECTION_LABEL_BY_PRODUCT` the title each is shown under, and
`UPGRADE_SECTIONS` (marked *advisor* above) the subset the upgrade advisory
reads. *Special notices* is the counterpart of FortiWeb's *Upgrade notes and
important information*, so it is stored under `upgrade_notes`.

> **The key fact for upgrade planning:** the *same* Bug ID flips
> **Known → Resolved** across versions, so "what does upgrading current →
> target fix / leave open" is a pure diff over this data.

### Freshness

The modal, the Scout advisory and the Migration report name where the
knowledge came from: **"Knowledge from `<pack>` (`<date>`)"**, with a warning
when the pack is older than 30 days or no pack has been imported
(`knowledge_fetch.freshness()`).

## 2. Topics (curated)

Issues have **no** category column upstream, so each is tagged with a **curated**
topic by a deterministic, offline keyword classifier (`TOPIC_RULES` /
`classify_topic`): *SSL/TLS & Certificates, High Availability, Authentication &
SSO, Logging & Reports, FortiGuard & Updates, GeoIP & IP Reputation, WAF /
Signatures, API Protection, Server Policy & Pools, Networking, Machine Learning,
Bot Mitigation, Caching & Compression, GUI / Web UI, Upgrade & Configuration,
System & Performance,* else *General*. The modal's topic filter reflects the topics
actually present (`_topics()` in `app/views/release_notes.py`), so tuning the rules
never breaks the UI.

## 3. The modal (account menu → Release Notes)

Reading needs `VIEW`. Three tabs:

- **Issues** — filter by version / status (known·resolved) / topic / keyword;
  double-click a row for the full description + workaround + the source link.
- **Upgrade advisor** — pick **current → target**. Two answers, stacked, and
  they are different KINDS of answer:
  - **Scout advisory** (top) — the verdicts: what will block or complicate this
    window, each with the vendor's sentence attached. See §6.
  - the bug diff (below) — issues *resolved in the range* (gained), issues
    *still known in the target* (inherited), and the upgrade-notes prose
    (`GET /release-notes/advise?current=…&target=…` →
    `services.release_notes.advise`).
- **Notes** — full-text search the prose sections (What's new / Upgrade notes / …).

The version pickers of the Issues and Notes tabs also list the builds the
operator's appliances of this product run, marked *in your fleet — no notes
here*, when the corpus lacks them. Picking one — or opening the modal on an
empty corpus — never renders an empty list. It says:

> **"No release notes for this build in the local corpus — import a newer
> knowledge pack (Software Update → Knowledge packs)."**

Two buttons:

- **⟳ Reload corpus** (`POST /release-notes/reload`, any signed-in user)
  re-reads the JSON from disk and reports **where from** (`source`) and **how
  old** (`generated_at`): the counts on screen go stale while a pack import
  finishes in another gunicorn worker, or while `satom-ha-datasync` drops a
  fresher corpus in.
- **Knowledge packs…** (administrators) opens Software Update → Knowledge packs,
  where the feed is checked and packs are downloaded and imported.

**Sharing between nodes is data replication, not git.** The primary imports;
`satom-ha-datasync` carries `data/` to the standby within 5 minutes.

### What was removed, and why

- **The scan (3.0).** The *🔎 Scan from Fortinet* panel, version discovery, the
  HTML parsers and the routes `/release-notes/scan`, `/release-notes/discover`
  and `/release-notes/scan/status` are gone, together with the scan status file.
  The harvester carries that work, with its rules intact: a page that is
  published but cannot be parsed is reported as *unreadable*, never as "no
  notes"; a page that genuinely says "there are no known issues" is told apart
  from an empty table. Guard: `tests/test_no_vendor_http.py` — no module under
  `app/` that imports an HTTP client names a Fortinet web host.
- **The crawler fallback (2.13).** A crawler-based transport with its endpoint
  and key fields was removed on 2026-10-07; nothing in SATOM configures a
  crawler any more.
- **The git controls (2026-09-14).** *Publish to git* and *⤓ Sync from git*
  (`POST /release-notes/sync`) were removed: `reports/` is a symlink into the
  gitignored `data/reports/`, so git refused the path; `/sync` ran `git pull`
  over the running code tree for a `VIEW` user; and its success message
  described the local file either way. Guards:
  `tests/test_release_notes_nogit.py`.

## 4. Data model

`ReleaseIssue(product, version, status, bug_id, description, workaround, topic,
source_url)` and `ReleaseSection(product, version, section, title, content,
source_url)`, serialised to `reports/_release_notes.json`
(`{generated_at, versions[], issues[], sections[]}`).

There is **no DB projection** — the JSON corpus *is* the store. A pack import
merges into it and rewrites it; each request re-reads and product-scopes it
(`load_db`, via `_load()` in `app/views/release_notes.py`). Which pack wrote
each (product, version) is recorded in `data/apipacks/provenance.json`.
`version_key` zero-pads a version so a plain sort ranks versions, and the filters
are pure functions over the loaded lists — `filter_issues(issues, version=,
status=, topic=, query=)` for the Issues tab, `advise(...)` for the advisor.

The upgrade advisory is a pure function `advise(issues, sections, current, target)`
→ `UpgradeAdvisory(resolved, known_in_target, notes, is_upgrade)`, exposed to the
modal as `GET /release-notes/advise?current=…&target=…`.

## 5. Routes (read-only, plus one switch)

```http
GET  /release-notes/data         → counts, versions, fleet_missing, topics, sections,
                                   empty_reason, knowledge (pack + date + stale)
GET  /release-notes/issues       → rows (+ empty_reason when the build has no notes)
GET  /release-notes/notes        → prose sections (+ empty_reason)
GET  /release-notes/advise       ?current=…&target=…   the bug diff
GET  /release-notes/advisory     ?current=…&target=…   the Scout advisory (§6)
POST /release-notes/reload       → {counts, message, source, generated_at}
POST /release-notes/scout-switch   admin (USER_MANAGE): Scout on/off (§6, "Switching it off")
```

There is no CLI entry point for the corpus itself. Packs are imported with
`satom execute apipack import …` or `satom execute knowledge fetch --import
--yes` (see [cli.md](cli.md)).

## 6. Scout Advisory (`services/release_advisor.py`)

`GET /release-notes/advisory?current=…&target=…` → an `Advisory`:

```
verdict        blocker | caution | clear | unknown
findings[]     {rule, severity, title, detail, evidence, version, section,
                source_url, data}
path[]         the required hop sequence, when one was stated
gaps[]         the (version, section) pairs the advisory NEEDED and does not have
read[]         the coverage it did have
rules_digest   a seal over the rules' own source
```

`detail` is our instruction; `evidence` is the vendor's sentence **verbatim**. A
rule that paraphrases a prerequisite and gets it slightly wrong is worse than no
rule, because it is believed.

**The case it was built for.** FortiWeb 8.0.7 is a maintenance release whose
*Supported upgrade paths* states that anything at 7.6.1 or lower must land on
7.6.2 first, and that 7.6.2 expands the partition and needs 1.5 GB free on the log
disk. Both sentences sit inside a 13 000-character page — which is exactly the
page an operator skims when the version number ends in `.7`.

Three rules of the house, carried over from Scout's ladder:

- **Absence is never innocence.** Missing coverage yields `unknown`, never
  `clear`, and the gaps are named. A gap says WHICH kind it is: a version nobody
  harvested, or a version harvested before these sections were collected (which
  is fixed by importing a newer knowledge pack).
- **The criteria are not editable.** `RULES` is the single author of every
  verdict and `rules_digest()` hashes the rules' own source onto the report, so an
  archived advisory names the rule set that produced it. An editable threshold
  would make a second author of a verdict nobody can reproduce.
- **A catch-all beats a complete list.** `vendor-marked` carries through every
  block Fortinet themselves flagged *Caution* / *Warning*, so prose no tailored
  rule understands still reaches the operator — with no verdict attached and no
  pretence of one. Where a tailored rule already cites the same block, the
  catch-all copy is dropped: printed twice, the weaker one sits under an
  instruction that already said what to do.

Rules are direction-aware: an upgrade advisory never quotes the *Downgrading*
page, and a rollback advisory never quotes *Supported upgrade paths*.

### 6a. Two renderers, one detector (`admonitions()`)

Fortinet mark admonitions in **two shapes**, and until 2026-09-14 the catch-all
only knew one of them:

| shape | looks like | docset |
|---|---|---|
| pure | the mark ALONE on its line, body in the block after it | markdown (`src-md`) |
| embedded | the mark glued to the sentence — `Note : This issue has been…` | MadCap (`src-mc`) |

Measured over the live corpus the day it was found: **0** pure-mark lines in
every FortiWeb release from 7.6.5 to 8.0.6, and **18** in 8.0.7. Eleven releases
of caveats carried by nothing, with nothing red and nothing logged — the same
class of failure as the harvester's, one layer up.

`admonitions(ctx, *sections)` is the single author of "what the vendor marked".
It returns `(mark word, body block)` — the word **as Fortinet wrote it**, so a
vendor *Warning* is not reprinted as our `caution` bucket, which would be a
classification of ours set in the typography of a quotation.

The `header + paragraph` heuristic was **measured and rejected**: over the same
corpus it matches **28–30 blocks per version**, which would bury the panel it is
meant to sharpen. Detection is narrow on purpose; the heading is read only to
TITLE a finding whose trigger is already the prose below it.

### 6b. Destination-scoped rules (`TARGET_SCOPED`)

Every other rule asks *"does the move start low enough for this to bite?"* — it
compares the current version against a floor the vendor wrote down. A whole
class of hazard has **no floor**:

> If you are running FortiWeb in a VM environment and the total number of
> configured server policies exceeds 20, **do not upgrade to FortiWeb 8.0.7 at
> this time.**  — *8.0.7, Upgrade notes*

That is true from 8.0.6 and true from 7.2.1 alike. A rule set that can only
express floors answers "nothing found" for every origin, and this sentence sat
correctly harvested in the corpus while the advisory said `caution`.

`target-prohibition` fires when the vendor names the version being **installed**
— the target, not merely a version the span steps over. Gating on "is it inside
the span" made `7.2.1 → 8.0.7` raise a blocker about a FortiWeb 100D
incompatibility with 7.6.0, a release that route never lands on.

- It is **conditional by nature and says so**: the title carries the vendor's own
  heading for the condition, the evidence is their sentence verbatim, and the
  panel prints *"Applies to the DESTINATION — this holds no matter which version
  you upgrade from"*. Demoting it to a note because it might not apply would bury
  the words *do not upgrade* under four other notes; a blocker that names its own
  condition is a gate an operator clears in one glance.
- It **respects a floor the vendor stated inside the block** (*"not supported to
  upgrade to 8.0.5 from versions earlier than 6.3.0"*), via the same
  `_floor_excludes()` the catch-all filter uses — one author, so the two cannot
  drift.
- It ranks **first** in `RULE_ORDER`: "there is no window" is read before "the
  window needs two halves".
- **Known limit, stated rather than hidden:** a prohibition attached to a
  mandatory HOP is not raised, because the hops are derived from the findings and
  do not exist yet when the rules run. That hop's own advisory shows it.

### 6c. The coverage guard

`admonition_coverage(sections)` counts, per version, the blocks the catch-all can
actually see. A zero is **never** "that release had nothing to warn about" —
Fortinet mark the upgrade pages of every FortiWeb release. A zero means the
parser and the renderer have parted company.

`tests/test_advisor_admonitions.py::test_live_corpus_has_no_blind_version` reads
whatever corpus is on disk and fails on silence. It is the only assertion in that
file that does not already know what the prose looks like, and therefore the only
one that can catch the **next** renderer change. It skips where no corpus exists
(fresh install, CI), because "never harvested" is a different problem and failing
on it would train the team to ignore the test.

### Switching it off

`scout.enabled` (Settings → Scout → **Availability**, and the switch beside the
advisory in the modal — **the same flag**, not a second one). Off is enforced on
the **blueprint**: hiding a nav entry closes nothing, because the URL, the
bookmark and the link in a ticket all still work. `/scout/*` answers **503**, not
404 — "switched off" and "does not exist" are different answers to the operator's
next question — and the menu entry stays visible but disabled with the reason,
because an absent entry reads as a product that never had the feature.

## 7. Tests

- `tests/test_release_notes.py` — the pure corpus model (topic classifier,
  `version_key` ordering, merge, the advisory diff) and the modal's JSON routes
  against an isolated corpus.
- `tests/test_release_notes_products.py` — section maps, labels, routes and the
  pack import, per product.
- `tests/test_release_notes_pages.py`, `tests/test_release_notes_picker.py` —
  the published pages and the version pickers.
- `tests/test_release_notes_nogit.py` — the removed git controls stay removed.
- `tests/test_no_vendor_http.py` — no vendor HTTP in the product.
- `tests/test_release_advisor.py`, `tests/test_advisor_admonitions.py` — the
  rules, driven over VERBATIM vendor prose; gating, collapsing, scope, coverage
  and the seal.
- `tests/test_scout_switch.py` — the switch, enforced on the route.

No network in any of them.
