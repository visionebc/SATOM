# Release Notes & Upgrade Planning

A searchable corpus of FortiWeb **known** and **resolved** issues (plus the prose
sections) across firmware versions, harvested from `docs.fortinet.com` — built to
**plan upgrades**: diff your current firmware against a target and see what you
*gain* (issues fixed) and *inherit* (issues still open).

- **Service:** `app/services/release_notes.py` (pure — no Qt, no DB)
- **Store:** the git-shared JSON corpus `reports/_release_notes.json` — read
  with `load_db()`, merged with `merge_db()`, written with `save_db()`. There
  are **no** release-notes DB tables.
- **UI:** account menu (top right) → **Release Notes** — a modal
  (`app/templates/partials/release_notes_modal.html`,
  `app/static/js/release_notes.js`) served by `app/views/release_notes.py`
  (blueprint `release_notes`, url prefix `/release-notes`)
- **Harvest:** `POST /release-notes/scan` (the modal's 🔎 button) — there is
  **no** CLI entry point

## 1. Where the data comes from

Fortinet publishes a *Release Notes* document per version at
`docs.fortinet.com/document/fortiweb/<version>/release-notes/<id>/<slug>`. The
section ids are **stable** across the recent docsets:

| Section | id | slug | kind |
|---|---|---|---|
| Known issues | `54989` | `known-issues` | Bug-ID table |
| Resolved issues | `91537` | `resolved-issues` | Bug-ID table |
| What's new | `639023` | `whats-new` | prose |
| Upgrade notes & important information | `745354` | `upgrade-notes-and-important-information` | prose |
| Upgrading from previous releases | `81434` | `upgrading-from-previous-releases` | prose |
| Product integration & support | `756870` | `product-integration-and-support` | prose |

The issue sections are two-column `Bug ID` / `Description` tables (a known issue
often embeds a `Workaround:` — split into its own field). The pages are served
**server-side** (no JS), so a plain `httpx` GET works headless; a **Firecrawl**
transport (self-hosted LAN or cloud) is available as a fallback.

> **The key fact for upgrade planning:** the *same* Bug ID flips
> **Known → Resolved** across versions, so "what does upgrading current → target
> fix / leave open" is a pure diff over this data.

### Coverage / limitation

Only pages that carry the MadCap `mc-main-content` article are harvested
(`has_release_content`). **Older maintenance releases** whose section ids drifted
resolve to a 200 *landing* (just the version-switcher chrome) — those are skipped
so nothing bogus is stored. In practice the harvested range is the recent,
upgrade-relevant releases (validated: FortiWeb **7.6.5–7.6.9** and **8.0.2–8.0.5**,
181 issues / 36 sections as of 2026-06). Versions that don't publish parseable web
release notes simply have no data (better than garbage).

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

Reading needs `VIEW`; the 🔎 scan needs `USER_MANAGE` (admin). Three tabs:

- **Issues** — filter by version / status (known·resolved) / topic / keyword;
  double-click a row for the full description + workaround + the source link.
- **Upgrade advisor** — pick **current → target**: the issues *resolved in the
  range* (gained), the issues *still known in the target* (inherited), and the
  upgrade-notes prose (`GET /release-notes/advise?current=…&target=…` →
  `services.release_notes.advise`).
- **Notes** — full-text search the prose sections (What's new / Upgrade notes / …).

### 🔎 Scan from Fortinet

Auto-discovers every version from the docs site and harvests the selected
`major.minor` families, merging them into `reports/_release_notes.json`.
**No appliance needed** — it reads the public docs directly with a Firecrawl
fallback (both transports on by default). Optionally publishes to git (multiuser-
safe, like the inspector reports). Admin only (`USER_MANAGE`).

`⤓ Sync from git` (`POST /release-notes/sync`) pulls the shared reference and
re-reads it, so a fresh clone that pulled the JSON is current on first open.

## 4. Data model

`ReleaseIssue(product, version, status, bug_id, description, workaround, topic,
source_url)` and `ReleaseSection(product, version, section, title, content,
source_url)`, serialised to `reports/_release_notes.json`
(`{generated_at, versions[], issues[], sections[]}`).

There is **no DB projection** — the JSON corpus *is* the store. A scan merges into
it (`merge_db`) and rewrites it (`save_db`); each request re-reads and
product-scopes it (`load_db`, via `_load()` in `app/views/release_notes.py`).
`version_key` zero-pads a version so a plain sort ranks versions, and the filters
are pure functions over the loaded lists — `filter_issues(issues, version=,
status=, topic=, query=)` for the Issues tab, `advise(...)` for the advisor.

The upgrade advisory is a pure function `advise(issues, sections, current, target)`
→ `UpgradeAdvisory(resolved, known_in_target, notes, is_upgrade)`, exposed to the
modal as `GET /release-notes/advise?current=…&target=…`.

## 5. Running a scan (there is no CLI)

The harvest runs **in the app**, as a background thread behind the modal's
🔎 **Scan from Fortinet** button (`_do_scan` in `app/views/release_notes.py`):

```http
POST /release-notes/scan
{"majors": "7.6,8.0", "all": false, "use_direct": true,
 "use_firecrawl": true, "firecrawl_endpoint": "http://192.0.2.66:3002",
 "publish": true}

GET  /release-notes/scan/status   → {running, lines[], result, error}
POST /release-notes/sync          → git pull + re-read the shared corpus
```

`majors` defaults to `7.0,7.2,7.4,7.6,8.0`; `all` harvests everything the docs
site lists (slow). The worker writes `reports/_release_notes.json` and, with
`publish`, commits it through `services/git_service.git_publish` so the team
shares one corpus.

## 6. Tests

`tests/test_release_notes.py` — HTML-fixture parsing, the content guard, the
curated topic classifier, `version_key` ordering, the scan (fake fetcher), merge,
the advisory diff, and the store projection + range queries (no network, no Qt).
