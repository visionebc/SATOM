# API library — versioned, append-only, in the database

> **Audience:** operators who keep the library fed and read its pages, and
> engineers who write an adapter or a reader. Operator walkthroughs of the
> pages built on it are in the [User guide](user-guide.md) §30.5,
> §30.8–§30.12, §40.3 and §41.8–§41.9; the guards are catalogued in
> [Safeguards](safeguards.md) §192–§193, §196 (endpoint baselines, §9
> below), §197 (per-build resolution, §9.8) and §209–§213 (the CLI channel,
> §13). The features built on the CLI channel have their own pages:
> [Build compatibility](build-compatibility.md),
> [Migration report](migration-report.md), [CLI writer](cli-writer.md) and
> [Knowledge Harvester](knowledge-harvester.md).
>
> **Since:** SATOM 2.2.0. CLI channel: 2.13.0 (unreleased).

The API library is SATOM's record of **which API each firmware build serves**:
endpoints, fields, field types and options, per product and per exact build,
**by both channels** — REST and the CLI — with every claim traceable to the
evidence it came from. It lives in the application database (the `api_lib_*`
tables), it only ever grows, and every page that answers a firmware question
reads it.

**The key is always the exact build, never the API version.** Two builds that
speak the same REST API version still differ in fields (FortiWeb 7.6.8 and
8.0.6 both answer `/api/v2.0/`; 8.0.6 has 135 more fields and 25 fewer).

---

## 1. What it is for

The library answers four questions. The file-based matrix it replaces could
answer none of them at scale.

1. **Which API does this appliance speak?** Resolve the appliance's running
   firmware to an exact build and list what that build serves.
2. **What changed between two builds?** Endpoints and fields added, removed,
   or retyped, and "since which build does field X exist?"
3. **Can I move this object from device A to device B?** What is lost, what
   the destination offers, and whether the destination serves the endpoint at
   all.
4. **Incremental knowledge.** Every harvest adds evidence. Nothing is lost when
   an appliance is retired, deleted or upgraded.
5. **By which channel?** Does this build serve the field over REST and the CLI,
   the CLI only, only in `show full-configuration`, or REST only (§13.3) — and
   therefore: will a write on this build keep it
   ([Build compatibility](build-compatibility.md)), will this box's
   configuration survive the move ([Migration report](migration-report.md)),
   and does it have to be written by CLI ([CLI writer](cli-writer.md))?

**Why it replaced the files.** The previous store (`data/api_matrix/*.json`,
`data/rediscovery/*/by-version`, `data/field_schemas`) was derived and
rewritten wholesale on every rebuild, and the rebuild filtered its evidence
through the live appliance table. Deleting an appliance therefore deleted the
proof of what its firmware served. That is how the **8.0.3** build disappeared:
it had been measured on two FortiADC appliances that were later retired. A test
run once overwrote the production matrix with an empty one the same way. The
backfill (§8.3) re-read the archived evidence, and 8.0.3 is back.

The JSON matrix file still exists, as an **export only** (§7).

---

## 2. The model

### 2.1 Principles

- **Evidence is immutable.** A harvest is stored once, with its raw payload
  (gzip) and a content hash. Re-harvesting identical content only bumps
  `last_confirmed_at` and `confirmations` on the existing row. Ingest is
  idempotent: running any import twice creates nothing the second time.
- **Facts are bounded.** Facts are keyed by (field, build, source), not by
  harvest. Growth tracks the number of distinct builds, not the number of
  sweeps: a daily sweep of an unchanged box adds no fact rows.
- **Nothing is filtered by the live appliance table.** Device identity (name,
  serial, model, platform, raw firmware string) is copied into the evidence
  row. Retired and deleted devices keep their evidence and are listed as
  `retired` witnesses instead of dropping out.
- **Unknown is never "compatible".** `fields=None` (endpoint answered, no rows
  revealed any field) is not `fields={}` (measured, none). A build with no
  evidence is `unmeasured`. "Removed" requires both builds to be measured.
- **Vendor data is a claim, not a measurement.** It is labelled `vendor_doc`
  everywhere, never outranks a sweep of a real appliance, and an open vendor
  range stops at the newest build the vendor's data knows about.
- **Nothing is deleted.** No code path in this feature deletes a row. A wrong
  rename mapping is retired, not removed.
- **Product-agnostic.** FortiWeb, FortiADC, FortiAuthenticator, FortiAnalyzer
  and FortiGate use the same tables. FortiGate is **catalog-only**: SATOM does
  not manage FortiGates, but the library holds their API for reference.

### 2.2 Build statuses

Every page reports one of these for a build. They are deliberately distinct.

| status | meaning |
|---|---|
| `measured` | at least one real appliance (or a live schema read) produced evidence for this exact build |
| `vendor_only` | only vendor data covers this build; nothing of ours confirmed it |
| `unmeasured` | the library has no evidence for this build; every endpoint is *unknown* here, never compatible |
| `unknown_firmware` | the appliance's firmware was never read, so there is no build to look up |

A build whose patch level was never recorded (a line such as `8.0` held as a
build) is shown as **patch unknown**. It is not `8.0.0`.

### 2.3 Endpoint and field answers

For one endpoint on one build the library answers `measured`, `blind`,
`unmeasured` or `absent`:

- **measured** — the fields are known, with type, options, default and
  whether a write needs them, where the source reveals that;
- **blind** — the endpoint answered, but no row revealed its fields. On
  FortiWeb this is every empty collection. It is not "an endpoint with no
  fields";
- **unmeasured** — nobody asked this build about this endpoint;
- **absent** — measured, and this build does not serve the endpoint.

Verdict merge within one build: `ok` from any healthy witness wins, then
`absent`, then `error`. An `error` only means the build was asked and did not
answer; it is never read as "not served".

### 2.4 Source priority

When two sources describe the same thing, the order is
`sweep` > `schema` > `cli_tree` > `cli_full` > `manual` > `legacy_matrix` >
`vendor_doc`. The two CLI sources describe the CLI channel and are never read
by a REST answer (§13).
**Fields are compared only within one kind of evidence.** A sweep carries
wire-only companions (`_val` twins, `sz_`/`q_` internals) that a schema
strips, and subtracting one from the other invents removals. A field set known
on one side only, or by different kinds on the two sides, is reported as
*unknown*, never as added or removed.

---

## 3. Products and sources

| Product key | Evidence sources | Where the evidence comes from |
|---|---|---|
| `fortiweb` | `sweep`, `schema`, `cli_tree`, `cli_full` | rediscovery sweeps of live appliances; field schemas harvested per firmware line; the CLI `tree` and `show full-configuration` of each build (§13), plus a shape-checked REST probe of every `tree` object |
| `fortiadc` | `sweep`, `legacy_matrix`, `cli_tree`, `cli_full` | sweeps, and the frozen line-only matrix file from before the build axis; the CLI adapter is **unverified**. No FortiADC is left in the lab fleet, so no new FortiADC evidence arrives until one is registered or a pack brings it |
| `fortiauthenticator` | `schema` (and `sweep`), `cli_tree`, `cli_full` | a live, **read-only** harvest of the device's own Tastypie schema (`GET /api/v1/` and `GET /api/v1/<resource>/schema/`); its small setup CLI read by a `set ?` help walk |
| `fortianalyzer` | `vendor_doc`, `schema` | the vendor's Ansible collection `fortinet.fortianalyzer` (its `v_range` data); the JSON-RPC syntax read (**unverified** adapter) |
| `fortigate` | `vendor_doc`, `schema`, `cli_tree` | the vendor's Ansible collection `fortinet.fortios` (its `v_range` data); `?action=schema` and the CLI `tree` from a lab box, by pack or file import. Catalog-only |

Which adapter reads which channel of which product, and on which device and
build it was verified, is §13.10.

Source vocabulary (closed set): `sweep`, `schema`, `vendor_doc`, `manual`,
`legacy_matrix`, and the CLI channel `cli_tree` and `cli_full` (§13).
Anything else is refused at ingest.

**What the library held when 2.2.0 was cut** (measured):

| Product | Source | Size |
|---|---|---|
| FortiAuthenticator | live schema, 8.0.3 | 58 resources, 316 fields |
| FortiAnalyzer | `fortinet.fortianalyzer` 1.10.0 | 202 endpoints, 2,275 fields, 56 builds (6.2.1 – 7.6.4) |
| FortiGate | `fortinet.fortios` 2.6.0 | 723 endpoints, 11,049 fields, 37 builds (6.0.0 – 8.0.0) |

**Why not the FortiWeb and FortiADC Ansible collections.** `fortinet.fortiweb`
and `fortinet.fortiadc` carry no per-endpoint or per-field version data (only
the `version_added` of the collection itself). An endpoint list without ranges
would assert "valid on every build", which is exactly the claim the library
refuses to make without a measurement. Importing one is accepted and imports
nothing (§8.2).

**FortiAuthenticator specifics.** The harvest issues `GET` requests only. A
schema request that fails with a server error on a non-database singleton is
not a missing resource: the verdict comes from the list response, and the field
names come from the one object the device returned. A `405` on `GET` means
"served, but not readable" (POST-only actions), so those are `ok`. "Absent"
needs a directory that answered and did not list the resource, or a `404` on
the resource itself. "Required" is computed with Tastypie's own rule: not
read-only, not blank, not nullable, and no default.

---

## 4. The evidence document (the ingest contract)

Every adapter (sweep, schema directory, vendor collection, live FAC schema,
legacy matrix) produces this plain dict. `api_library.ingest(doc, raw=...)` is
the only writer.

```python
{
  "product": "fortigate",                 # product key
  "source": "vendor_doc",                 # closed vocabulary above
  "captured_at": "2026-09-25T21:00:00",   # when the evidence was produced
  "origin_ref": "ansible:fortinet.fortios:2.6.0",   # where it came from
  "device": None | {                      # None for vendor/manual evidence
      "appliance_id": 34, "name": "appliance-a", "serial": "FVVM...",
      "model": "FortiWeb-KVM 8.0.5", "hw_type": "vm",
      "firmware_raw": "8.0.5,build0123"},
  "scope": {"kind": "build", "version": "8.0.5", "build": "build0123"}
         | {"kind": "line", "line": "8.0"}
         | {"kind": "spans", "versions": ["6.0.0", "6.2.0", ...]},
  "healthy": True,                         # False => stored, never folded into facts
  "skip_reason": "",
  "endpoints": {
     "<logical name>": {
        "urn": "/api/v2/cmdb/firewall/policy",
        "section": "firewall",
        "verdict": "ok" | "absent" | "error",   # point evidence only
        "rows": 3,                               # None when not known
        "spans": [["6.0.0", ""]],               # spans evidence only; "" = open end
        "fields": None | {                      # None = fields not revealed (blind)
            "<field>": {"type": "str", "options": ["enable", "disable"],
                        "default": "enable", "required": False,
                        "children": ["name", "id"],   # nested table columns
                        "spans": [["6.2.0", "7.4.3"]]}   # spans evidence only
        }
     }
  }
}
```

**Content hash.** sha256 of the canonical JSON (`sort_keys`, compact) of the
measurement and of who measured it: product, source, scope (without its build
token), endpoints, health, summary and the witness (appliance id, or device
name when there is none). `captured_at`, `origin_ref` and device decoration
(serial, model, platform, raw firmware string, build token) are left out, so a
live sweep and a later backfill of the same snapshot are one evidence row,
while two appliances returning identical content stay two witnesses. The hash
is unique per (product, source).

**Health.** A sweep in which more than **25 %** of the endpoints errored is
stored with `healthy=False` and never folded into facts: a half-refused pass
(a licence lapse, for instance) would otherwise read as a build that lost half
its API. The FortiAuthenticator harvest applies the same ratio, and marks a
pass unhealthy when its directory did not answer or its firmware could not be
resolved.

**Logical endpoint names.** FortiWeb, FortiADC, FortiAuthenticator and
FortiAnalyzer reuse the registry `name` where one exists. FortiGate uses the
Ansible module name without the `fortios_` prefix (`firewall_policy`); its URN
is `/api/v2/cmdb/<path>/<name>`. FortiAnalyzer uses the module name without
`faz_` and the first `jrpc_urls` entry as URN. A FortiAuthenticator resource
the registry does not name is filed under a derived name in section `other`.

**Vendor ranges.** Stored as ranges, never expanded per build. `""` as the end
of a span means "open". The document's highest version (from any range edge
or `summary.max_version`) is the **cap** for every open end: a build newer than
the collection knows about is `unmeasured`, not `ok`. When two collections
cover a build, the one that knows the newer firmware wins.

---

## 5. Tables

Models: `app/models_apilib.py`, migration `apilib01`. All tables are portable
(PostgreSQL in production, SQLite in tests).

- `api_lib_build` — `product, version, build, line, line_only, sort_key,
  origin ('evidence'|'vendor'|'declared'), first_seen, last_seen`.
  Unique (product, version). `sort_key` is a zero-padded string
  (`00008.00000.00005`) so range queries work in SQL.
- `api_lib_evidence` — `product, source, build_id (nullable), scope_kind,
  appliance_id (plain int, no FK), device_name, device_serial, device_model,
  device_hw_type, firmware_raw, origin_ref, captured_at, ingested_at,
  last_confirmed_at, confirmations, sha256, healthy, skip_reason,
  summary (JSON), raw_gz (LargeBinary, nullable)`.
  Unique (product, source, sha256).
- `api_lib_endpoint` — `product, name, first_seen, last_seen`.
  Unique (product, name).
- `api_lib_endpoint_fact` — `endpoint_id, build_id, source, urn, section,
  verdict, fields_known, witnesses (JSON list of device names), attrs (JSON,
  CLI channel metadata, migration `apilib05_cli_channel`),
  first_evidence_id, last_evidence_id, first_seen, last_seen`.
  Unique (endpoint_id, build_id, source).
- `api_lib_field` — `endpoint_id, name, first_seen, last_seen`.
  Unique (endpoint_id, name).
- `api_lib_field_fact` — `field_id, build_id, source, type, options (JSON),
  default (JSON), required, children (JSON), platforms (JSON list of hw_type
  or model), attrs (JSON: `cli_id`, `hidden`, `range`, `help`, `cli_type`,
  `datasource`, `lab_default`), first_evidence_id, last_evidence_id,
  first_seen, last_seen`.
  Unique (field_id, build_id, source).
- `api_lib_span` — `endpoint_id, field_id (nullable: NULL = endpoint span),
  evidence_id, source, from_key, to_key (nullable = open), from_version,
  to_version, attrs (JSON)`.
- `api_lib_field_map` — operator-authored renames: `product, endpoint,
  from_version, from_field, to_version, to_field, note, created_by,
  created_at, retired_at, retired_by`. Without it a rename reads as "field
  lost + field added". A wrong mapping is retired (`retired_at` set), never
  deleted; readers skip retired rows. Edited at `/web/registry/field-map`.

The vendor document's `summary` records `collection`, `collection_version`,
`min_version`/`max_version`, `modules_total`, and every module left out with
its reason (`skipped`, `skipped_by_reason`), so a shrinking endpoint count
after a collection upgrade can be explained instead of guessed at.

---

## 6. Service API (`app/services/api_library.py`)

Ingest:

- `ingest(doc, raw=None) -> dict` — idempotent; returns
  `{"evidence_id", "created": bool, "facts": {...counts}}`. Raises
  `ValueError` on a malformed document or an unknown source.
- `evidence_from_sweep(product, snapshot, device, origin_ref) -> dict` —
  rediscovery snapshot → evidence document, with the error-ratio rule.
- `evidence_from_schema_dir(product, line, path) -> dict`.
- `evidence_from_legacy_matrix(product, matrix_doc) -> list[dict]`.
- `backfill(data_root, products=None) -> dict` — reads every
  `rediscovery/*/by-version/*.json` and `_config.json` (deleted appliances
  included; device identity taken from the snapshot, falling back to
  `appliance #<id>`), `field_schemas/<product>/<line>/` (the `_default`
  fallback excluded), and the pre-build-axis matrices in `api_matrix/`.

Query:

- `products() -> list[dict]`
- `builds(product) -> list[dict]` — version, line, origin, sources, evidence
  count, measured, in_fleet, vendor_only, first_seen, last_seen. Declared
  versions and versions a live box runs are merged on read and never written.
- `endpoints_at(product, version) -> dict` — endpoint → urn, verdict,
  fields_known, sources, witnesses, first/last seen, vendor span coverage.
- `fields_at(product, endpoint, version) -> dict` —
  `{"status": "measured"|"blind"|"unmeasured"|"absent", "fields": {...},
  "provenance": [...]}`.
- `compare(product, base, target, endpoint=None) -> dict` — endpoints added,
  removed, unknown; per endpoint fields added, removed, retyped, renamed,
  unknown. Honours `api_lib_field_map`.
- `field_history(product, endpoint, field) -> dict` — builds where seen,
  first and last build, sources.
- `resolve_appliance(appliance) -> dict` — product, version, build row (or
  None), status (§2.2).
- `matrix_doc(product, versions=None) -> dict` — the document shape
  `api_matrix.build()` has always returned, so its consumers did not change.
  Each version also carries `cli` (CLI-channel object counts per source).
- `urn_key(urn) -> str` — the REST path without prefix or query; the join
  between the channels (§13).
- `channels_at(product, version, endpoint=None, exceptions=None) -> dict` —
  per field: `both | cli_only | hidden | rest_only | unknown`, with evidence
  ids and a completeness summary (§13.3). `compare()` carries the CLI half
  under `channels`.

Adapters that talk to nothing: `apilib_vendor.evidence_from_ansible_collection(path)`
(reads the collection with `ast`; vendor code is **never imported or
executed**) and `apilib_fac.evidence_from_capture(capture, device)`. The only
adapter that reaches a device is `apilib_fac.harvest(appliance)`, GET only.

---

## 7. Who reads it

| Reader | What it asks |
|---|---|
| `api_matrix.build` / `load` | `matrix_doc()`. `rebuild` still writes `data/api_matrix/<product>.json`, as an **export** for the stdlib `satom get api …` commands on a node whose database is down. Nothing in the application reads the file back |
| API versions page (`/web/registry/versions`, `/adc/api/versions`) | `builds()`, `compare()`, `endpoints_at()`, `fields_at()`, `field_history()`, for every product including FortiGate and FortiAnalyzer. It never renders a whole FortiGate matrix |
| API field renames (`/web/registry/field-map`) | writes `api_lib_field_map` |
| `version_compat` (clone/migrate pre-flight, upgrade pre-flight) | `fields_at()` and `compare()` at the exact builds from `resolve_appliance()`. Every answer carries its provenance, so a page says "vendor claims" rather than "measured". A vendor-only absence **warns**; only a measured absence blocks. The clone pre-flight also offers the destination's new fields (opt-in, validated server-side) |
| API Explorer | resolves the selected appliance to a build, marks endpoints served / absent / unknown, refuses an unserved endpoint server-side unless confirmed, and can queue a harvest |
| `firmware_probe` | queues a harvest when an appliance changes build (§8.4), and tells the new-build watch (§13.11) |
| `build_compat` (every write path) | `channels_at()`, the `tree` options and ranges, field maps and CLI ids of each target's build ([Build compatibility](build-compatibility.md)) |
| `migration_report` (Migration Report page, Upgrade Flow stage 1) | the CLI half of `compare()` and `channels_at()` of the source and target builds ([Migration report](migration-report.md)) |
| `cli_writer` (object editor) | `channels_at()` of the appliance's build, to route each field to REST or CLI ([CLI writer](cli-writer.md)) |
| Build compatibility, Schema builds pages | `channels_at()`, `compare()`, `field_history()` (§13) |

---

## 8. Operations

### 8.1 The `flask apilib` commands

Run them from the installation directory as the service account:

```
cd /opt/satom
sudo -u satom env FLASK_APP=wsgi:app venv/bin/flask apilib <command>
```

| Command | What it does |
|---|---|
| `flask apilib status` | counts per product (builds, endpoints, evidence by source, `(catalog only)`), then one line per product, build and source |
| `flask apilib backfill [--data-root DIR] [--product P ...]` | ingests every on-disk evidence store (§8.3) |
| `flask apilib import-vendor PATH` | imports an extracted vendor Ansible collection (§8.2) |
| `flask apilib ingest-file PATH` | ingests one evidence document (plain or gzipped JSON), or a JSON list of them |
| `flask apilib harvest-fac [--appliance NAME]` | reads the live schema of every FortiAuthenticator, or one, and ingests it |
| `flask apilib schema-harvest <id\|name> [--lab] [--no-probe]` | one appliance's CLI channel (`tree` + `show full-configuration`) and a REST probe of the paths the library lacks (§13.4) |
| `flask apilib adapter-harvest <id\|name> [--ssh-secret-env VAR]` | one appliance through its product's schema adapter (§13.10); for FortiAuthenticator, `VAR` names an environment variable holding the CLI password |
| `flask apilib schema-import --product fortigate\|fortianalyzer --version X [--build B] [--tree FILE] [--schema FILE]` | ingests saved schema captures of a product SATOM does not read live |
| `flask apilib compat PRODUCT BASE TARGET` / `flask apilib channels PRODUCT BUILD` | two builds through both channels / one build per channel, as JSON ([Build compatibility](build-compatibility.md) §5) |
| `flask apilib migration-report APPLIANCE --target BUILD [--backup ID]` | the [Migration report](migration-report.md) as JSON |
| `flask apilib pack export\|inspect\|import` | API packs (§11.4) |
| `flask apilib baseline status\|promote\|adopt\|export\|apply\|check\|resolve` | the endpoint baselines that seed the registry (§9) |

Every command writes through `ingest`, so every command is safe to re-run:
identical evidence answers `"created": false` and bumps a confirmation
counter. The output is JSON. The full option reference is in the
[CLI manual](cli.md) §8.

### 8.2 Refreshing vendor data (FortiGate, FortiAnalyzer)

Vendor evidence changes only when you import a newer collection. A build newer
than the imported collection's highest version reads `unmeasured`, so import a
new release when the vendor publishes firmware you care about.

1. **Download** the collection release from Ansible Galaxy —
   `fortinet.fortios` for FortiGate, `fortinet.fortianalyzer` for
   FortiAnalyzer. Either use the *Download tarball* link on the collection's
   Galaxy page, or on any machine with Ansible:

   ```
   ansible-galaxy collection download fortinet.fortios
   ansible-galaxy collection download fortinet.fortianalyzer
   ```

2. **Extract** it into a directory the service account can read. The
   directory you import must hold `MANIFEST.json` and `plugins/modules/`:

   ```
   mkdir -p /tmp/fortios
   tar -xzf fortinet-fortios-<version>.tar.gz -C /tmp/fortios
   chown -R satom: /tmp/fortios
   ```

   (A collection installed with `ansible-galaxy collection install -p DIR`
   works too: import `DIR/ansible_collections/fortinet/fortios`.)

3. **Import** it:

   ```
   cd /opt/satom
   sudo -u satom env FLASK_APP=wsgi:app venv/bin/flask apilib import-vendor /tmp/fortios
   ```

   The output names the product and `origin_ref`
   (`ansible:fortinet.fortios:<version>`). Importing the same release again
   creates nothing. A newer release is new evidence and, where both cover a
   build, the newer one speaks for it.

4. **Check** with `flask apilib status` and on the API versions page with the
   product selector.

Nothing is fetched from the internet by SATOM itself; the import reads a local
directory.

### 8.3 Backfill

`flask apilib backfill` reads what is already on disk under `data/`:
rediscovery snapshots (including deleted appliances), harvested field schemas,
and the frozen pre-build-axis matrices. Run it once after upgrading to 2.2.0;
after that, sweeps and harvests ingest as they happen. Running it again is
harmless: the result counts `confirmed` instead of `created`. `--product`
limits it to one product (repeatable); `--data-root` points it at another tree,
for instance a restored backup's `data/`.

The result lists `skipped` snapshots (a snapshot whose product cannot be
determined) and, per product, how many documents were stored unhealthy.

### 8.4 Harvesting: how the library keeps growing

| Trigger | What happens |
|---|---|
| **A rediscovery sweep** (FortiWeb, FortiADC) | ingests its own snapshot right after writing the files. A library failure is logged and recorded as `apilib_error` in the sweep's state; it never fails the sweep |
| **Firmware change** | when the firmware probe (API v1 `POST /appliances/<id>/firmware-check`, or the discovery run on the API versions page) sees an appliance's normalized version change — or records its first version and the library has no evidence for that build — it queues one background job of type `apilib_harvest` |
| **API Explorer → Harvest this appliance now** | queues the same job for the selected appliance (needs `appliances.apply`) |
| **Scheduled action `apilib_harvest`** | harvests, one appliance at a time, every FortiWeb, FortiADC and FortiAuthenticator whose running build has no healthy evidence from its live source. Admin action, dry-run capable. **Declared but not scheduled by default**: create a schedule for it (daily is plenty) under **Scheduled Actions** (FortiWeb ADOM → Administrator) |
| `flask apilib harvest-fac` | an immediate FortiAuthenticator harvest from the shell |

What a harvest does per product: FortiWeb and FortiADC run a rediscovery
sweep; FortiAuthenticator reads its Tastypie schema (GET only) and ingests it.
FortiAnalyzer and FortiGate have no live **REST** harvester and every entry
point says so by name (`no live harvester for fortianalyzer`).

The **CLI channel** has its own harvest — the schema harvest (§13.4), the
scheduled action `schema_harvest` and the per-product adapters (§13.10) — and
its own watch: an appliance on a build with no harvested schema raises one
notification and is listed on the **Schema builds** page (§13.11).

A build "needs a harvest" when the exact build has no healthy build-scoped
evidence from the product's **live** source (`sweep` for FortiWeb and
FortiADC, `schema` for FortiAuthenticator). Vendor or legacy data for a build
does not count, and neither does evidence for its line.

**Queue rules.** At most one harvest is pending or running per appliance; a
second request answers with the first job's id. Appliances in maintenance are
not queued. A harvest job appears in the Job Manager, cannot be stopped midway
(a sweep has no safe checkpoint), and is green only when it stored **healthy**
evidence.

**The switch.** Background dispatch is controlled by the configuration key
`APILIB_HARVEST_DISPATCH`: on by default, off when `TESTING` is set, so a test
cannot start a sweep against a real network. Set it to false to stop automatic
harvests; the scheduled action and the CLI still work.

**Which database.** A harvest, a sweep and the explorer all write to the
database of the application that is running them, never to one captured
earlier in the process.

---

## 9. Endpoint baselines — the registry's seed

> **Since:** SATOM 2.4.0 (unreleased). Replaced the four `endpoints*.yaml`
> files at the repository root.

The **endpoint registry** (`registry_endpoints`, the map from a logical name
such as `server_policy` to the URN SATOM calls) is a different thing from the
library: the library records *what each build serves*, the registry is *what
SATOM calls*. Until 2.4 the registry was seeded from four hand-written YAML
files that never said which firmware they described, and whose insert-only
seed could add a name but never correct one. Such a seed goes stale by
construction: three years on, it still describes whatever firmware was current
when someone last edited it.

A **baseline** is the registry's seed, pinned to one firmware build and
produced from what the library measured on that build.

### 9.1 The contract

- **Pinned to a build.** "The FortiWeb catalog as of 7.6.8", not "the FortiWeb
  catalog". The API protocol (`v2.0`, `v1`, `jsonrpc`) is recorded separately:
  it is not the firmware and it is not what changes between builds.
- **Promoted from measurements, never written by hand.** Promotion takes the
  library's measured sources for that build (`sweep`, `schema`, `manual`,
  `legacy_matrix`; never `vendor_doc`). A build nobody measured cannot be
  promoted.
- **Sealed.** The content (product, build, protocol and every entry) is hashed
  with SHA-256. Timestamps and the note are outside the hash, so promoting the
  same content twice is one row.
- **Shipped as a generated artifact.** Each product's active baseline lives in
  `app/registry/baselines/<product>.json`, one entry per line so a promotion
  reads as a reviewable `git diff`. The application **refuses** an artifact
  whose seal does not match its content: a hand edit is rejected at boot, not
  half-applied.
- **Applied at boot.** On every install path (native, Docker, a fresh
  database, an upgrade), the application inserts the shipped baseline if the
  database lacks it and reconciles the registry to the active one, **once per
  promotion**. The data does not travel as an alembic migration: a fresh
  installation builds its schema with `db.create_all()` and never runs
  `flask db upgrade`, so a data migration would never reach it. Migration
  `apibl01` creates the two tables only.
- **Append-only.** Promoting adds a baseline; it never rewrites an old one. The
  active baseline of a product is the one promoted last. Re-promoting old
  content re-activates the existing row instead of duplicating it.
- **Operators still win.** A registry row the baseline wrote carries
  `updated_by = baseline:<product>@<build>` (rows from before 2.4 carry the
  legacy `seed` and are adopted). A row an operator edited, disabled or created
  carries the operator's name and is **never** touched by a baseline.

### 9.2 Entry provenance

Every entry says why it is in the baseline.

| provenance | meaning |
|---|---|
| `measured` | the baseline build served it; the URN comes from that evidence |
| `carried` | the baseline build has no evidence about it (no sweep reaches it); kept from the previous baseline, with `measured_on` naming the build that did prove it |
| `legacy` | adopted from the retired YAML seed and never measured on any build |
| `contradicted` | adopted from the YAML, but the baseline build measured it **absent**. Kept so that adoption changed nothing; the next promotion that measures it drops it, and `check` lists it |

### 9.3 What a promotion does

`flask apilib baseline promote --product P --build X` computes the new baseline
and prints the diff against the active one. It changes nothing without
`--apply`:

- a name build X **served** comes in (`+`), with the URN the evidence carries.
  When the vendor moved a resource, this is how the registry follows (`~`);
- a name build X measured **absent** goes out (`-`);
- a name build X has **no evidence about** is carried, and says so.

With `--apply` the baseline is stored and the registry is reconciled: missing
rows are added, baseline-owned rows are corrected, re-tagged or soft-disabled,
and operator rows are counted and left alone. `--export` also rewrites the
product's artifact. That is release work: commit the artifact, and every
installation receives the baseline on its next boot.

### 9.4 Resolving a name on a build

`api_baseline.resolve_at(product, name, build)` (CLI:
`flask apilib baseline resolve`) answers with an authority, in this order:

| status | when |
|---|---|
| `override` / `disabled` | an operator's registry row exists for the name |
| `measured` / `absent` | the library measured that exact build |
| `baseline` | the build is not measured; the active baseline answers, labelled as an assumption |
| `absent` | a baseline exists and does not list the name |
| `unmeasured` | there is no baseline at all |

It never returns a guessed URN.

### 9.5 Checking for drift

`flask apilib baseline check` compares, per product, the registry with the
active baseline (missing rows, baseline-owned rows with the wrong URN, rows the
baseline dropped that are still enabled, whether the baseline was applied) and
the baseline with the evidence of **every build the fleet runs today** (served,
measured absent, URN mismatches, names only the baseline vouches for).
Operator rows are listed as overrides, not as drift. It exits with status 1
when anything drifted, so it can gate a release.

### 9.6 Commands

| Command | What it does |
|---|---|
| `flask apilib baseline status` | the active baseline of each registry product: build, protocol, method, entries per provenance, applied or not, seal |
| `flask apilib baseline promote --product P --build X [--apply] [--export] [--note TEXT]` | §9.3. Dry run without `--apply` |
| `flask apilib baseline check [--product P]` | §9.5. Exit status 1 on drift |
| `flask apilib baseline resolve --product P [--build X] NAME` | §9.4 |
| `flask apilib baseline apply [--product P]` | reconcile the registry to the active baseline again |
| `flask apilib baseline export [--product P]` | rewrite the artifact(s) from the active baseline |
| `flask apilib baseline adopt --product P --build X FILE` | one-time import of a legacy flat `name: urn` map as a product's **first** baseline; refused once one exists |

### 9.7 The first baselines

The four shipped baselines were adopted from the retired YAML seeds, with each
entry labelled against the library's evidence. Adoption changed nothing the
registry serves: on the reference installation the 877 registry rows were
identical (name, URN, enabled) before and after, and `check` reported no URN
mismatch on any build the fleet runs.

| product | pinned build | protocol | entries | provenance |
|---|---|---|---|---|
| FortiWeb | 7.6.8 | `v2.0` | 486 | 287 measured, 191 legacy, 8 carried from 8.0.5 (promoted 2026-09-29; adopted with 517) |
| FortiADC | 8.0.3 | `v1` | 255 | 217 measured, 38 legacy |
| FortiAnalyzer | 7.6.7 | `jsonrpc` | 64 | 64 legacy |
| FortiAuthenticator | 8.0.3 | `v1` | 40 | 40 measured |

**The 39 contradicted FortiWeb entries** were names the 7.6.8 sweep measured as
not served, among them `web_protection_profile`, `load_balance` and
`server_pool_rule`. Adoption kept them, because dropping names from what clones,
sweeps and the explorer resolve is a change of behaviour, not a change of
storage. They left with the promotion of 2026-09-29
(`flask apilib baseline promote --product fortiweb --build 7.6.8 --apply
--export`): read live, each of their URNs answered FortiWeb's `-20001` *"The
REST API has invalid URL"*, while the object's real path (for example
`waf/web-protection-profile.inline-protection`) is a valid URL. 31 of them are
absent on 8.0.5 too, and those 31 left. The other 8 (`waf_mcp_security_policy`,
`waf_file_list`, `system_captcha_puzzle` and five more) are served on 8.0.5, so
they stay, labelled `carried` with `measured_on: 8.0.5`. A promotion never drops
a name another measured build serves, because a fresh install would then ship
no row for it: its sweep would never probe it, and a box on that build would
never see it. Per-build resolution (§9.8) keeps them off a 7.6.8 box.

**What the YAML comments recorded**, preserved here because the files are gone:

- *FortiAnalyzer.* Every entry was probed live (`get`, code 0) against a
  FortiAnalyzer 7.6.7 build 3737 on 2026-07-12. URNs are JSON-RPC URLs: two
  dialects, picked by the client from the URL family (`/cli /dvmdb /sys /task`
  use the legacy envelope; `/logview /eventmgmt /incidentmgmt /report
  /fortiview /fazsys` use JSON-RPC 2.0 with `apiver 3`). ADOM-scoped URIs keep
  `adom/root`, which works with Admin Domains disabled. The alert-log detail
  needs `?alertid=<id>` (-32002 without it), and a report `get` needs
  `state=generated` and a time range, which `faz_objform` supplies.
- *FortiADC.* Derived on 2026-07-07 from the FortiADC 8.0.3 CLI Reference with
  the rule `config a-b c-d` → `/api/a_b_c_d`. Child tables follow
  `/api/<parent>_child_<table>?pkey=<parent mkey>`. `config user tacacs+` was
  left out (the `+` does not map). 217 of the 255 were later measured on 8.0 and
  8.0.3 appliances; the other 38 are `legacy`.
- *FortiAuthenticator.* Every entry was probed live against a
  FortiAuthenticator 8.0.3 build 0099 on 2026-08-05. The census of the 18
  resources deliberately left out is in
  [fortiauthenticator.md](fortiauthenticator.md) §2.

### 9.8 Per-build resolution in the services

A baseline pinned at one build disables the names that build measured absent.
The registry still holds one URN per name for the whole fleet, so without more
work a box on a newer build would lose names it does serve: promoting the
FortiWeb baseline at 7.6.8 disables 39 names, and 8 of them
(`system_captcha_puzzle`, `system_certificate_eab_credentials`,
`system_certificate_ocsp_signing_certs_group`, `waf_custom_tracking_policy`,
`waf_file_list`, `waf_mcp_security_exception`, `waf_mcp_security_policy`,
`waf_mcp_security_rule`) are served on 8.0.5. The services therefore resolve a
name **for the build of the box they are talking to**
(`app/registry/loader.py`).

`loader.resolve_for(product, name, version)` returns a URN or raises:

1. **An operator's row wins.** Enabled: its URN. Disabled:
   `loader.EndpointNotServed`.
2. **The evidence of that exact build.** When `version` is an X.Y.Z build and
   the library measured the name on it (measured sources only, never
   `vendor_doc`): served with a URN → that URN; measured absent →
   `EndpointNotServed`.
3. **The enabled registry** otherwise.
4. **`KeyError`** with the same message the product's registry resolver
   has always raised.

`EndpointNotServed` is a `KeyError`, so every caller that turned an unknown
name into a named error keeps doing so. It carries `product`, `name`,
`version` and `authority`, and reads *"`<name>` is not served by `<product>`
`<version>` (`<authority>`)"*. An empty or unparseable version, or a line
without a patch (`8.0`), gives exactly the registry's answer. If the evidence
cannot be read (a DB error), resolution falls through to the registry and logs
a warning: an unreadable library never breaks a caller.

`loader.registry_for(product, version)` applies the same rules to the whole
map: the enabled registry, minus names measured absent on the build (unless an
operator's enabled row), with the measured URN in place of the registry's
(unless an operator's row), **plus** names whose baseline-owned row is disabled
and that the build measured served. It only adds names that have a registry
row: a sweep driven by this map never calls an endpoint nobody catalogued.
Maps are cached per (product, build) with the registry's 60-second TTL and
dropped by every registry write (`loader.invalidate_*`) and by a baseline
apply (`api_baseline._invalidate`).

**The fleet view.** `loader.get_all_endpoints()` feeds consumers that serve
the whole fleet at once. It returns the enabled registry plus every name whose
baseline-owned row is disabled and that is measured served on at least one
build a live FortiWeb runs today (not in maintenance, host not `*.invalid`).
When the last 8.0.x box leaves the fleet, the 8 names leave the menus.
`loader.load_registry()` and `loader.resolve()` stay the pure registry, and
`loader.get_registry_endpoints()` is the pure registry as display dicts.
`objform.known_collections()` (the generic editor's allow-list) is memoised
for the life of the process, so it picks up a fleet change on the next restart.

| Consumer | Reads |
|---|---|
| Nav menus (`server_objects`, `config_sections`, `wp_menu`), `config_catalog`, `rediscovery.sweep_plan`, `objform` allow-lists, provisioning (service and page), `read_layer`, the API Explorer tree and its per-build marks, the custom-REST picker of scheduled actions | fleet view (`get_all_endpoints`) |
| Registry search page, Structure page and `structure.registry_urn_index` / `load_catalog` (coverage accounting) | pure registry (`get_registry_endpoints`) |

**Call sites that resolve per build:**

- the FortiADC, FortiAnalyzer and FortiAuthenticator clients (`_resolve`), and
  the new `FortiWebClient.resolve`. Each client keeps `appliance.fw_version`;
  a name the build does not serve comes back from `list_with_error` as its
  message, not a 500;
- `services/backup.py` (local backup list, download, create, restore);
- `services/exception_inject.py` (`plan_injection(..., version=)`,
  `apply_injection` from `ops.appliance`, `candidate_targets` from the client);
  the API v1 WAF-exception plan passes the appliance's build;
- `services/clone.py`: `ClonePlanner` indexes the **target** box's map;
  `ClientReader.get_object` uses its own client's build;
- `services/write_through.py`: `diff_object`, `local_update` and
  `local_delete` map a collection with the cached appliance's build;
- `services/device_sync.py`: the FortiAnalyzer and FortiAuthenticator config
  sweeps use `registry_for` of the box;
- the `execute` consoles of `views/adc_api.py`, `faz_api.py` and `fac_api.py`;
- the custom-REST scheduled action (`scheduled_actions.resolve_endpoint`).

**Still registry-only** (no appliance or build reachable without changing many
signatures): the FortiWeb tab pages (`server_objects`, `section_config`,
`web_protection`) reading menu URNs; the FortiWeb device sweep
(`device_sync.snapshot_from_device`, fleet `sweep_plan`) and the FortiADC
discovery plan (`adc_ops.discovery_plan`); the FortiAnalyzer and
FortiAuthenticator tab pages (`views/faz.py`, `views/fac.py`); the catalog
pages of the three explorers; `policy_ops._apiver_targets` and
`deep_capture._lg`; `exception_deploy.push_plan`; `lua_studio`; the
fleet-level analyses (`analysis_adc`, `analysis_fac`) and the FortiAuthenticator
harvest (`apilib_fac`, which measures against the registry on purpose);
`cli_coverage`, `discovery_run` and `device_identity`, which account for the
registry itself.

---

## 10. Limits that do not go away

- **FortiWeb has no REST schema endpoint.** An empty collection reveals no
  fields over REST. Such endpoints are `blind`, never "no fields". The CLI
  `tree` gives the build's schema anyway (§13.1), so a field of an empty table
  reads `unknown` on the REST side, not absent. Configure one row on a box
  running that build and sweep it again to measure REST.
- **A configuration dump is not a schema.** `show full-configuration` prints
  only the fields that apply under each row's current settings (§13.8).
- **REST hides what it drops.** A gated field sent alone answers 200 and is
  not applied (§13.9); only a readback proves a write.
- **Vendor data is a claim by the vendor's tooling**, not a measurement. It is
  labelled `vendor_doc` everywhere, never outranks a sweep of a real box, and
  its absence of an endpoint warns instead of blocking.
- **Vendor data stops at the collection's release.** A build newer than the
  collection's highest version is `unmeasured` until a newer collection is
  imported.
- **FortiWeb and FortiADC have no vendor evidence**, because their collections
  carry no version data. A build no appliance has run stays `unmeasured`.
- **FortiADC has no live evidence source today**: no FortiADC is left in the
  lab fleet. Its historical builds (including 8.0.3) stay in the library.
- **The field map is authored, not discovered.** The library proposes rename
  candidates by CLI attribute id (§13.7) but does not apply them: a rename is a
  removal plus an addition until an operator records it.
- **FortiADC and FortiAnalyzer adapters are unverified** (no lab device). A harvest
  through them names the gap (`unverified`), and so does the Schema builds page
  that lists the adapters.

---

## 11. API packs — the library for nodes that cannot measure it

An installation learns what a build serves by sweeping a box that runs it,
from vendor collections downloaded from Galaxy, and from docs.fortinet.com
(a direct download — SATOM has no other documentation transport). An offline
node has none of those, and a node with no FortiADC will never measure
FortiADC. An **API pack** carries what one SATOM knows to another as one signed
tarball (`app/services/api_pack.py`). Packs are written by SATOM's own export
and by the separate [Knowledge Harvester](knowledge-harvester.md) in the same
format (knowledge packs, `kb-*`, §13.12); the release notes in a
pack may cover any product with a release-notes map (FortiWeb, FortiADC,
FortiAuthenticator, FortiAnalyzer, FortiGate — see
[release_notes.md](release_notes.md)), and each item imports only its own
product's rows.

### 11.1 What a pack carries

| Section | Content | Source on the exporting node |
|---|---|---|
| `library` | One evidence document per healthy evidence row: sweeps, schemas, `legacy_matrix`, `vendor_doc`, and the CLI channel `cli_tree` / `cli_full` with their `attrs` | `api_lib_evidence` |
| `docs` | Release notes **with the full vendor text** (issues, workarounds, prose sections); harvested field schemas per line; the FortiWeb field overlay | `reports/_release_notes.json`, `data/field_schemas/`, `data/fortiweb_field_schema.json` |
| `cli-coverage` | Per product and firmware version: the CLI-only blocks and near matches, with their `set` names and counts | the newest usable CLI dump per version in the device vault (`cli_coverage`) |

Layout:

```
satom-apipack-<version>/
    manifest.json      signed: items + sha256 of every file
    manifest.sig       Ed25519 over manifest.json's exact bytes
    library/<product>/<source>-<scope>-<sha12>.json.gz
    docs/release-notes/<product>.json.gz
    docs/field-schemas/<product>/<line>.json.gz
    docs/fortiweb-field-overlay.json.gz
    cli-coverage/<product>/<version>.json.gz
```

### 11.2 What a pack never carries

- **No configuration.** A sweep's evidence row stores the raw snapshot, and
  the snapshot holds the rows the box returned. Export re-derives the
  normalised document (field **names and types** only) and keeps it only if
  it reproduces the row's stored `sha256`. A row that does not reproduce is
  listed under `skipped` and is not exported. The CLI digest carries block
  paths, `set` names and counts, never an `edit` name, a value or a line of
  the dump.
- **No estate identity.** Device names become `witness-<hmac>`, keyed by a
  per-installation secret (`data/apipacks/witness.salt`), so the same box gets
  the same pseudonym in every pack and re-importing a newer pack confirms
  evidence instead of duplicating it. Serials and appliance ids are dropped.
  Witness slots (`device.name`, `witnesses[]`, `appliance`, `witness`, and the
  name inside a harvest `source` such as `live:fw1@8.0`) are replaced **by
  position**, whatever the name. A deny-list alone missed a deleted box named
  only inside a schema document.
- **The export is refused whole** if any witness slot holds something other
  than a pseudonym, or any payload holds a known device name, serial,
  appliance address or an IPv4 on an appliance's /16. The release-notes text
  is exempt from the address check only, because it is vendor prose.
- Evidence that came from a pack is never re-exported.

### 11.3 Import rules

Importing only ever **adds**:

| Item | Imported when | Skipped as |
|---|---|---|
| Library document | its hash is not stored yet | `present` (same hash), or `local`: this node holds its own healthy evidence of the same source for that build or line |
| Release notes | for each (product, version) the node does not hold | `present`. A version scanned locally is never replaced |
| Field schemas | per object file that does not exist locally | `present` |
| Field overlay | when the node has none | `present` |
| CLI digest | always (pack-owned, `data/apipacks/cli-coverage/`) | `present` when byte-identical |

Imported evidence carries `origin_ref = apipack:<version>:<source>` and
pseudonymous witnesses, so it is distinguishable everywhere a witness is
listed. **Known limit:** a pack sweep imported *before* the node sweeps the
same build itself is merged with the later local sweep under the library's
normal rule (an `ok` from any healthy witness wins on that build).

A pack is verified with the update-package verifier
(`deploy/update_package.py`) against the same root-owned trust store
(`/etc/satom/update-keys`): signature first, then every file's hash, then
schema (`satom.api-pack/1`). An unsigned pack, a pack signed by an untrusted
key, and an altered pack are all refused before anything is read. Each import
that changed something is logged in `data/apipacks/imports/`.

### 11.4 Commands

```bash
# export (as the service account); unsigned unless --sign-key is given
flask apilib pack export --version 2.6.0 --out /tmp/packs \
      [--product fortiweb] [--section library|docs|cli-coverage] \
      [--sign-key satom-release.key --passphrase-file pass]

# sign later with the update-package tool
python3 deploy/sign_update_package.py sign /tmp/packs/satom-apipack-2.6.0.tar.gz --key …

# what importing would do, per item: new / present / local
flask apilib pack inspect satom-apipack-2.6.0.tar.gz

# import everything new, or a selection
flask apilib pack import satom-apipack-2.6.0.tar.gz [--product fortiadc] \
      [--section docs] [--item library/fortiadc/sweep-8.0.3-…] [--dry-run]
```

`inspect` and `import` take `--trust-dir` for a non-default trust store.

The operator console wraps the import for root, so nobody has to assemble the
service account's environment by hand:

```bash
satom show apipack                                   # packs on this node + import log
sudo satom execute apipack import shipped            # dry run of every pending shipped pack
sudo satom execute apipack import shipped --yes      # import them (release pack, then knowledge pack)
sudo satom execute apipack import ./satom-apipack-2.6.0.tar.gz --yes \
     [--product fortiweb,fortiadc] [--section docs]
```

It runs `flask apilib pack import` **as the service account** (`runuser -m`):
run as root, the release notes and field schemas it writes would become files
the web worker can no longer update. A pack outside the application tree (an
operator's home is `0700`) is first copied to `data/apipack-uploads/`. It
refuses on a standby. Without `--yes` it only reports what would happen.

### 11.5 How a node gets a pack

The release pipeline builds one pack per release and commits it to
**`api-packs/`** in the repository, before the tag (§11.6). Because the pack
lives in the tree, it travels the way the code does, and no node downloads
anything to get it:

| Path | How the pack arrives | How it is imported |
|---|---|---|
| Online install | `git clone` of the public repository | the installer, after the health check |
| Offline install | the bundle's `app.tar.gz` | the installer, after the health check |
| Update (git or offline package) | the new tree | **the update runner, on the primary** (from 2.7.0); otherwise **Settings → Software Update → API library packs** |
| Standalone | `satom-apipack-<version>.tar.gz` (+ `.sha256`) from the GitHub release, the download catalog or `/downloads` | upload it on that page, or `satom execute apipack import <file> --yes` |

**Installer.** On a standalone node or a cluster primary, once `/healthz`
answers, the installer runs `satom execute apipack import shipped --yes`. It is
never fatal: the installation is complete at that point, and a pack that does
not import is a warning with the command to retry. A secondary is skipped: its
database is read-only, and it gets the library by replication and the files
by the data sync. Two environment variables control it, and they are
variables rather than prompts on purpose — a new prompt would shift every
answer file written for an earlier release by one line:

| Variable | Values | Default |
|---|---|---|
| `SATOM_API_PACK` | `all` · `none` · a path to a pack | `all` (the release's own pack) |
| `SATOM_API_PACK_PRODUCTS` | comma list, e.g. `fortiweb,fortiadc` | every product |

**Update.** From 2.7.0, after an update has passed its health check on a
primary or standalone node, the runner imports the pending shipped packs itself
(`satom execute apipack import shipped --yes`, step *import shipped API pack*
in the update log). Like the installer's step it never fails the update: a
pack that does not import is a red step with the command to retry, and the
node stays on the new code. A standby is skipped. `SATOM_API_PACK_AUTO=0` in
the runner's environment turns it off. The first update INTO 2.7.0 is applied
by the previous runner, which does not have this step: import once by hand
after it. While a shipped pack is pending on a node, Software Update says so
above the pack list, with a link that opens each one.

`api-packs/` keeps **every** release's pack (about 400 KB each), so a node can
import an older pack too.

**Knowledge packs (2026-10-07).** Next to the release packs, `api-packs/` may
carry ONE knowledge pack, `satom-apipack-kb-YYYYMMDD[.N].tar.gz`, built by the
separate tool **satom-harvester** (lab `tree` / `show full-configuration`
dumps, sweeps, vendor release notes) and re-signed with the release key by the
release pipeline (step `kb_pack`). It has to be its own file: a release pack is
exported from the release host's library and never carries what that host
imported from a pack (§11.3 rule 3). The two series are independent and both
cumulative, so:

| | release pack | knowledge pack |
|---|---|---|
| name | `satom-apipack-<x.y.z>` | `satom-apipack-kb-YYYYMMDD[.N]` (`.10` sorts after `.2`) |
| kept in `api-packs/` | every release | only the newest |
| imported by *shipped* | the newest, first | the newest, second |

*shipped* imports the newest pack of each series **that this node has not
fully imported yet** (a logged full pass with no failed item), release pack
first. A run where an item failed, or where only ticked items were taken,
leaves the pack pending, so the next update retries it. Software Update lists
knowledge packs with the label *knowledge pack (satom-harvester)*, marks older
packs of a series *superseded*, and its notice names every pending pack. The
import rules are the same for both series: signature against the trust store,
and what the node measured itself always wins.

**Software Update.** The *API library packs* card lists the release's packs
(*this release*) and any uploaded pack (the newest five are kept). Selecting
one verifies it and shows every item with its state — `new`, `present`, or
`local` (this node measured it itself) — filterable by product and by section.
Only `new` items can be ticked; *Import selected* runs as a background job with
per-item progress, and the page re-reads the states when it ends. A failed item
turns the job red but keeps what was imported and says which items failed. The
standby page shows the card read-only and the import route refuses there. A
pack signed by a key the node does not trust is refused with the
`satom execute trust add-key` command that fixes it.

### 11.6 Built by the release pipeline

The pipeline step `api_pack` (after `docs_gate`, before the push and the tag)
checks that `api-packs/` in the release commit holds exactly this release's
pack and its `.sha256`, that the checksum matches, that the signature verifies
against the public key the product ships (`deploy/update-keys/`), and that the
manifest names this version. When it does not, the repair `build_api_pack`
exports the pack on the primary from its live library, signs it on the release
host with the release key (the same key as the update packages; the primary
never sees the private half), and commits exactly `api-packs/` — the new pack
in, every earlier release's pack kept — after refusing a dirty work tree. The
publish steps attach the pack, taken from the tag, to the GitHub release and
the download catalog.

The pipeline also reads every file inside the pack with the **public mirror's
own redaction and secret rules**. The mirror cannot do it: the pack is a gzip
of gzips, which the history rewrite skips as binary. One exception, for the
vendor release notes only: a rule match that is a bare IPv4 address is
Fortinet's example text, not ours. Any other match stops the release, and it
is never auto-repaired — rebuilding would export the same text again.

### 11.7 CLI coverage from a pack

The CLI-coverage card (API explorer and the ADC API page) diffs a stored CLI
dump. When the node has **no dump** for the firmware asked about, it falls
back to an imported digest for **that exact version** (or line, when the page
is scoped by line) and says so: the evidence line names the pack's witness,
version and capture date. The block text is not offered — the node never had
the dump. Other readers of the coverage report (Structure, discovery) ignore
the digests, because they act on a stored dump.

### 11.8 Limits

- A container install has no Software Update page (§22 of the user guide) and
  its installer path is the stack, not `install-satom.sh`: importing a pack
  there is not covered yet. The image does carry `api-packs/`.
- `short` and `partial` releases publish code only: the pack rides in the
  repository and the bundles, but is attached as a release asset only by a
  `full` release.

---

## 12. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| A build reads **`unmeasured`** | Nothing measured it. For FortiWeb, FortiADC or FortiAuthenticator: *Harvest this appliance now* in the API Explorer, or run the `apilib_harvest` scheduled action. For FortiGate or FortiAnalyzer: the build is newer than the imported collection — import a newer one (§8.2) |
| A build reads **`vendor_only`** | Only the vendor's data covers it. Correct for FortiGate and FortiAnalyzer. Treat its answers as claims |
| The explorer shows **`firmware unknown`** | The appliance's firmware was never read. Run a firmware check first (API v1 `firmware-check`, or the discovery run); the probe then queues a harvest if the build needs one |
| *Harvest not queued* — `no live harvester for …` | FortiAnalyzer and FortiGate cannot be harvested live; use §8.2 |
| *Harvest not queued* — `… is in maintenance` | Take the appliance out of maintenance, or wait for the scheduled action |
| *Harvest not queued* — `background harvest is disabled (APILIB_HARVEST_DISPATCH)` | The switch is off on this installation. Use the scheduled action or `flask apilib harvest-fac` |
| *a harvest of … is already pending* | One is queued or running; watch it in the Job Manager |
| Harvest job red: `stored as unhealthy` | More than 25 % of the reads errored (licence, credentials, reachability). The failed pass is kept as evidence; fix the device and harvest again |
| Harvest job red: `a rediscovery of … is already running` | A sweep started in the last 15 minutes is still marked running. Wait for it; it ingests its own snapshot |
| Sweep finished, but `the library did not take it` | The sweep's files are on disk; the library write failed and the reason is in the message and the application log. Fix the cause and run `flask apilib backfill` — it picks the snapshot up |
| `import-vendor`: `not an Ansible collection (no MANIFEST.json)` | You pointed at the wrong directory. Import the directory that holds `MANIFEST.json` |
| `import-vendor`: `carries no version data; nothing imported` | A `fortinet.fortiweb` or `fortinet.fortiadc` collection. Expected (§3) |
| The endpoint count dropped after a collection upgrade | Read `skipped_by_reason` in the new evidence's summary: monitor, fact, generic and non-configuration modules are skipped by name |
| A field shows as **removed** plus a new one **added** after an upgrade | Probably a rename. Record it at `/web/registry/field-map` |
| A retired appliance still appears as a witness | Expected: evidence outlives the appliance and is marked `retired` |
| `ingest-file`: `unknown evidence source` | The document's `source` is not one of `sweep`, `schema`, `vendor_doc`, `manual`, `legacy_matrix`, `cli_tree`, `cli_full` |
| `cli_full field … carries default: cli_full holds names, never values` | A `cli_full` document carried a value. Only lab evidence (`summary.lab`) may carry a `default` (§13.2) |
| Schema harvest: `stored as unhealthy: the tree output was cut short` | The SSH read ended before the prompt came back. Harvest again; a box under load can take longer than the 180 s budget |
| A CLI-coverage row reads **Not in catalog** with REST *not measured* | No REST evidence for that path on the dump's build. Run a schema harvest of a box on that build (§13.4); the row then becomes a catalog gap or *CLI only* |
| `baseline promote`: `… has no measured evidence` | Nobody swept or harvested an appliance on that build. Promote a build that `flask apilib status` lists with a measured source, or sweep a box on the build first |
| `endpoint baseline of … not applied` in the log, and the registry is empty | The shipped artifact was refused. The message names the file and the reason (`seal mismatch` means it was edited by hand: restore it from the release) |
| An endpoint an operator fixed went back after an upgrade | It did not, unless the row still carries `seed` or `baseline:…` in `updated_by`: then it was the baseline's row, not the operator's. Edit it from the Registry page; the edit makes it an operator row |
| `baseline check` exits 1 | Read the report: `wrong_urn` / `missing` / `stale_enabled` are registry rows out of step with the baseline (`flask apilib baseline apply` fixes them); `urn_mismatch` on a fleet build means the vendor moved a resource: promote that build |
| `pack import`: `manifest.sig is missing — the package is unsigned` | Sign it (§11.4) or get the signed pack from the release. Unsigned packs are never imported |
| `pack import`: `no key in the trust store signed this package` | The signing key is not trusted here: `satom execute trust add-key <key>.pub` (same store as update packages) |
| `pack export`: `identifying data survived the scrub` | The message names the file and the value. A device name used as an API key or field name is the usual cause; nothing was written |
| A pack item stays `local` and is never imported | Expected: this node measured that build itself (§11.3) |
| Bell: *New build X on Y: schema not harvested* | An appliance runs a build with no CLI schema in the library. Open **Schema builds** and press **Harvest**, or import a knowledge pack that covers the build (§13.11) |
| A build reads `unknown` for hundreds of fields after a harvest | Those fields sit in empty tables, or under a parent table with no row: REST had nothing to read. Expected; it is not "absent". A knowledge pack with lab rows narrows it |
| `rest_only` counts that look like bookkeeping (`id`, `_id`, `seq`) | They are channel `meta` since 2.13 (§13.3). On an older pack, re-import; on this node, harvest the CLI schema so the build has a `tree` |
| Schema builds: *unverified adapter* | The product's adapter was never checked against a device (FortiADC, FortiAnalyzer). Its evidence is labelled; treat it as a documented convention (§13.10) |
| FortiAuthenticator harvest reads REST but no CLI | SATOM stores the REST API key, not a CLI login. Give the CLI password in the Schema builds harvest form (used once, never stored), or `flask apilib adapter-harvest --ssh-secret-env VAR` |
| Migration report: *cannot assess* | No usable `show full-configuration` dump in the vault, an unknown source build, or a target with no CLI schema. The reason is on the report ([Migration report](migration-report.md) §2.1) |

---

## 13. CLI channel and hidden fields

> **Since:** SATOM 2.13.0 (unreleased).

The same firmware build can serve an object over REST and over the CLI, over
one only, or with fields that only `show full-configuration` prints. The
library records the CLI channel beside the REST one, per exact build, so a
page can say "you can do this, but on build X this field does not exist", or
"this field exists only on the CLI".

What one build knows is a set of **sources**, each with its own evidence row:

| Source | Channel | What it says about a build |
|---|---|---|
| `sweep` | REST | which paths answered and which field names and JSON types their rows carry |
| `schema` | REST | the schema the device serves (FortiAuthenticator Tastypie, FortiGate `?action=schema`, FortiAnalyzer syntax) |
| `vendor_doc` | REST (claim) | the vendor's Ansible collection or CLI reference — a claim, never a measurement |
| `cli_tree` | CLI | the whole CLI schema: objects, fields, types, options, ranges, CLI attribute ids |
| `cli_full` | CLI | the field names `show full-configuration` prints (hidden fields included); never values |

The rest of this section is the model end to end: the two CLI sources (§13.1)
and what they never carry (§13.2), how a field's channel and a build's
completeness are derived (§13.3), how a write is checked against a build
(§13.3.1), how the channel is harvested (§13.4–§13.6), the three lab findings
every reader must respect (§13.7–§13.9), the per-product adapters (§13.10), the
new-build watch (§13.11) and knowledge packs (§13.12).

### 13.1 The two CLI sources

| Source | Read with | What it holds |
|---|---|---|
| `cli_tree` | `tree` at the root of the CLI (SSH, no `config`) | the whole schema: every object (table `[name(id)]`, singleton `{name(id)}`), every field with its CLI id, `<type>` or enum options; the first field of a table is its key |
| `cli_full` | `show full-configuration` | the field NAMES each existing object prints, defaults included; a name the build's `tree` does not list is marked `attrs.hidden` |

Both are build-scoped (one box, one build) and keyed by the **REST path
without prefix** (`system/ntp/ntpserver`), which is exactly what
`api_library.urn_key(urn)` makes of the URN a sweep carries. That is the only
join between the channels; no registry name is involved. Per object,
`summary.objects[<path>]` = `{cli_path, kind, mkey, parent, cli_id}` and the
same goes into the endpoint fact's `attrs`. Field metadata goes into the field
fact's `attrs`: `cli_id`, `hidden`, `range` `[lo, hi]`, `help`, `cli_type`
(the raw `<type>`), `datasource`, `lab_default`.

FortiOS (FortiGate) prints `[table]`, `<singleton>`, `--*key` and annotations
`(lo,hi)` / `(size)` but no types and no options; its command trees
(`diagnose__tree__`, `execute__tree__`) are skipped. FortiAuthenticator has no
`tree` (`No such command.`); its `cli_tree` evidence is the `set ?` help of
each setup-CLI object (`summary.format = "fac_help"`). FortiAnalyzer's CLI
schema is its JSON-RPC syntax answer, stored as `schema`.

**CLI path to REST path** (`cli_schema.rest_path`):

| Product | Rule | Status |
|---|---|---|
| FortiWeb | `module/` + namespaces and object joined with `.`; an object nested in a table or singleton goes with `/` (`waf/web-protection-profile.inline-protection`, `system/ntp/ntpserver`) | verified (7.6.8, 8.0.6) |
| FortiGate | `config a b c` -> `a.b/c`; a nested table is a field of its top-level object (`children`) | matches every vendor URN; `tree` verified on 8.0.1 |
| FortiAuthenticator | no `tree`; the five setup-CLI objects (`router static`, `system dns\|global\|ha\|interface`) are none of the 58 Tastypie resources, so they never join a REST path | verified (8.0.3) |
| FortiAnalyzer | the JSON-RPC `/cli/global/...` URL is the CLI path | **unverified** (no FortiAnalyzer in the lab) |
| FortiADC | `config a-b c-d` -> `a_b_c_d`; a table in a table -> `<parent>_child_<table>` | **unverified** (no FortiADC in the lab) |

### 13.2 What never enters the library

- **No values.** `cli_full` holds names. Ingest refuses a `cli_full` field
  that carries anything but `attrs`, and the API-pack export refuses such a row
  again. The one exception is lab evidence (`summary.lab = true`): on a freshly
  created lab row every value IS the default, so `default` is recorded with
  `attrs.lab_default`. Identity and secret fields (hostname, keys, passwords,
  certificates, `ENC` values) are never recorded as defaults.
- **No dump.** The configuration dump stays in the device vault; the library
  row stores the names-only document. The `tree` text is kept with its
  `cli_tree` row (it is a schema), and a pack exports the document, never that
  text.
- **No REST claim.** The REST readers (`endpoints_at`, `fields_at`, the REST
  half of `compare`, `matrix_doc`, `builds().measured`, `resolve_appliance`,
  baselines) read only the REST sources. A build measured only through the CLI
  is still `unmeasured` for REST, with `cli_measured: true`.

### 13.3 Channels of a build

`api_library.channels_at(product, version, endpoint=None, exceptions=None)`
answers, for every field of every path the build is known to have:

| channel | means | UI label |
|---|---|---|
| `both` | REST revealed it and the CLI has it | both |
| `cli_only` | the CLI `tree` has it; REST revealed the object's fields (or measured the object absent) and it is not there | CLI only |
| `hidden` | like `cli_only`, but only `show full-configuration` prints it | hidden |
| `rest_only` | REST revealed it; the build's `tree` does not list it | REST only |
| `unknown` | one channel never answered for it on this build (no `tree`, a blind or unasked REST endpoint). Never a "no". A name only the vendor documentation gives REST, absent from a measured `tree`, is `unknown` with `doc_conflict: true` | unknown, or *CLI (REST not measured)* when the `tree` has it |
| `meta` | REST bookkeeping (`api_library.REST_META`), reported and never counted toward completeness | meta |

What the lab measured with it (CLI `tree`, REST probe of every object, a lab
row created in every empty table and read back by both channels):

| Build | both | CLI only | hidden | REST only | unknown |
|---|---|---|---|---|---|
| FortiWeb 7.6.8 | 3,451 | 0 | 0 | 0 | 653 (was 1,744 before the lab rows) |
| FortiWeb 8.0.6 | 3,372 | 0 | 0 | 0 | 885 (was 2,545) |
| FortiAuthenticator 8.0.3 | 0 | 29 | 0 | 316 | 0 |

On FortiWeb every field the `tree` lists is served by REST on every object REST
serves, and `show full-configuration` names nothing the `tree` does not: the
real differences between the channels are conditional printing (§13.8) and
REST ignoring gated fields (§13.9), not field sets. The FortiWeb `unknown` rows
are fields of tables that could not be given a lab row (parent row not
creatable, licence, certificate import, HSM, a feature the box's mode hides).
On FortiAuthenticator the channels are two different worlds: the CLI is a small
setup CLI, REST holds the product's configuration. On FortiGate 8.0.1 the CLI
`tree` does not print 9 tables REST serves (the `llm/*` tables,
`waf/signature`, `waf/main-class`, `waf/sub-class`, `firewall/access-proxy`,
`firewall/access-proxy6` and `system/vdom`).

REST bookkeeping is `meta`, not `rest_only`. FortiWeb (measured on 7.6.8,
where it had read as 276 `rest_only`): `id` on tables whose tree has no `id`,
`_id`, `seq`, `<NO.>`/`<No.>`, `sub_table_id`, `sub_table_action`, `q_*`,
`sz_*`, `can_*`, `*_val`. A name the build's CLI lists for the object is a real
field (tables whose key is `id`, `<No.>` sequence tables included); without a
measured `tree`, `id` is not called meta at all. Other products have no rule
until a REST row is measured next to a tree. Each field
carries `rest` / `cli` (`yes|no|unknown`) and the evidence ids. The summary is
**complete** when both channels were measured and nothing is `unknown`
outside a named exception — `licence` or `status-object`, from the evidence
(`summary.exceptions`) or the caller. Any other reason is listed as rejected.

`compare(product, base, target)` adds `channels`: `channel_moves` (a field
whose channel changed, e.g. `absent -> cli_only`), and the like-for-like `tree`
diff — objects and fields added or removed, enum options added and removed,
type, range and (lab) default changes, and **rename candidates**: a field (or
object) gone from one build and a new one with the same CLI id. Candidates are
reported, never applied; `api_lib_field_map` stays the only authority, and a
candidate it already maps says `mapped: true`. Object metadata (CLI id, key,
kind) is read from the evidence `summary.objects` when the facts carry none, so
object rename candidates (`endpoint_rename_candidates`) and `field_moves` (a CLI
id that left one object and reappears in another: an object renamed with its
fields, or a field that became a subtable) work on harvester packs too.
`field_history` reads both channels and labels each row `rest` or `cli`.

### 13.3.1 What reads the channels

Three features are built on `channels_at` and the CLI half of `compare()`; each
has its own page:

| Feature | Question | Page |
|---|---|---|
| `services/build_compat.py` | will this **payload** fit each target's exact build? Missing fields are skipped per device, CLI-only fields flagged, invalid values and absent objects block, an unmeasured build "cannot be guaranteed". Wired into template apply and approval deploy, baseline and system-profile apply, the carve-out push and the object editor; the **Build compatibility** page shows the field x build matrix | [Build compatibility](build-compatibility.md) |
| `services/migration_report.py` | will this **appliance's configuration** survive a move to build X? block / translate / warn / info and a verdict, from its newest `show full-configuration` dump; never a value in the report | [Migration report](migration-report.md) |
| `services/cli_writer.py` | which fields of a write must go **by CLI** on this build, and did they land? A gated CLI transaction with `abort` on error and a fresh-session readback | [CLI writer](cli-writer.md) |

`satom execute apilib compat <product> <A> <B>` and `satom execute apilib
channels <product> <build>` print the library's own answers from the console.

### 13.4 Harvesting the CLI channel

`services/schema_harvest.harvest(appliance)` reads one appliance's build:

1. SSH `tree` -> `cli_tree`. `tree` is allowed by its own whole-command gate
   (`ssh_ops.assert_schema_command`); the read-verb allowlist is unchanged. The
   read waits for the prompt (a 1-2 MB answer), paging off as for every
   console session. A dump that is cut short, holds fewer than 50 objects or
   no `system` object is stored unhealthy.
2. `show full-configuration` -> `cli_full`: the newest usable vault dump of
   the same box on the same build when it is younger than 24 h, otherwise a
   fresh SSH capture (not stored in the vault).
3. FortiWeb only: one REST GET per `tree` object the library's REST evidence
   does not cover (never asked, errored, blind), classified by shape (§13.5),
   ingested as sweep evidence keyed by the REST path with `origin_ref`
   `schema_harvest:…`. A nested object under a table is asked with the first
   row's key (`?mkey=`), which is never recorded; one with an empty parent, or
   two tables deep, is skipped and counted. This partial evidence does not
   count as the build's sweep (`apilib_harvest.needs_harvest`, pack "local
   wins"), and a baseline promotion ignores path-named entries.

Entry points: **API Explorer -> Harvest CLI schema** (permission
`appliances.apply`, a device job), the scheduled action `schema_harvest`
(admin, per target), `flask apilib schema-harvest <id|name> [--lab]
[--no-probe]`, and `sudo satom execute apilib harvest <id|name> [--no-probe]`.
`--lab` is for lab boxes only.

### 13.5 FortiWeb answers an unserved nested path with its parent

Measured on 7.6.8: `system/interface/<anything>` answers 200 with the
interfaces; `waf/web-protection-profile.inline-protection/<anything>` with all
profiles; with `?mkey=` or under a singleton, with the parent's dict. Only an
unknown top-level path answers `-20001`, and a real empty table answers `[]`.
`rediscovery.fortiweb_shape_verdict(urn, payload, expected_fields=None,
parent_payload=None)` reads the shape: a nested path whose answer equals the
parent's, whose rows hold the child as their own key (`<child>` /
`sz_<child>`), or whose row keys share nothing with the object's fields is
`absent`. `_probe_fortiweb` reads the parent once for a nested path that
returned rows, so the sweep, `probe_endpoint`, the CLI-coverage probe and the
discovery run share the verdict.

**The trap, in one line: never read a FortiWeb verdict from the HTTP status.**
Before 2.13 the probe called every 200 `ok`, so a sweep could register a URN
that only ever returned its parent. Measured on 7.6.8 and 8.0.6, every real
`tree` object that answered with data carried its own keys — the shape probe
changed no real verdict there — while synthetic controls
(`router/static/<fake>?mkey=…`, `fds/update-flag/<fake>`) come back
parent-fallback and a fake top-level module `absent`, on both builds. The same
rule holds for writes: a POST/PUT with an unknown field also answers 200
(§13.9).

### 13.6 CLI coverage: catalog gap or CLI only

The coverage diff used to call every block the catalog does not name "CLI
only". Measured on 7.6.8, all 50 of those blocks were served by REST. Now:

| Bucket | Label | Means |
|---|---|---|
| `catalog_gap` | Catalog gap · REST serves it | the library measured the block's REST path served on the dump's build |
| `cli_only` | Not in catalog | not shown to be served; the row's REST column says *CLI only* when REST measured it absent, *not measured* otherwise |

Discovery runs and the Structure page read both buckets
(`cli_coverage.not_in_catalog`).

### 13.7 Renames: CLI attribute ids propose, field maps decide

Every object and field in a FortiWeb `tree` carries a CLI attribute id
(`name(4246)`), recorded as `attrs.cli_id`. Measured on FortiWeb 7.6.8 → 8.0.6:

- same name → same id for **4,121 of 4,121** fields, and 534 of 534 objects;
- same id → another name in the same object: **18**, every one a real rename
  (`token-secret` → `jwt-token-secret`, `token-header` → `jwt-token-name`,
  `appsec-cloud-connection-url` → `threat-analytics-authurl`,
  `max-setting-initial-window-size*` → `h2-setting-initial-window-size*`, …);
- same id in another object: 2 structural moves (`waf bot-detection-policy
  allow-source-ip` → `source-ip-list`, an object rename that kept its table id;
  `url-type`/`url-pattern` → the new subtable `page-list`);
- new attributes get fresh ids; no id was reused for an unrelated attribute; a
  box running 7.6.8 before its upgrade printed a `tree` byte-identical to another
  7.6.8 box — the ids belong to the build, not to the device.

So `compare()` reports **rename candidates** (fields and objects) and
**moves** by equal CLI id, and [Build compatibility](build-compatibility.md)
and the [Migration report](migration-report.md) show them as hints and
warnings. They are never applied. `api_lib_field_map`, authored by an operator
at `/web/registry/field-map`, stays the only authority: a mapped candidate says
`mapped: true`, and the migration report turns it from `warn` into `translate`.
The rule held on one pair of builds; re-check it on every new pair before
relying on it blindly. Lookalike pairs matched by type alone are noise.

### 13.8 `show full-configuration` prints conditionally

`show full-configuration` prints only the fields that **apply under the row's
current settings**; REST returns them all. Measured on lab rows: 204 fields in
56 objects (7.6.8) and 349 fields in 78 objects (8.0.6) were missing from the
dump while REST and the `tree` had them. A related answer: `set <field> ?`
answers *Parsing error* for a field gated under the current values (50 of 222
rows on 7.6.8, 72 of 280 on 8.0.6).

Consequences:

- **A field missing from a dump is not missing on the build.** `cli_full` only
  ever adds names (and `hidden` when the `tree` lacks them); it never removes
  one. The schema is the `tree`.
- A [Migration report](migration-report.md) reads the dump for what the device
  **uses**, and the `tree` for what the target **has**.
- FortiWeb 7.6.8 and 8.0.6 have **0 hidden fields**: `show full-configuration`
  names nothing the `tree` does not.

### 13.9 REST silently ignores gated fields

A FortiWeb cmdb POST/PUT carrying an unknown field, or a field gated behind a
toggle that is off, answers **HTTP 200 and drops it**. Confirmed in 17 of 17
lab cases: the dependent field sent alone while its toggle is off is not
applied; the toggle and the dependent field sent in **one** request are.
Examples: `server-balance` → `lb-algo` / `health` in a server pool; `http-reuse`
→ `reuse-conn-*`; syslog `proto tls` → `enc-algorithm` / `local-cert`; WAF
`action block-period` → `block-period`; recurring scan schedules → `time` /
`wday`; 8.0.6 cookie security `samesite` → `samesite-value`.

Rules every write path follows:

- **Send dependent fields together**, with the toggle that exposes them, in one
  request.
- **Only a readback proves a write.** The [CLI writer](cli-writer.md) reads every
  field back; a REST write that matters reads the object back.
- The knowledge pack's lab evidence names the fields a toggle exposes
  (`attrs.depends_on`: 12 on 7.6.8, 15 on 8.0.6).
- [Build compatibility](build-compatibility.md) strips the fields a build does
  not have *before* the write, so the 200-and-drop never hides a missing field.

### 13.10 Per-product adapters

Every product describes its schema its own way; `services/schema_adapters/`
holds one adapter per product, all ending in the same evidence (`cli_tree`,
`cli_full`, `schema`, `sweep`) keyed by the REST path. Each adapter declares its
capabilities and where it was verified; the **Schema builds** page shows both.

| Product | CLI schema | REST schema | Verified |
|---|---|---|---|
| FortiWeb | `tree` (types, options, ranges, ids) | shape probe of every `tree` object (no REST schema endpoint) | **yes** — lab VMs on 7.6.8 and 8.0.6 |
| FortiAuthenticator | no `tree`: `config <object>` + `set ?` help walk of the setup CLI (5 objects, 29 fields); `show full-configuration` | Tastypie `/api/v1/<res>/schema/` (58 resources, 316 fields), directory complete | **yes** — 8.0.3 build0099 |
| FortiGate | `tree` (FortiOS format; nested tables folded into fields) | `GET /api/v2/cmdb/<path>?action=schema` | **yes** — 8.0.1 build0245 (catalog-only: evidence arrives by pack or `flask apilib schema-import`) |
| FortiADC | `tree` (FortiOS-family format assumed) | none implemented | **no** — no FortiADC in the lab |
| FortiAnalyzer | JSON-RPC `get` with `option: syntax` | the same answer (the `/cli/global/...` URL is the CLI path) | **no** — no FortiAnalyzer in the lab |

Read-only by construction: the FortiWeb, FortiADC and FortiGate harvests send
`tree` (behind its own whole-command gate) and `show`; the FortiAuthenticator
walk can send only `?` questions, `config <object>` and `edit <a row the box
listed>`, never `set <value>`, `next`, `end` or `abort`, and drops the session;
the FortiAnalyzer session sends only login, `get` and logout.

FortiAuthenticator's credential is the REST API key, which does not log into the
CLI. Its CLI half runs only when the operator gives the CLI password for that one
harvest (Schema builds form, or `flask apilib adapter-harvest --ssh-secret-env`);
it is never stored. Without it the CLI half is reported skipped, by name.

### 13.11 New builds: detection, notification, one-click harvest

`services/schema_watch.py` compares the build every appliance runs with the
builds that have harvested schema evidence (`cli_tree`; `schema` for
FortiAnalyzer). It runs after every firmware read (`firmware_probe`) and from the
scheduled action `schema_watch`.

- **One bell notification per product and build** to the administrators: *New
  build 8.0.7 on fweb-01: schema not harvested*, linking to Schema builds. It is
  not repeated for the next appliance on the same build.
- **Schema builds** (`/web/schema-builds/`, sidebar in the FortiWeb ADOM;
  reading needs `registry.view`) lists the adapters with their capabilities and
  verification, the harvested builds per product, and every appliance on a build
  without a harvested schema with a **Harvest** button (`appliances.apply`,
  audited as `schema_builds.harvest`).
- After a harvest the page compares the new build with the **closest** harvested
  build of the same product: every new or changed object and field, with its
  channel on the new build. An item whose REST side nobody measured on that build
  reads *unknown — to verify* until a sweep or probe measures it.
- The scheduled action `schema_harvest` also runs FortiAuthenticator and
  FortiAnalyzer through their adapters.

### 13.12 Knowledge packs

A node that has never run a build can still know it: the separate
[Knowledge Harvester](knowledge-harvester.md) measures lab devices and the vendor
documentation and writes a **knowledge pack** (`satom-apipack-kb-YYYYMMDD`) in
the same signed format `satom.api-pack/1`, with `library` evidence of the
sources `cli_tree`, `cli_full`, `sweep`, `schema` and `vendor_doc`, and the
vendor release notes in `docs`.

- It is **imported like any API pack** (§11.3–§11.5): verified against the
  node's trust store, imported only where it adds, every item tagged
  `apipack:<version>:<source>`. Knowledge packs sort after SATOM's numbered
  release packs.
- **Local measurement wins.** An item this node measured itself for the same
  source and build is `local` and never replaced.
- A `cli_full` item carries names only; the one exception is lab evidence
  (`summary.lab = true`), whose fresh-row values are recorded as `default` with
  `attrs.lab_default`.
- Each release ships the current knowledge pack in `api-packs/`; an offline node
  that skipped a release imports it by hand like any other pack.
