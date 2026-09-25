# API library — versioned, append-only, in the database

> **Audience:** operators who keep the library fed and read its pages, and
> engineers who write an adapter or a reader. Operator walkthroughs of the
> pages built on it are in the [User guide](user-guide.md) §30.5,
> §30.8–§30.10 and §41.8–§41.9; the guards are catalogued in
> [Safeguards](safeguards.md) §192–§193.
>
> **Since:** SATOM 2.2.0.

The API library is SATOM's record of **which API each firmware build serves**:
endpoints, fields, field types and options, per product and per exact build,
with every claim traceable to the evidence it came from. It lives in the
application database (the `api_lib_*` tables), it only ever grows, and every
page that answers a firmware question reads it.

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
`sweep` > `schema` > `manual` > `legacy_matrix` > `vendor_doc`.
**Fields are compared only within one kind of evidence.** A sweep carries
wire-only companions (`_val` twins, `sz_`/`q_` internals) that a schema
strips, and subtracting one from the other invents removals. A field set known
on one side only, or by different kinds on the two sides, is reported as
*unknown*, never as added or removed.

---

## 3. Products and sources

| Product key | Evidence sources | Where the evidence comes from |
|---|---|---|
| `fortiweb` | `sweep`, `schema` | rediscovery sweeps of live appliances; field schemas harvested per firmware line |
| `fortiadc` | `sweep`, `legacy_matrix` | sweeps, and the frozen line-only matrix file from before the build axis. No FortiADC is left in the lab fleet, so no new FortiADC evidence arrives until one is registered |
| `fortiauthenticator` | `schema` (and `sweep`) | a live, **read-only** harvest of the device's own Tastypie schema (`GET /api/v1/` and `GET /api/v1/<resource>/schema/`) |
| `fortianalyzer` | `vendor_doc` | the vendor's Ansible collection `fortinet.fortianalyzer` (its `v_range` data) |
| `fortigate` | `vendor_doc` | the vendor's Ansible collection `fortinet.fortios` (its `v_range` data). Catalog-only |

Source vocabulary (closed set): `sweep`, `schema`, `vendor_doc`, `manual`,
`legacy_matrix`. Anything else is refused at ingest.

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
  verdict, fields_known, witnesses (JSON list of device names),
  first_evidence_id, last_evidence_id, first_seen, last_seen`.
  Unique (endpoint_id, build_id, source).
- `api_lib_field` — `endpoint_id, name, first_seen, last_seen`.
  Unique (endpoint_id, name).
- `api_lib_field_fact` — `field_id, build_id, source, type, options (JSON),
  default (JSON), required, children (JSON), platforms (JSON list of hw_type
  or model), first_evidence_id, last_evidence_id, first_seen, last_seen`.
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
| `firmware_probe` | queues a harvest when an appliance changes build (§8.4) |

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
FortiAnalyzer and FortiGate have no live harvester and every entry point says
so by name (`no live harvester for fortianalyzer`).

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

## 9. Limits that do not go away

- **FortiWeb has no schema endpoint.** An empty collection reveals no fields.
  Such endpoints are `blind`, never "no fields". Configure one row on a box
  running that build and sweep it again.
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
- **The field map is authored, not discovered.** The library cannot tell a
  rename from a removal plus an addition until an operator says so.

---

## 10. Troubleshooting

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
| `ingest-file`: `unknown evidence source` | The document's `source` is not one of `sweep`, `schema`, `vendor_doc`, `manual`, `legacy_matrix` |
