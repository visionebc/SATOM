# API library — versioned, append-only, in PostgreSQL

Status: design contract for the `feat/api-library` branch (SATOM 2.2.0).

## Why

The API library answers four questions, and the file-based matrix could answer
none of them at scale:

1. **Which API does this appliance speak?** Resolve the appliance's running
   firmware to an exact build and list what that build serves.
2. **What changed between two builds?** Endpoints and fields added, removed,
   or retyped, and "since which build does field X exist?"
3. **Can I move this object from device A to device B?** What is lost, what
   the destination offers, and whether the destination serves the endpoint.
4. **Incremental knowledge.** Every harvest adds evidence. Nothing is lost when
   an appliance is retired, deleted, or upgraded.

The previous store (`data/api_matrix/*.json`, `data/rediscovery/*/by-version`,
`data/field_schemas`) was derived and rewritten wholesale on every rebuild.
Evidence from appliances that were deleted was filtered out. That is how the
8.0.3 build disappeared, and how a test run once overwrote the production
matrix with an empty one.

## Principles

- **Evidence is immutable.** A harvest is stored once, with its raw payload
  (gzip) and a content hash. Re-harvesting identical content only bumps
  `last_confirmed_at` and `confirmations` on the existing row.
- **Facts are bounded.** Facts are keyed by (field, build, source), not by
  harvest. Growth tracks the number of distinct builds, not the number of
  sweeps.
- **Nothing is filtered by the live appliance table.** Device identity (name,
  serial, model, platform) is copied into the evidence row. Retired devices
  keep their evidence.
- **Unknown is never "compatible".** `fields=None` (endpoint answered, no rows)
  is not `fields=[]`. A build with no evidence is `unmeasured`. "Removed"
  requires both builds to be measured.
- **Product-agnostic.** FortiWeb, FortiADC, FortiAuthenticator, FortiAnalyzer
  and FortiGate all use the same tables. FortiGate is catalog-only: SATOM does
  not manage FortiGates, but the library can hold their API.
- **Every product is English-only** in code, comments, docs and messages.

## Products and sources

| Product key | Evidence sources |
|---|---|
| `fortiweb` | `sweep` (rediscovery), `schema` (harvested field specs) |
| `fortiadc` | `sweep`, `legacy_matrix` (frozen 2026-08-13 file; no FortiADC is left in the fleet) |
| `fortiauthenticator` | `schema` (live Tastypie `/api/v1/<resource>/schema/`), `sweep` |
| `fortianalyzer` | `vendor_doc` (Ansible `fortinet.fortianalyzer` `v_range` data) |
| `fortigate` | `vendor_doc` (Ansible `fortinet.fortios` `v_range` data) |

Source vocabulary (closed set): `sweep`, `schema`, `vendor_doc`, `manual`,
`legacy_matrix`.

## Evidence document (the ingest contract)

Every adapter (sweep, schema dir, vendor collection, live FAC schema, legacy
matrix) produces this plain dict. `api_library.ingest(doc, raw=...)` is the
only writer.

```python
{
  "product": "fortigate",                 # product key
  "source": "vendor_doc",                 # closed vocabulary above
  "captured_at": "2026-09-25T21:00:00",   # when the evidence was produced
  "origin_ref": "ansible:fortinet.fortios:2.6.0",   # where it came from
  "device": None | {                      # None for vendor/manual evidence
      "appliance_id": 34, "name": "fortiweb17", "serial": "FVVM...",
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

Content hash: sha256 of canonical JSON (`sort_keys`, compact) of the document
with `captured_at` removed. The hash is unique per (product, source).

Logical endpoint names: FortiWeb/FortiADC/FAC/FAZ reuse the registry
`name` where one exists. FortiGate uses the Ansible module name without the
`fortios_` prefix (`firewall_policy`); its URN is `/api/v2/cmdb/<path>/<name>`.
FortiAnalyzer uses the module name without `faz_` and the first `jrpc_urls`
entry as URN.

## Tables (models: `app/models_apilib.py`, migration `apilib01`)

All tables are portable (PostgreSQL in production, SQLite in tests).

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
  Unique (endpoint_id, build_id, source). Verdict merge within one fact:
  `ok` from any healthy witness wins, then `absent`, then `error`.
- `api_lib_field` — `endpoint_id, name, first_seen, last_seen`.
  Unique (endpoint_id, name).
- `api_lib_field_fact` — `field_id, build_id, source, type, options (JSON),
  default (JSON), required, children (JSON), platforms (JSON list of hw_type
  or model), first_evidence_id, last_evidence_id, first_seen, last_seen`.
  Unique (field_id, build_id, source).
- `api_lib_span` — `endpoint_id, field_id (nullable: NULL = endpoint span),
  evidence_id, source, from_key, to_key (nullable = open), from_version,
  to_version, attrs (JSON)`. Vendor ranges are stored here once, never
  expanded per build. An open end is capped at the evidence's highest
  known version: a later build is `unmeasured`, not `ok`.
- `api_lib_field_map` — operator-authored renames: `product, endpoint,
  from_version, from_field, to_version, to_field, note, created_by,
  created_at`. Without it a rename reads as "field lost + field added".

Rows are never deleted by any code path in this feature.

## Service API (`app/services/api_library.py`)

Ingest:

- `ingest(doc, raw=None) -> dict` — idempotent; returns
  `{"evidence_id", "created": bool, "facts": {...counts}}`.
- `evidence_from_sweep(product, snapshot, device, origin_ref) -> dict` —
  rediscovery snapshot → evidence document. Applies the error-ratio rule
  (`> 25%` errored endpoints → `healthy=False`).
- `evidence_from_schema_dir(product, line, path) -> dict`.
- `evidence_from_legacy_matrix(product, matrix_doc) -> list[dict]`.
- `backfill(data_root, products=None) -> dict` — reads every
  `rediscovery/*/by-version/*.json` and `_config.json` (including deleted
  appliances; device identity taken from the snapshot, falling back to
  `appliance #<id>`), `field_schemas/<product>/<line>/`, and the legacy
  matrices. Safe to run repeatedly.

Query:

- `products() -> list[dict]`
- `builds(product) -> list[dict]` — version, line, origin, sources, evidence
  count, measured, in_fleet, vendor_only, first_seen, last_seen.
- `endpoints_at(product, version) -> dict` — endpoint → urn, verdict,
  fields_known, sources, witnesses, first/last seen. Includes vendor span
  coverage.
- `fields_at(product, endpoint, version) -> dict` —
  `{"status": "measured"|"blind"|"unmeasured"|"absent", "fields": {...},
  "provenance": [...]}`.
- `compare(product, base, target, endpoint=None) -> dict` — endpoints added,
  removed, unknown; per endpoint fields added, removed, retyped, unknown.
  Honours `api_lib_field_map`.
- `field_history(product, endpoint, field) -> dict` — builds where seen,
  first and last build, sources.
- `resolve_appliance(appliance) -> dict` — product, version, build row (or
  None), status.
- `matrix_doc(product, versions=None) -> dict` — the exact document shape
  `api_matrix.build()` returns today, so existing consumers keep working.

## Readers

- `api_matrix.build/load` read from the library. The JSON file becomes an
  export only.
- `/web/registry/versions` lists every product including FortiGate, reads
  `builds()` and `compare()` directly (the FortiGate matrix is too large to
  render as a whole document).
- `version_compat` reads `fields_at()` and `compare()`.
- API Explorer resolves the selected appliance to a build, marks endpoints
  the build does not serve, and warns before sending.
- `firmware_probe` enqueues a harvest when an appliance changes build.

## Limits that do not go away

- FortiWeb has no schema endpoint. An empty collection reveals no fields.
  Such endpoints are `blind`, never "no fields".
- Vendor data is a claim by the vendor's tooling, not a measurement. It is
  labelled `vendor_doc` everywhere and never outranks a sweep of a real box.
