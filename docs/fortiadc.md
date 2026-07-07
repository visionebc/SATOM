# FortiADC — API conventions & area status

> Ground truth for the FortiADC side of the manager. Built 2026-07-07 from the
> FortiADC **8.0.3** admin guide + CLI reference (docs.fortinet.com, Firecrawl
> harvest) cross-checked against the official `terraform-provider-fortiadc`
> SDK and the `fortinet-ansible-dev` httpapi plugin. **No lab device existed
> when this was built — nothing here is live-verified yet.** When the VM
> lands: probe the registry, verify a write round-trip, then update this file.

## REST conventions

* **Login**: `POST /api/user/login` `{username, password}` → `{"token": …}`.
  Later calls send `Authorization: Bearer <token>` **and** the login cookies
  (the official Ansible plugin sends both). Logout: `GET /api/user/logout`.
  Alternative: a REST-API admin token as header `APITOKEN: <token>`.
* **Paths**: CLI tree flattened with underscores —
  `config load-balance virtual-server` → `/api/load_balance_virtual_server`.
* **Envelope**: `{"payload": …}` — array for collection GETs, object or
  1-element array for `?mkey=` reads, **number** for writes (negative =
  device error code).
* **CRUD**: `POST` bare URL (mkey in body) / `GET` / `PUT ?mkey=` /
  `DELETE ?mkey=`.
* **Child tables**: `/api/<parent>_child_<table>?pkey=<parent mkey>` (child
  row keyed by `&mkey=`), e.g. pool members =
  `/api/load_balance_pool_child_pool_member?pkey=<pool>`.
* **VDOM**: `?vdom=<name>`; `global` = omit the param.
* `config user tacacs+` has no derivable URL (the `+`) — left out of the seed.

## Where things live

| Concern | File |
|---|---|
| Endpoint seed (product=fortiadc, api_version=v1) | `endpoints_fortiadc.yaml` → `registry_endpoints` table |
| Registry access | `app/registry/loader.py` (`load_adc_registry` / `resolve_adc` / `seed_adc_from_yaml`) |
| REST client (Bearer + cookie, payload envelope, generic CRUD) | `app/clients/fortiadc.py` |
| GUI menu tree (Server LB / Link LB / Global LB / WAF / …) | `app/services/adc_menu.py` |
| Views (dashboard, tabbed section pages, raw-JSON object editor) | `app/views/adc.py` |
| Templates | `app/templates/adc/` |
| Product gate (fortiadc sessions → adc + shared blueprints) | `app/__init__.py::_product_gate` |
| Tests | `tests/test_adc.py` |

## Status / pending (needs the lab VM)

* Registry URNs are docs/SDK-derived; expect a few phantoms — probe with the
  device and disable/fix rows from the Registry page (product filter TBD).
* Object lists are **live-only** (no DB-first cache, no device_sync for ADC).
* Writes are a raw-JSON editor (immediate apply, audited, `config_write`) —
  no dry-run, no field forms, no waf_specs equivalent yet.
* No curated list columns (columns derive from the live payload).
* Candidate next steps once verified: field-spec catalog, DB-first cache,
  objedit-style forms, backups/upgrade runbook parity.


## Virtual server dependency chain + create-field seed (verified live, fadc 8.0.3, 2026-07-07)

A FortiADC **virtual server** is NOT a flat "name + IP" object — the device
refuses a create that has no load-balance pool, and the pool needs a real-server
member. Full chain (create in this order):

```
load_balance_real_server   (address = back-end IP)                 <- create 1st
load_balance_pool          (owns pool_member child rows)           <- create 2nd
  child load_balance_pool_child_pool_member
        (real_server_id = <real server name>, NOT inline ip:port)   <- add member
load_balance_virtual_server(pool = <pool name>, interface, address,
        port, profile=LB_PROF_*, method=LB_METHOD_*)                <- create last
```

**REST field names differ from the CLI tokens** (verified by reading the live
objects, not guessed): the VS's pool is **`pool`** (CLI `set load-balance-pool`),
a member references its real server by **`real_server_id`** (CLI
`set real-server`), the member port is `port`. A VS create with no `pool`
returns bare **errcode -56** ("Empty value isn't allowed") naming no field.

**Create-form guard (`app/services/adc_objform.py`).** A blank create form
derives its fields from sibling objects, so on a fresh box (0 siblings) it was
just the Name box and any create -56'd. `CREATE_FIELDS` now seeds the
create-critical fields (with defaults) for `load_balance_virtual_server`,
`load_balance_real_server`, and the `..._child_pool_member` child table;
`create_field_groups()` renders them, `required_fields()` lists the REST keys the
device requires, and `create_hint()` shows the dependency chain atop the form.
`app/views/adc.py` (`form_create_object` / `form_save_row`) **validates the
required fields BEFORE the device call** → a clear `400 "Missing required
field(s): pool"` instead of a blind -56. The create form/child-row JS
(`adc/object.html`) sends every non-empty seeded field on create (`collectAll`,
not the diff-only `collectChanged`). Verified live on fadc 8.0.3: form renders
the pool field + hint; no-pool create blocked 400; with-pool create dry-runs
correctly. Adding a new required object = one `CREATE_FIELDS` entry (tests:
`tests/test_adc_create_seed.py`).
