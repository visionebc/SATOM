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
