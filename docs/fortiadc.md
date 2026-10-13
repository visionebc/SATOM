# FortiADC — API conventions & area status

> Ground truth for the FortiADC side of the manager. Built 2026-07-07 from the
> FortiADC **8.0.3** admin guide + CLI reference (docs.fortinet.com, harvested
> with a crawler outside SATOM) cross-checked against the official `terraform-provider-fortiadc`
> SDK and the `fortinet-ansible-dev` httpapi plugin. No lab device existed
> when this was built. Since 2026-10-11 the lab has fortiadc10 (7.6.7) and
> fortiadc11 (8.0.4): the sections dated after that are measured on them, and
> the CLI schema adapter (`tree`, `show full-configuration`, the CLI -> REST
> path rule) is verified on fortiadc10 7.6.7 (API library §14.10).

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
| Endpoint seed (product=fortiadc, api_version=v1) | baseline `app/registry/baselines/fortiadc.json` (FortiADC 8.0.3) → `registry_endpoints` table |
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

## Firmware and the GETs that are writes (fortiadc10, 7.6.7, 2026-10-11)

Read off the FortiADC 7.6.7 GUI bundle (System > Settings > Firmware and
Backup & Restore); the reads were run against fortiadc10. Code:
`app/services/adc_ops.py` (transport), `app/services/upgrade.py` (dispatch).

| Action | Call |
|---|---|
| Partition table | `GET /api/system_global/boot_partition` → `[{partno, active, partid, timestamp}]`; empty `partid` = empty partition |
| Flash | `GET /api/system_global/clear_tmp_space`, then multipart `POST /api/upload/image` (`hasync` 0/1, file field name free); `payload` 0 = accepted, installs into the inactive partition and reboots |
| Boot the other partition | `GET /api/system_global/swap_boot_partition` (reboots) |
| May this account flash | `GET /api/platform/info?vdom=root` → `isSystemAdmin` + `isSystemWritable` |
| Config restore (not wired yet) | multipart `POST /api/upload/check_config` (`entire=enable`) → `{ret, file_path}`; `ret` 2 → `POST /api/system_global/restore_config_local {password, filename}`; `ret` 1 = password-protected file |

**Plain GETs change the box:** `platform/reboot`, `platform/shutdown`,
`platform/reset` (factory reset) and `swap_boot_partition` are all GETs in the
GUI. `adc_ops.ADC_SIDE_EFFECT_PATHS` lists them; the API console, scheduled
custom REST calls and the discovery plan refuse every path on it.


## Depth capture and the virtual-server tree (fortiadc10, 7.6.7, 2026-10-12)

`app/services/adc_vstree.py`. The rediscovery sweep reads the 217 parent
tables; the 27 `<parent>_child_<table>` tables need `?pkey=<parent mkey>` and
are read only by the **depth pass** (Rediscover → *Capture full depth*), once
per parent row of that sweep, into `data/rediscovery/<id>/_deep.json`
(`sweep_generated_at` names the sweep the parents came from). A 404 table is
asked once and recorded absent; a stop discards the partial file.

Measured on fortiadc10:

* **Embedded in the parent row** (the child table repeats it): pool members
  (`pool_member`), routing/rewriting match conditions (`match`), interface
  secondary/trust/HA lists, persistence lists, ippool `node_member`,
  certificate-verify `member`, schedule group `member_list`.
* **Only in the child table**: members of local-cert groups (`local_cert`,
  `intermediate_cag`, `default`), intermediate-CA groups (`intmed_ca`) and CA
  groups (`ca`). Without the depth pass a VS's certificate chain cannot be drawn.
* List fields are **space-separated strings** (`content-routing-list:
  "cr-a cr-b "`); `NONE` means unset (`rs_profile`).
* Auth policy rules (`member[].user_group_id`) and user-group members
  (`member[].radius_server|ldap_server|local_user`) are embedded with no child
  table.
* The VS spells `client_ssl_profile`, `auth_policy`, `ips_profile`,
  `dos_profile`, `ztna_profile`, `scripting_list` with `_` and `waf-profile`,
  `error-page`, `content-routing-list` with `-`. The reference map (`REFS`) is
  explicit for that reason: matching values against every table's names was
  tried and is wrong (`comments` matched a service name, timeouts matched
  reputation rows).
* A WAF profile names its sub-profiles by the table suffix
  (`web_attack_signature` → `security_waf_web_attack_signature`); the tree
  follows that rule for every field instead of a fixed list.

The VS Inspector builds one index and draws every VS from it. Live, the
index is read breadth-first from the VS rows: each round reads the child
tables of the groups just reached (`?pkey=`), then every table those rows
name, once per table, on one reused connection. Only what a VS reaches is
read. For the 15 VS of fortiadc10 that is 70 reads in 0.8 s; reading every
table `REFS` could reach plus every group's child table took 90 reads and
7.6 s (2026-10-12). One VS (`?policy=`) takes 37 reads and 0.4 s. The trees
are identical. `?source=capture` draws from `_config.json` + `_deep.json`
with no device call.

The depth pass also feeds two other stores, like the FortiWeb depth does:

* **Cache, `layer='deep'`** (`adc_vstree.deep_sections` →
  `device_sync.persist_deep_snapshot`, replace per device). Each row of a
  parent table whose child table this build serves becomes a depth-0 object.
  The child rows read for it sit at depth 1 as `<parent>/<child>`, the key
  the gx write-through already keeps. When the child table answered rows,
  the list the parent embeds for the same members is dropped. Analysis reads
  this layer: the Global deep-object picker (*FortiADC object*), sub-element
  counts, the fleet inventory (pools, and pool members as back-ends), and
  the FortiADC object inventory's `…_child_…` rows.
* **API library**: the child tables as sweep evidence of the build, with
  origin `rediscovery-depth:<id>@<version>`. A table that answered for any
  parent is `ok`, and field names come from its rows. This evidence is
  partial: `apilib_harvest.needs_harvest` and the pack import's "local
  measurement wins" rule ignore it, as they ignore a schema harvest's probe.

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
