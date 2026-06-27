# WPP Exceptions — workflow, data model & field reference

> How the manager authors WAF **exceptions** for a Server Policy's Web Protection
> Profile, the **FortiWeb 7.6.4 field reference** for each exception dialog (GUI
> labels/sections/enums scraped from the admin guide via the internal Firecrawl
> [[internal-firecrawl-lan]]; wire names from the team SDK), and the DB model that
> records the per-policy alignment FortiWeb itself cannot.
>
> Companion of [`web_protection_profile.md`](web_protection_profile.md). Keep current
> when the exception specs (`app/ui/pages/wpp_specs.py`), the store
> (`app/services/exceptions.py`) or the page change.

## 1. Why this exists

A Web Protection Profile is **usually shared** by several Server Policies (see
`web_protection_profile.md` §6). An exception added to a profile therefore applies
to *every* policy that binds it, and FortiWeb has **no record of which policy a
carve-out was authored for**. The team's rule:

1. **WPP templates stay clean** — they carry no exceptions (enforced:
   `TemplateLibrary.save` rejects a `web-protection-profile` body with exception
   objects/refs, via `services.exceptions.body_exception_markers`).
2. To except, **clone** a profile (Operations → Clone → WPP) into a non-template,
   live profile and bind it to the Server Policy.
3. Author the exceptions on the **Exceptions** page (sidebar, under Web
   Protection). They are stored as **desired-state** in the app DB — never written
   to the box from here; injection to FortiWeb is a separate step.

The page also produces the **alignment report**: FortiWeb → Server Policy → WPP →
exceptions (with stale-record detection against the device's live bindings).

## 2. Data model (migration v7)

`db/store.py` adds two tables; `services/exceptions.WppExceptionStore` is the CRUD
+ join over them (own connection, like `TemplateLibrary`). NEVER secrets.

```
wpp_exceptions(id, appliance_id, wpp_mkey, exc_type, name, payload_json,
               reason, enabled, author, created_at, updated_at)
wpp_exception_policies(exception_id → wpp_exceptions.id ON DELETE CASCADE,
                       server_policy)            -- PK(exception_id, server_policy)
```

* `exc_type` = the `objform`/`wpp_specs` spec key (so the same FortiWeb-style form
  re-opens it). `payload_json` = the FortiWeb-shaped exception entry.
* An exception is assigned to **one OR several** Server Policies (the junction is
  the missing relationship). `alignment(appliance_id, bindings)` joins the DB
  records with the device's live `(server_policy → wpp)` bindings → per-policy
  exceptions + a **stale** list (records whose policy/WPP no longer match a live
  binding: policy renamed/removed, WPP swapped).

## 3. Exception-type catalog

`EXCEPTION_TYPES` in `app/ui/pages/exceptions_page.py` — the menu of WAF exceptions
the operator can add, each mapped to a curated spec key:

| GUI group | Sub-policy | spec key | structure |
|---|---|---|---|
| Standard Protection | HTTP Protocol Constraints | `http_constraint_exception_item` | named object → entry list |
| Standard Protection | Allow Method | `allow_method_exception_item` | named object → entry list |
| Standard Protection | Geo IP Block List | `geo_ip_exception_member_item` | named object → IP list |
| Standard Protection | Syntax-Based Detection | `syntax_exception_item` | inline list on the policy |
| Standard Protection | Bot Mitigation | `bot_exception_element_item` | named object → element list |
| Client-Side Security | HTTP Header Security | `http_header_security_exception_item` | named object → entry list |
| Client-Side Security | Cookie Security | `cookie_security_exception_item` | inline list on the policy |
| Advanced Protection | URL Encryption | `url_enc_exc_item` | inline list on the rule |
| Advanced Protection | Link Cloaking | `link_cloak_exc_item` | inline list on the rule |
| Advanced Protection | File Security | `file_exception_item` | named object → MD5 list |

## 4. Field reference (FortiWeb 7.6.4)

GUI labels/order/enums from the 7.6.4 admin guide (Firecrawl); wire names from the
SDK. Combos are editable — an unexpected device token always survives.

### HTTP Protocol Constraints exception (`http_constraint_exception_item`)
`Web Protection > Protocol > HTTP Constraints Exceptions`. Match a host/URL, then
toggle which constraints to **omit**.

| Label | wire | type | notes |
|---|---|---|---|
| Host Status / Host | `host-status` / `host` | toggle / text | |
| Source IP / IP | `source-ip-status` / `source-ip` | toggle / IP | IPv4/IPv6/range |
| Request Type | `request-type` | enum | Simple String=`plain` / Regular Expression=`regular` |
| URL Pattern | `request-file` | text | starts with `/` |
| (omit toggles) | `block-malformed-request`, `illegal-*-check`, `max-http-*-length`, … | toggle | enable = exempt; common set curated, rest auto-render. **Wire names best-effort — confirm vs SDK before a real inject.** |

### Allow Method exception (`allow_method_exception_item`)
`Web Protection > Access > Allow Method > Allow Method Exceptions`.

| Label | wire | type | notes |
|---|---|---|---|
| Host Status / Host | `host-status` / `host` | toggle / text | |
| Type | `request-type` | enum | `plain` / `regular` |
| URL Pattern | `request-file` | text | |
| Allow Method Exception | `allow-request` | multi | space-separated: `get post head options trace connect delete put patch webdav rpc others` |

### Geo IP exception (`geo_ip_exception_member_item`)
`IP Protection > Geo IP` → exception object → IP list. One field: `ip`
(IPv4/IPv6 or range). Parent Geo IP action is a subset (Alert & Deny / Deny (no
log) / Period Block); block-period 1–600.

### Syntax-Based Detection exception (`syntax_exception_item`)
`Web Protection > Advanced Protection > SQL/XSS Syntax Based Detection` → per
sub-attack-type exception list (inline).

| Label | wire | type | enum |
|---|---|---|---|
| Element Type | `match-target` | enum | `HOST` `URI` `FULL-URL` `PARAMETER` `COOKIE` |
| Operation | `operator` | enum | `STRING_MATCH` `REGEXP_MATCH` |
| Name | `value-name` | text | Parameter/Cookie |
| Check Value… | `value-check` | toggle | Parameter/Cookie → reveals Value |
| Value | `value` | text | |
| Attack Type | `attack-type` | enum | 11 values (`*_sql_injection` / `*_xss_injection` / `line_comments` …) |
| Concatenate | `concatenate-type` | enum | `AND` `OR` (uppercase) |

### Bot Mitigation exception (`bot_exception_element_item`)
`Bot Mitigation > Exception Policy` → element list (named object).

| Label | wire | type | enum |
|---|---|---|---|
| Element Type | `match-target` | enum | `Client IP` `Host` `URI` `Full URL` `Parameter` `Cookie` |
| Operation | `operator` | enum | `Equal`/`Not Equal` (Client IP) or `String Match`/`Regular Expression Match` |
| Client IP | `ip-range` | text | Client IP type |
| Name | `value-name` | text | Parameter/Cookie |
| Check Value… | `value-check` | toggle | |
| Value | `value` | text | |
| Concatenate | `concatenate-type` | enum | `and` `or` |

### HTTP Header Security exception (`http_header_security_exception_item`)
`Web Protection > Advanced Protection > HTTP Header Security` → exception (named).

| Label | wire | type | notes |
|---|---|---|---|
| Client IP | `client-ip-status` | toggle | |
| IPv4/IPv6/IP Range | `client-ip` | text | when enabled |
| Request URL Type | `request-url-type` | enum | `plain` / `regular` |
| Request URL | `request-url-pattern` | text | starts with `/` |

### Cookie Security exception (`cookie_security_exception_item`)
`Web Protection > Cookie Security > Cookie Exceptions Table` (inline). Fields:
`cookie-name` (req), `cookie-domain`, `cookie-path`. (`wildcard` is an SDK field
not shown in the 7.6.4 dialog.)

### URL Encryption exception (`url_enc_exc_item`)
URL Encryption **Rule** → Exception List (inline). Fields: `url-type` (Type;
`plain`/`regular`), `url-pattern` (Request URL).

### Link Cloaking exception (`link_cloak_exc_item`)
Link Cloaking **Rule** → Exception List (inline). Fields: `url-type` (Type),
`url-pattern` (URL Pattern).

### File Security exception (`file_exception_item`)
`file-exception-policy` (named) → entry list. Fields: `file-name`, `md5` (match
key), `comment`. Allows a specific file past file-security/AV scanning.

## 5. Where it lives in the repo

| Concern | File |
|---|---|
| DB tables (v7) | `app/db/store.py` (`wpp_exceptions`, `wpp_exception_policies`) |
| Store + alignment join + template guard helper | `app/services/exceptions.py` |
| Template "no exceptions" guard | `app/services/templates.py` (`save`, kind WPP) |
| **Inject to box** (REST map + planner + apply) | `app/services/exception_inject.py` |
| **Git-share** (export/import/publish per device) | `app/services/exception_sync.py` |
| Exception-type catalog + page + editor | `app/ui/pages/exceptions_page.py` |
| Inject dialog (dry-run preview → push) | `app/ui/pages/exception_inject_dialog.py` |
| Alignment report dialog | `app/ui/pages/exception_report_dialog.py` |
| The FortiWeb-style forms (specs) | `app/ui/pages/wpp_specs.py` (the `*_exception*`/`*_exc_*` specs) |
| Tests | `tests/test_wpp_exceptions.py`, `tests/test_exception_inject.py`, `tests/test_exception_sync.py` |

## 6. Inject to the device ("save to policy")

Authoring is desired-state in the DB; pushing it onto a box is the SEPARATE step in
`services/exception_inject.py` + the **⬆ Inject to device…** button on the
Exceptions page (`exception_inject_dialog.py`). A WAF exception entry is always a
**by-parent sub-table row**, so the write is uniformly
`FortiWebOps.create(item_logical, payload, mkey=<target>)` — a POST of the entry
scoped to its parent (snapshot + audit + change-history + `dry_run`, exactly like
every other write path). Two parent shapes:

* **container** — a dedicated *named* exception object the WPP sub-policy points at
  (`http_constraint_exception`, `allow_method_exception`, `geo_ip_exception`,
  `bot_exception_policy`, `http_header_security_exception`, `fiel_exception_policy`).
* **inline** — the entry lives on the sub-policy / rule itself
  (`syntax_based_detection`, `cookie_security`, `url_encryption_rule`,
  `link_cloaking_rule`).

`EXCEPTION_REST` maps each `exc_type` → `(item_logical, parent_logical, inline)`;
both endpoints are registry LOGICAL names (resolved per firmware) and are locked
against the registry + the UI catalog by `tests/test_exception_inject.py` and
`dev_smoke`. The **target (parent object name) is a LIVE box concept** chosen at
inject time (`candidate_targets` lists them off the device) — never stored in the
desired-state DB. The dialog plans a **dry-run** first; a real push needs an
explicit click + unlock + confirm.

**Auto-bind (wire the container into the profile).** A freshly-created named container
is orphaned until a WPP sub-policy *points at it*. The **"Auto-bind to WPP sub-policy"**
checkbox + the **"Bind to (sub-policy)"** column do that in the same step: after the
entry is written, `apply_injection(auto_bind=True)` issues
`ops.update(bind_logical, <sub-policy>, {bind_field: <container>})`. Supported for the
four container types whose `ExcRest` carries `bind_logical`/`bind_field` (wire names
from `wpp_specs.py`, locked to the registry by `tests/test_exception_inject.py`):

| exc_type | container | WPP sub-policy (`bind_logical`) | field (`bind_field`) |
|---|---|---|---|
| `http_constraint_exception_item` | `http_constraint_exception` | `http_constraint` | `exception_name` |
| `allow_method_exception_item` | `allow_method_exception` | `allow_method_policy` | `allow-method-exception` |
| `geo_ip_exception_member_item` | `geo_ip_exception` | `geo_ip` | `exception-rule` |
| `bot_exception_element_item` | `bot_exception_policy` | `bot_mitigation_policy` | `exception` |

`http_header_security` (bound on a sub-table ROW) and `file` (no profile ref field)
have no clean top-level bind, so they stay **bind-manual** (do it in the WPP editor);
`supports_auto_bind(exc_type)` gates the UI. `bind_candidates(reader, exc_type)` lists
the sub-policies off the box. The bind is **best-effort** — a failure never sinks the
entry write — and runs in dry-run too (so the preview is faithful) but only marks the
step `bound` on a real apply.

> **Status / validate before a real push.** The inject WRITE PATH is **verified live**
> on fw1 7.6.8 (by-parent create + class-action update + container auto-create, with
> throwaway objects, all cleaned up). The **"Create target object if missing"**
> checkbox auto-creates the named container (`apply_injection(create_container=True)`);
> the **auto-bind** UPDATE above is plumbed + unit-tested (fakes) but its bind wire
> names are SDK-derived and **not yet round-tripped on a box** — `dry_run` stays the
> default, review the plan first.

## 7. Git-share (multi-user desired-state)

Exceptions live in each operator's LOCAL DB, so `services/exception_sync.py` shares
them through the same per-device git tree the Policy Inspector publishes (the
multiuser-safe `reports/<device>/` + `pull --rebase` + retry). It adds one file,
`reports/<device>/_exceptions.json` (type + payload + reason + policies; NEVER
secrets), mirroring `_inventory.json`:

* **Publish (write-through)** — every add/edit/delete calls
  `publish_device_exceptions` (off-UI, best-effort) → writes the file + commit/push.
* **Sync** — the **⤓ Sync from git** button runs `sync_device_exceptions`
  (`git_pull` ff-only + `import_device_exceptions`), merging other operators'
  carve-outs into the local DB, **de-duplicated by content key** (`_content_key`:
  device + WPP + type + payload + policy set) so re-syncing is idempotent and never
  overwrites a local row.

## 8. Caveats / not yet

* **Inject is authored/desired-state** — see §6's note: the entry posts to a chosen
  target; container auto-create AND auto-bind (for the 4 supported types) are wired,
  but the auto-bind UPDATE is not yet round-tripped on a box — keep `dry_run` default
  and review the plan.
* **HTTP-constraint omit-toggles** were corrected against fw1 7.6.8 (the full ~45
  set, with the device's MIXED case — `Illegal-*`/`Post-*`/`Internal-*` Capitalised);
  the exception link field is `exception_name` (UNDERSCORE — see
  [[fortiweb-underscore-fields]]). The editor's *Edit raw JSON…* escape still covers
  any uncurated field.
* The forms render with **empty option sources** (offline authoring) — REF fields
  are editable combos; ENUM choices come from the spec, so they are faithful
  without a device. The alignment report's stale detection needs the device's live
  bindings (passed from the page; no network in the dialog).

## 9. Signature carve-outs — same model, SAME page (store v8)

The same desired-state, policy-bound store ALSO tracks **signature** customizations.
They used to live on a separate 🔏 Signatures page; **as of 2026-06-21 that page was
FOLDED INTO ⚠ Exceptions** ("they'll ultimately be managed this way and must be
assigned to a Server Policy"). ONE area, both kinds.

* **Why** — when a Server Policy is migrated to another box, the team must remove
  everything *custom* authored for it (exceptions AND signature carve-outs) and leave
  no residue. The manager records the policy binding FortiWeb can't.
* **Storage** — migration **v8** adds a `category` column (`exception` | `signature`)
  to `wpp_exceptions`; the Server-Policy junction is shared. `WppExceptionStore` gained
  `category=` filters, `add(category=…)`, and `delete_for_policy(appliance, policy,
  category=None)` — the clean-migration purge (unbinds the policy, deletes orphaned
  entries, KEEPS entries still shared with another policy). The DB **and git** stay
  PARTITIONED by category (`_exceptions.json` | `_signatures.json`) even though one
  page drives both.
* **UI** — `exceptions_page.ExceptionsPage` is the single area. Its **New…** type
  picker offers BOTH groups, so the unified catalog `CATALOG = EXCEPTION_TYPES +
  SIGNATURE_TYPES` (17 types). `SIGNATURE_TYPES` is headlined by the per-signature
  **Signature Exception** (`signature_filter_item`) — plus disabled signature,
  alert-only, disabled sub-class, class action, and custom signature **rule** +
  **meet-condition**, all the same `objform`/`wpp_specs` specs. The **category follows
  the selected type** (`ExceptionEditDialog._category_for` → `_BY_KEY[key].category`),
  so the one editor authors both. 🗑 **Purge (migrate)** removes EVERY carve-out (both
  categories, `delete_for_policy(category=None)`) for a clean migration. Reads open to
  all roles; New/Edit/Delete are CONFIG_WRITE + unlock.
* **Per-signature exception** (the headline) — FortiWeb GUI *Signature Details → `<id>`
  → Exception tab → Create New*: exempt a signature ID (e.g. `010000001`) from matching
  when a request element matches a value. Stored as a row of the signature set's
  `filter_list` (`cmdb/waf/signature/filter_list` → logical `signature_filter_item`).
  The `wpp_specs` form has the full, case-exact field set (verified live on fw1 7.6.8):
  `signature_id`, `match-target` (Element Type: `HTTP_METHOD`/`CLIENT_IP`/`HOST`/`URI`/
  `FULL_URL`/`PARAMETER`/`COOKIE`/`HTTP_HEADER`/`JSON_ELEMENTS`), `operator`
  (`STRING_MATCH`/`REGEXP_MATCH`/`EQ`/`NE`/`INCLUDE`/`EXCLUDE`), `http-method` (NOT
  `HTTP-method`), `ip`, `name`, `value-check`, `value`, `concatenate-type` (`AND`/`OR`).
  Max 128 per signature. The set is SHARED (referenced by a WPP `signature-rule`, bound
  to policies) so the binding is tracked here — *casado a una server policy*.
* **🔎 Detect on device** (`services.exception_detect`) — reads the LIVE per-signature
  exceptions off the box and imports the chosen ones into desired-state, bound to their
  policy. Walks **server policy → WPP (`signature-rule`) → signature set → `filter_list`**
  via the reliable `?mkey=` read (`clone.scoped_rows` — path-style `get_raw` LEAKS the
  parent table when a sub-table is empty). `detect_signature_exceptions(reader, bindings)`
  → `DetectedSigExc`; `import_detected_signature_exceptions(store, …)` de-dups by content
  key (idempotent). UI: `signature_detect_dialog.SignatureDetectDialog`. Verified live on
  fw1 7.6.8 (finds exactly the `010000001` carve-out → `pol-demo-ecom`).
* **Inject + git-share (wired).** ⬆ **Inject** pushes the by-parent carve-outs onto
  the box — `SIGNATURE_REST` maps the signature-set sub-lists
  (`signature_disable_item`/`_filter_item`/`_alert_only_item`/`_subclass_disable_item`)
  + a custom rule's `signature_group_rule_condition` (meet-condition) to
  `ops.create(item_logical, payload, mkey=<target>)`; the target is picked LIVE but
  **`candidate_targets` hides read-only/predefined sets** (`can_view==1` — you must
  clone them first; falls back to showing them if nothing else is writable) and a
  **signature-set carve-out PRE-SELECTS the set its WPP already binds**
  (`wpp_signature_set`). Dry-run preview first. ⤓ **Sync** git-shares them through the
  per-device file `reports/<device>/_signatures.json`
  (`export_device_exceptions(category='signature')` — exceptions never leak in and
  vice-versa; the page publishes both files in one push). **Alignment report** spans
  both categories (device → policy → WPP → carve-outs + stale, export TXT/JSON).
* **Element-type gating** — the `signature_filter_item` form uses `Field.show_when`
  (objform) to reveal ONLY the input relevant to the chosen Element Type (Client IP for
  `CLIENT_IP`, HTTP Method for `HTTP_METHOD`, Name/Check-Value for named elements, Value
  for the rest); `values()` drops hidden keys so switching type never carries a stale
  value into the saved carve-out — mirroring the FortiWeb GUI.
* **Class-action override** injects as an **UPDATE** (`ExcRest.op="update"`, row keyed
  by `main_class_id`) — PUTs the existing main-class row on the signature set. Only the
  custom RULE *object* itself (a top-level create, not a by-parent row) stays out —
  created via the WPP editor / clone. The WRITE PATH is **verified live** on fw1 7.6.8
  (by-parent create + class-action update + container auto-create + a real
  `signature_filter_item` create→delete round-trip on `sig-test-policy`, throwaway
  objects, cleaned up); `dry_run` stays the default.
