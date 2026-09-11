# FortiAuthenticator (FAC) — how this product is wired

FortiAuthenticator is the fourth managed product, added 2026-08-05 against
`FACVMKVM v8.0.3, build0099 (GA)`. It is the odd one out: FortiWeb and FortiADC
speak the Fortinet CMDB REST dialect, FortiAnalyzer speaks JSON-RPC, and
FortiAuthenticator speaks **Django/Tastypie** — a plain REST API with a
per-resource path, HTTP Basic auth and cursor pagination. Everything below was
verified against a live unit; nothing here is transcribed from the vendor guide
without a probe behind it.

## 1. The API in one page

| | |
|---|---|
| Base | `https://<host>/api/v1/` |
| Auth | HTTP Basic, **username + per-user API key** |
| Directory | `GET /api/v1/` lists all 58 resources |
| Collection | `{"meta": {...}, "objects": [...]}` |
| Singleton | a bare object (no `meta`, no `objects`) |
| Page size | default **20**, server max **1000** |

### The API key is not the password

`GET /api/v1/systeminfo/` with the admin **login password** answers **401**,
even though the same credential logs into the GUI. The key is issued per user
by ticking **Web service access** on an Administrator account
(*Authentication → User Management → Local Users → \<user\>*). Store it in the
appliance's password column — it is Fernet-encrypted there like every other
device credential.

`FortiAuthenticatorClient` says this in the 401 message rather than returning a
bare "unauthorized", because the generic wording sends an operator to rotate
the wrong secret.

### `limit=0` does NOT mean "all"

Measured on the device: with no `limit` the page is 20 rows; `?limit=0` comes
back as `meta.limit == 1000`, the server's `MAX_LIMIT`. A client that trusts
either value reports a **prefix of the identity store as the whole thing** —
and on an identity product that is the difference between "12 users" and "12 of
5,000 users". `list_with_error()` therefore walks `meta.next` to exhaustion,
and if the walk stops early it returns the rows **together with an error**. A
short read is never reported as a successful read.

### `schema=500` is not a broken endpoint

Tastypie's `/schema/` introspection crashes on the non-ORM singletons, so 22 of
58 resources answer 500 there. Eight of them **serve GET 200 with real data**
anyway (`systeminfo`, `logsettings`, `snmpgeneral`, `userlockoutpolicy`,
`scheduledbackupsettings`, `fortitokenmobileprovisioning`,
`fortitokenmobilelicenses`, `fortiguardmessages`). A registry seeded from "does
`/schema/` work?" would have silently dropped them. The census in
`endpoints_fortiauthenticator.yaml` is keyed on the **list** response instead.

### Secrets are write-only — verified, not assumed

A canary round-trip on 2026-08-05 created a RADIUS client with a known secret
and a local user with a known password, read both back and deleted them. The
device omits `radiusclients.secret` and `localusers.password` from the GET
payload **entirely** — not masked, absent. The SoT snapshot therefore cannot
leak them by construction. `app/views/fac.py::_NEVER_RENDER` still strips those
field names before anything reaches a template: that is the belt to this brace,
because the cost of being wrong is a credential in every screenshot of the page.
**Re-run the canary after a firmware upgrade before trusting it again.**

### `POST /api/v1/localusers/` is a bulk endpoint

It answers **HTTP 207 Multi-Status** with a list body, **no `Location` header**,
and a per-item status key the vendor spells **`statue`**. Code that looks for
`status`, or for a Location header, reads a successful create as a failure. The
API console shows the body verbatim for exactly this reason.

## 2. The census: 58 resources, 40 usable

| class | count | what it is |
|---|---|---|
| **GET-able** | **40** | seeded into the registry (32 collections + 8 singletons) |
| POST-only (405 on GET) | 11 | actions, not readable config |
| Forbidden (403) | 4 | `csv`, `oauth`, `pushpoll`, `transfertoken` — refused even with a valid key |
| Other | 3 | `faccloudhost` (401), `recovery` (500), `userfortitokenpolicy` (400) |

The full census, with each rejection's reason, lives at the tail of
`endpoints_fortiauthenticator.yaml` so a future reader knows the other 18 were
considered and rejected, not overlooked.

## 3. Where each piece lives

| concern | file |
|---|---|
| Registry seed | `endpoints_fortiauthenticator.yaml` (repo root) |
| Registry loader | `app/registry/loader.py` → `resolve_fac`, `seed_fac_from_yaml` |
| REST client | `app/clients/fortiauthenticator.py` |
| Sidebar / section map | `app/services/fac_menu.py` |
| Section pages | `app/views/fac.py`, `app/templates/fac/` |
| Registry + console | `app/views/fac_api.py`, `app/templates/fac_api/` |
| Config harvest | `app/services/device_sync.py` → `snapshot_from_fac` |
| Guards | `tests/test_fac.py` |

The registry is **DB-first**: the YAML is an INSERT-ONLY seed and operator edits
always win. When a firmware upgrade moves a resource, fix the URN on
*FortiAuthenticator → API → Registry* — no code change, no deploy.

## 4. The menu mirrors the unit, not the guide

`fac_menu.py` is built from the `nav_menu_definition` JSON the unit itself
serves on `GET /` to an authenticated session — **6 groups, 129 leaves**. That
is a stronger source than the administration guide (which is what the
FortiAnalyzer menu was crawled from), because it is what *this firmware*
actually renders.

The GUI is much wider than the API: 129 leaves against 40 readable resources.
**16 of the 28 section pages have no bound endpoint** and say so, rather than
rendering an empty table that reads as "nothing is configured on this device".
`tests/test_fac.py` asserts the menu binds every registry endpoint **exactly
once** — a resource can neither go missing (harvested but unreachable in the UI)
nor be bound twice (the same table on two pages). Neither failure raises an
error on its own.

## 5. Section pages are read-only, deliberately

The other three products grew editable config tabs on top of a dry-run contract
that took several iterations to get right. Rather than ship a fourth unproven
copy of that machinery, writes live in the API console, where every request is
explicit, permission-gated (`registry.execute_write`), **dry-run by default**
and audited. The read path is what makes the fleet observable; the write path
can grow later against the same registry without moving anything.

The console will not post outside `/api/v1/`. A raw-path field that accepts
anything is a request forger pointed at the appliance GUI, which lives on the
same origin and answers to the same session.

## 6. The snapshot excludes the operational endpoints

`_FAC_SOT_EXCLUDE` = `system_info`, `token_fortiguard_messages`,
`token_ftm_licenses`, `cert_scep_requests`.

Every one of them changes between two reads of an **idle** unit — CPU and memory
percentages, SMS and token quotas, the pending SCEP queue. Harvesting them would
make the content hash differ on every sweep and record pure churn as a
configuration change, defeating the dedupe that keeps the SoT store small. Same
reasoning as `_FAZ_SOT_EXCLUDE`.

Verified on a live sweep: 8 objects across 4 sections, 0 errors, and a second
sync with unchanged config creates **no new SoT version**.

## 7. Two traps when registering an appliance

1. **`verify_ssl` must be off.** fac01 presents a self-signed certificate; with
   verification on, `CERTIFICATE_VERIFY_FAILED` kills every call *before it
   authenticates*, and the appliance sits at `last_status=unknown` forever. This
   is the same failure that stalled `fadc` (2026-07-12) and `fortiweb08`
   (2026-07-28) — it is the first thing to check when a new appliance never
   syncs.
2. **The password column holds the API key**, not the login password (§1).

## 8. The 18-character ceiling — read this before adding a fifth product

`fortiauthenticator` is **18 characters**. Every product key the app had ever
written was ≤ 13 (`fortianalyzer`), so the whole product-scoping layer was
declared `varchar(16)`: `appliances.kind` plus the `product` column on
`api_tokens`, `app_ids`, `audit_logs`, `baselines`, `firmware_images`,
`lua_scripts`, `monitor_dashboard`, `monitor_report`, `notifications`,
`plugins`, `scheduled_action` and `templates`.

**This is why the ADOM could exist as a placeholder for months without anyone
noticing: a placeholder never writes a row.** The first real insert failed with
`StringDataRightTruncation`, and the columns that would have failed *later* are
the ones that hurt — an audit entry, a device alert, an API token — each of them
a write that happens long after the operator believes the device is integrated.

All 13 were widened to `varchar(32)` in the DB and in the models on 2026-08-05.
The columns were chosen by **inspecting their stored values**, not by matching
their names: `monitor_probe.kind` (`cpu`, `interface`, …),
`notifications.kind` (`info`, `warning`, …) and `plugins.kind` (`view`) share a
column name but a different domain and were left alone.
`tests/test_fac.py::test_product_key_columns_can_hold_the_longest_adom_key`
fails if any of them narrows again, and it compares against the longest key in
`branding._FALLBACK` rather than a hardcoded 18, so a longer fifth product is
caught the day it is declared.


---

## 9. What SATOM measures on it

The unit gets **two collectors nothing else in the fleet has**, plus the shared
`box` one. The cadence model and the full nine-collector table are in
[metrics-architecture.md §2](metrics-architecture.md); what belongs here is why
this product needed a pair of its own.

**An authenticator does not run out of bandwidth — it runs out of
entitlement.** A box sitting at 4 % CPU refuses the sixth local user when the
licence ships `users_usage_detail {max: 5}`, and that is a cliff no CPU, memory
or session series would ever show. Measuring it the way a FortiWeb is measured
would produce a dashboard that is green on the day the product stops working.

### `capacity` — the licence cliff, from ONE call

One `systeminfo` call yields every licence counter and every FortiToken pool:

| series | labels | meaning |
|---|---|---|
| `satom_fac_licence_used` / `_total` / `_pct` | `resource=<counter name>` | licence headroom per counter |
| `satom_fac_token_used` / `_total` / `_pct` | `pool=<pool name>` | FortiToken pool occupancy |
| `satom_fac_ha_peer` | — | `1` when the unit reports an HA peer serial, `0` otherwise |

The counter name is a **label**, not part of the metric name, so one MetricsQL
expression covers the whole fleet however many counters a future firmware adds.

Two rules in there are load-bearing:

* **A counter with no ceiling emits `used` and `total` but no percentage.** The
  store drops a `None`, so a "percent consumed" panel never shows a fabricated
  0 % for a feature that has no limit — which would read as *plenty of room* for
  something that has no room concept at all.
* **`satom_fac_ha_peer` exists because the config harvest cannot carry it.**
  The unit exposes no HA resource whatsoever across the 58 censused (§2), and
  `systeminfo.ha_sn` is the only signal it gives; that object is excluded from
  the source of truth for churn, so the series is the only place HA presence
  can live.

### `identity` — what the directory CONTAINS, counted not fetched

`satom_fac_inventory`, one series per resource, labelled `resource=`: local /
RADIUS / LDAP / IAM users, user groups, group memberships, MAC devices,
FortiTokens, user certificates, RADIUS clients, TACACS+ clients and SSO groups
— twelve counters.

They are **counting** calls. `limit=1` makes each one a few hundred bytes and
Tastypie's `meta.total_count` still reports the true total, so a directory with
50 000 users costs exactly what an empty one costs. Fetching the rows in order
to count them would be the per-policy mistake in another costume — the same
mistake the whole collection model was rebuilt to remove.

**A resource that fails is reported, never skipped.** A directory that silently
returns 11 of 12 counters looks exactly like a directory with one empty
resource, and those are different facts. If every resource fails the collector
raises, which surfaces as `satom_scrape_up 0` rather than as an absence.

### The signal it cannot give you

> **There is no authentication-RATE series, and there is not going to be one
> from this transport.** All 58 resources were censused (2026-08-05) and none
> reports auth success or failure counters — that lives in syslog, which this
> product deliberately does not ingest. These series answer **what exists**,
> never **is it authenticating**. A dashboard built on them must not be labelled
> "authentication health", because it would be describing the directory's
> contents while an outage was in progress.

### Where the operator sees this

*Monitoring → Collection* holds the per-target interval and the store's health;
the built-in **Fleet metrics (store)** board draws from the same series. In the
FAC ADOM the monitoring kinds are the product-appropriate set — the baseline
plus entitlement — which is what §17.2 of the
[user guide](user-guide.md) describes from the operator's side.
