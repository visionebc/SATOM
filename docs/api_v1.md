# SATOM API v1 — Integration Manual

> **This is SATOM's own API** — the one your systems use to talk to SATOM.
> It is **not** the Fortinet device API that SATOM uses internally to manage
> FortiWeb, FortiADC, FortiGate, FortiAnalyzer and FortiAuthenticator (that one
> is documented in [device-api.md](device-api.md) and
> [api-library.md](api-library.md)).

**SATOM** exposes a small, versioned, **token-authenticated**
HTTP API at `/api/v1` for third-party integrations and automation.

- **Base URL:** `https://<your-satom-host>/api/v1` — the address of your own
  SATOM server
- **Auth:** every request carries `Authorization: Bearer <token>`
- **Format:** JSON in, JSON out (always — even on errors)

This surface is **deliberately narrow**. It cannot upgrade, flash or reboot a
device, and it cannot run any action flagged *destructive* — no token, of any
scope, can reach those.

In the terms of the NAF Framework ([naf-alignment.md](naf-alignment.md)) this
API is part of *Presentation*: the door other systems use. What it opens onto
is the appliance inventory, health, configuration history, findings and the
metrics store (*Observability*), the pre-created Scheduled Actions, the
Processes and the external approval of a Change Request (*Orchestrator*), and
the object authoring below — WAF carve-outs, FortiADC rules, templates,
bindings and baselines (*Intent*). The OpenAPI document (§10) describes every
route of this surface.

There are exactly **three** ways to change anything, and they are not
interchangeable:

1. **Scheduled Actions** (§3) — operational moves an operator pre-created for
   you. You trigger one *by id*; you cannot alter the parameters it was saved
   with.
2. **Object authoring** (§6 FortiWeb, §7 FortiADC) — you write your own WAF
   carve-out or FortiADC rule. Only a type on a **curated allow-list**, and only
   if an administrator granted your token the matching **capability**.
3. **Intent** (§12) — templates, bindings and baselines: desired state. Only
   with the `template_draft` / `template_apply` capabilities, and a push to a
   device is the console's own canary-gated job, never a direct write.

The same page also exposes what SATOM has *recorded* — configuration history
and diffs, findings, metrics (§13) — and describes itself as an OpenAPI
document (§10).

Object authoring is **not** a proxy to the appliance configuration database. No
token, of any scope, can author an administrator account, an interface or a
route through this API: those types are not on the list, and the list is
published by the API itself (`GET /waf/exception-types`, `GET /adc/rule-types`).

---

## 1. Getting a token

Tokens are issued by an administrator in the app (**API Tokens** section). You
**cannot** self-serve one from this page — ask an admin. When a token is created
you receive the plaintext **once**; it is stored only as a hash and can never be
shown again. A token looks like:

```
fmk_<public_id>_<secret>
```

Each token has **four** chained limits you should understand before you rely
on it. All four are evaluated on every call; the first that says no wins:

| Limit | Meaning |
|---|---|
| **Scope** | `read` ⊂ `write` ⊂ `admin`. Triggering an action needs `write`. |
| **Owner-capped** | The token never exceeds its owner's role. If the owner lacks `config_write`, the token's `write` scope does nothing. Disable the owner → the token dies with them. |
| **Product (ADOM)** | The token is bound to `fortiweb`, `fortiadc` or `global` and acts only on that product. |
| **Capability** | Object authoring (§6, §7) is refused unless the token *carries* the matching capability — `waf_exception_draft` / `waf_exception_apply` / `adc_rule_draft` / `adc_rule_apply`. An **empty capability list means no object writes at all**; it is never read as "everything". Ask the administrator for the one you need, by name. |

> A `write` token with an **empty capability list** is not scoped to a single
> action or device: it can run every non-destructive catalog action enabled in
> its ADOM that needs no explicit grant. Treat it as a credential for all of
> that automation, or ask for a token restricted to named capabilities (below).

> **Draft and apply are different credentials, not a flag you choose.** A token
> holding only `*_draft` that sends `"apply": true` is refused with
> `403 capability_denied` and **nothing is written** — it is never quietly
> downgraded to a draft. That matters: a silent downgrade would return success
> to an automation that then believes the hole is closed.

---

## 2. Authentication

Send the token on **every** call as a Bearer header:

```
Authorization: Bearer fmk_abc123_def456...
```

Missing/blank → `401 unauthenticated`. Wrong/expired/revoked → `401 invalid_token`.
The API never issues an HTML login redirect — you always get JSON.

---

## 3. Endpoints

Paths are relative to the base URL. **Scope** is the minimum token scope;
**capability** is the extra explicit grant, where one applies.

| Method | Path | Scope | Capability | Purpose |
|---|---|---|---|---|
| `GET`  | `/ping` | read | — | Identity of the token (owner, scopes, product) |
| `GET`  | `/appliances` | read | — | Device inventory + cached status |
| `GET`  | `/appliances/<id>` | read | — | One device |
| `POST` | `/appliances/<id>/firmware-check` | write | `inventory` | Ask the device its running firmware, **live** (§8) |
| `GET`  | `/actions` | read | — | Scheduled actions visible to the token |
| `POST` | `/actions/<id>/run` | write | — | Trigger a **non-destructive** action |
| `GET`  | `/actions/runs/<run_id>` | read | — | Poll the outcome of a run |
| `POST` | `/change-requests/<id>/external-approval` | admin | — | Record the external change authority's verdict on a change request in **External** approval mode (below) |
| `GET`  | `/waf/exception-types` | read | — | The allow-list of WAF carve-out types (§6) |
| `GET`  | `/waf/exceptions` | read | — | Carve-outs this token authored (`?all=1` needs `admin`) |
| `GET`  | `/waf/exceptions/<id>` | read | — | One carve-out |
| `POST` | `/waf/exceptions` | write | `waf_exception_draft` (+ `waf_exception_apply` for `"apply": true`) | File a WAF carve-out (§6) |
| `DELETE` | `/waf/exceptions/<id>` | write | `waf_exception_draft` | Withdraw one **you** authored, from desired state only (§6) |
| `GET`  | `/adc/rule-types` | read | — | The allow-list of FortiADC rule types (§7) |
| `GET`  | `/adc/rules` | read | — | FortiADC rules of a type, read from the appliance (§7) |
| `POST` | `/adc/rules` | write | `adc_rule_draft` (+ `adc_rule_apply` for `"apply": true`) | Create a FortiADC rule (§7) |
| `GET`  | `/ui/themes` | read | — | The theme names on this node and which one is active (§8) |
| `GET`  | `/ui/theme` | read | — | One theme as a `satom.ui-theme/2` document: tokens, logo and favicon; the active theme, or `?name=` (§8) |
| `GET`  | `/system/nodes` | read | `metrics`, only on a capability-restricted token | CPU, memory and disk of every SATOM node now, graded (§9). **Global** token only |
| `GET`  | `/system/nodes/history` | read | `metrics`, only on a capability-restricted token | The same readings over time (§9). **Global** token only |
| `GET`  | `/openapi.json` | read | — | This API as an OpenAPI 3.0 document, built from the live routes (§10) |
| `GET`  | `/templates` | read | — | Templates of the token's ADOM (§11) |
| `GET`  | `/templates/<id>` | read | — | One template: body, versions, review history, bindings (§11) |
| `GET`  | `/bindings` | read | — | Template bindings of the ADOM, `?appliance=<id>` for one device (§11) |
| `GET`  | `/baselines` | read | — | Baselines of the token's ADOM (§11) |
| `GET`  | `/baselines/<id>` | read | — | One baseline with its templates (§11) |
| `POST` | `/templates` | write | `template_draft` | Create a template, or a new version of one (§12) |
| `PUT`  | `/templates/<id>` | write | `template_draft` | Save a new version (versions are immutable) (§12) |
| `DELETE` | `/templates/<id>` | write | `template_draft` | Delete an unlocked version (§12) |
| `POST` | `/templates/<id>/approve` | write | `template_apply` | Approve (four-eyes: never the author) (§12) |
| `POST` | `/templates/<id>/reject` | write | `template_apply` | Reject with a reason (§12) |
| `POST` | `/templates/<id>/unapprove` | write | `template_apply` | Revoke an approval (§12) |
| `POST` | `/templates/<id>/apply` | write | `template_apply` | Preview, or start the canary-gated apply job (§12) |
| `POST` | `/bindings` | write | `template_draft` | Bind a device to a template family (§12) |
| `DELETE` | `/bindings/<id>` | write | `template_draft` | Remove a binding (§12) |
| `POST` | `/baselines` | write | `template_draft` | Create a baseline (§12) |
| `PUT`  | `/baselines/<id>` | write | `template_draft` | Update a baseline (§12) |
| `DELETE` | `/baselines/<id>` | write | `template_draft` | Delete a baseline (§12) |
| `GET`  | `/appliances/<id>/config-history` | read | `config_history`, only on a capability-restricted token | Recorded configuration versions of one device (§13) |
| `GET`  | `/appliances/<id>/config-diff` | read | `config_history`, only on a capability-restricted token | What changed between two versions, `?from=&to=` (§13) |
| `GET`  | `/findings` | read | `findings`, only on a capability-restricted token | What the alert engine finds right now (§13) |
| `GET`  | `/metrics/query` | read | `metrics`, only on a capability-restricted token | A read-only MetricsQL query over SATOM's own series (§13) |
| `GET`  | `/processes` | read | — | The processes the token's ADOM may see (§14) |
| `GET`  | `/processes/<id>` | read | — | One process, with its diagram (§14) |
| `POST` | `/processes/<id>/run` | write | `process_arm` for `"armed": true` | Walk a process — a **rehearsal** unless armed (§14) |
| `GET`  | `/triggers` | read | — | The triggers and their enabled automations (§15) |
| `POST` | `/events` | write | — | Post an `api.event`: starts the automations of every matching trigger (§15) |
| `GET`  | `/process-runs/<id>` | read | — | One walk and its steps; poll a run parked on a manual gate (§14) |

The write endpoints are rate-limited to **30/min**, like `/actions/<id>/run`.

### `GET /ping`
Verify a token and see what it can do.

```json
{
  "ok": true,
  "token": "abc123",
  "name": "integration-drain-bot",
  "owner": "svc-external",
  "scopes": ["read", "write"],
  "product": "fortiweb"
}
```

### `GET /appliances` / `GET /appliances/<id>`
Returns the devices the token's owner may see. Each device:

```json
{
  "id": 6,
  "name": "fw6",
  "kind": "fortiweb",
  "host": "192.0.2.75",
  "port": 443,
  "status": "up",
  "last_checked_at": "2026-07-08T18:00:00+00:00",
  "maintenance": false,
  "firmware": "FortiWeb-KVM 7.6.8,build1128(GA.M),260602",
  "firmware_checked_at": "2026-08-13T00:09:43.036612",
  "model": "FortiWeb-KVM 7.6.8",
  "hw_type": "vm"
}
```

`firmware` is **verbatim** as the vendor spells it — SATOM does not normalise
it. Turning that string into a comparable version is a matching rule that
belongs to whatever owns the vulnerability dictionary; a second copy of the
rule here would drift from it.

`firmware_checked_at` is the half that makes the version usable. **`null`
means nobody ever confirmed this version against the device** — it may be an
operator's note, or a reading from a firmware ago. A consumer that correlates
versions against advisories should refuse an unattested row rather than
publish a verdict about a box it never observed.

### `POST /appliances/<id>/firmware-check`
Ask ONE device what it is running, right now. Read-only against the appliance
(a single status call, the same one the connectivity probe makes) and it can
never reach the firmware *upgrade* path, which is hard-blocked on this API.

Requires the `write` scope **and** the explicit `inventory` capability: an
empty capability list does **not** grant it. Rate-limited to **10/min** —
every call opens an authenticated session to a live firewall.

Success (`200`):

```json
{
  "ok": true,
  "id": 14,
  "name": "fortiweb09",
  "kind": "fortiweb",
  "firmware": "FortiWeb-KVM 7.6.8,build1128(GA.M),260602",
  "model": "FortiWeb-KVM 7.6.8",
  "hw_type": "vm",
  "checked_at": "2026-08-13T00:09:43.036612",
  "changed": true,
  "previous": "7.6.8",
  "source": "live"
}
```

`changed: false` means the version did **not** move — it is still a fresh
observation, and `checked_at` advances.

Failure (`502`) — the device was not reached, or answered without a version:

```json
{
  "error": "device_refused",
  "detail": "errcode -20010: The license of peer VM FortiWeb is not valid.",
  "message": "The appliance did not return a firmware version; nothing was recorded.",
  "firmware": "FortiWeb-KVM 7.6.8,build1128(GA.M),260602",
  "firmware_checked_at": null
}
```

**A failed check writes nothing — not even the timestamp.** The last known
value and its (possibly `null`) age are echoed so the caller can decide
whether the stale reading is still good enough for it. If `firmware_checked_at`
could be stamped by a check that never reached a device, the field would mean
nothing to anyone.

### `GET /actions`
Lists the scheduled actions in the token's ADOM. Look at `api_runnable`: a
destructive action (`danger: true`) is shown but can **never** be triggered
through the API.

```json
{
  "actions": [
    {
      "id": 42,
      "name": "Drain backend web-01",
      "action": "backend_set_status",
      "label": "Enable/disable a pool member",
      "scope": "user",
      "product": "fortiweb",
      "enabled": true,
      "schedule_kind": "manual",
      "last_run": null,
      "last_status": "",
      "next_run": null,
      "danger": false,
      "api_runnable": true
    }
  ]
}
```

### `POST /actions/<id>/run`
Triggers the action **with the parameters it was saved with**. Rate-limited to
**30/min**. Returns the run id so you can poll it.

Which actions a token may trigger is decided by its **capabilities** (the
administrator ticks them when minting the token). Each catalog action belongs to
one capability:

| capability | actions | empty list grants it? |
|---|---|---|
| `backend_edit` / `backend_config` / `policy_status` / `cert_swap` | `backend_set_status` / `backend_set_config` / `policy_set_status` / `swap_certificate` (AppID-scopable) | yes |
| `maintenance` | `backup`, `device_sync`, `device_inspect`, `deep_capture`, `signature_sync`, `system_backup`, `cert_scan`, `appid_import` | yes |
| `reports` | `stats`, `inventory_snapshot`, `health_check`, `ha_check` | yes |
| `cert_renew` | `cert_manager_server`, `cert_manager_clientserver`, `cert_manager_client` | **no** |
| `monitoring` | `deep_monitor`, `metrics_scrape`, `monitor_report` | **no** |
| `sentinel` | `sentinel_sweep`, `sentinel_baseline`, `sentinel_vuln_sync`, `sentinel_feed_publish` | **no** |
| `feeds` | `signature_check`, `knowledge_fetch`, `artifact_refs` | **no** |
| `api_library` | `apilib_harvest`, `schema_harvest`, `schema_watch` | **no** |
| `netbox` | `netbox_reconcile` | **no** |

A token with a non-empty list runs only the actions of the capabilities it
lists. The capabilities marked **no** were added on 2026-10-15: before that
those actions had no capability, and only a token owned by a user administrator
could run them. An empty list keeps that rule for them, so no token issued
earlier gained anything. Destructive actions (`upgrade`, `upgrade_prep`,
`reboot`, `ha_failover`, `cert_lifecycle`, `custom_rest`) are never runnable
through the API, whatever the token holds. System Automations also need an
owner with user management rights.

**Reading recorded data.** Three capabilities gate what a token may *read*,
not run:

| capability | routes | empty list grants it? |
|---|---|---|
| `metrics` | `GET /metrics/query`, `GET /system/nodes`, `GET /system/nodes/history` | yes |
| `findings` | `GET /findings` | yes |
| `config_history` | `GET /appliances/<id>/config-history`, `GET /appliances/<id>/config-diff` | yes |

An empty list reads all three, as before. A restricted list must name the
surface: a dashboard token can hold `metrics` alone and run nothing.
`monitoring` still implies `metrics` and `findings`, which it granted before
these existed (2026-10-24), so no token issued earlier lost them. Before that
date the configuration history had no capability at all, so a token restricted
to, say, `backend_edit` could read every recorded configuration of its ADOM;
such a token now needs `config_history` too.

```json
{
  "ok": true,
  "run_id": 99,
  "action_id": 42,
  "status": "ok",
  "summary": "disable backend web-01 on pool pool-web"
}
```

### `GET /actions/runs/<run_id>`
Poll a run's outcome.

```json
{
  "run_id": 99,
  "action_id": 42,
  "status": "ok",
  "trigger": "api",
  "summary": "disable backend web-01 on pool pool-web",
  "started_at": "2026-07-08T18:01:00+00:00",
  "finished_at": "2026-07-08T18:01:04+00:00"
}
```

### `POST /change-requests/<id>/external-approval`
The external change authority's verdict on a change request whose approval
mode is **External**. Needs the **`admin`** scope (owner holds
`user_manage`). Body: `{"approved": true|false, "by": "CAB", "detail": "CHG-7"}`
— `approved` is required and must be a JSON boolean; `by` (default: the token
name) is recorded as `api:<by>`. `false` withdraws an earlier approval, which
makes the change un-runnable again.

| answer | when |
|---|---|
| `200` `{"ok": true, "external_approved_at": …}` | recorded |
| `400 bad_request` | `approved` missing or not a boolean |
| `404 not_found` | no such change, or it names no appliance visible to the token's ADOM |
| `409 not_external` / `409 closed` | the change is approved in SATOM (Manual mode), or already completed / failed / cancelled — nothing recorded |

Every call is audited (`api.change_request.external_approval`, refusals as
`…_refused`).

---

## 4. A complete example — drain / restore a backend

The API cannot *re-point* a backend to a new IP; what it can do is
**enable / disable** a pool member (drain or restore it). The recipe:

1. An admin creates a dedicated user (role `operator`, so it has `config_write`).
2. In **Automation → Scheduled Actions**, pre-create two actions and note their ids:
   - `backend_set_status` with `enabled=false` → "drain backend X"
   - `backend_set_status` with `enabled=true`  → "restore backend X"
3. The admin issues a token: owner = that user, product = `fortiweb`, scope = `write`.

Then the integrator calls:

```bash
TOKEN="fmk_abc123_def456..."
BASE="https://<your-satom-host>/api/v1"

# 1. Verify the token
curl -s -H "Authorization: Bearer $TOKEN" $BASE/ping | jq

# 2. Find the action id (api_runnable:true)
curl -s -H "Authorization: Bearer $TOKEN" $BASE/actions \
  | jq '.actions[] | {id, name, action, api_runnable}'

# 3. Drain the backend (action id 42)
curl -s -X POST -H "Authorization: Bearer $TOKEN" $BASE/actions/42/run | jq
#  -> {"ok":true,"run_id":99,"status":"ok","summary":"disable backend ..."}

# 4. Poll the result
curl -s -H "Authorization: Bearer $TOKEN" $BASE/actions/runs/99 | jq
```

---

## 5. Errors

Every error is JSON with an `error` code (and usually a `message`).

| HTTP | `error` | When |
|---|---|---|
| 401 | `unauthenticated` | No / malformed `Authorization` header |
| 401 | `invalid_token` | Unknown, expired or revoked token |
| 403 | `insufficient_scope` | Token scope too low for the endpoint |
| 403 | `owner_forbidden` / `owner_disabled` | Owner lacks the permission, or is disabled |
| 403 | `wrong_product` | Token's ADOM cannot touch that action's product |
| 403 | `destructive_blocked` | Firmware upgrade/flash/reboot — never allowed via API |
| 404 | `not_found` | No such action / run (or not visible to this token) |
| 409 | `disabled` | The action — or the process — is disabled |
| 409 | `already_running` | The action is already running |
| 403 | `capability_denied` | `"armed": true` on a process walk without the `process_arm` capability (§14) |
| 400 | `appliance_required` / `invalid_diagram` | A process walk needs a device, or its diagram cannot run yet (§14) |
| 429 | `rate_limited` | Too many requests (run is 30/min) |

Object authoring answers with these too, plus its own set — see
**§7 → Additional error codes** for the full list.

Every authenticated call and every run is **audited** (who, when, which token),
and so is every *refusal* of an object write: the denial reason is recorded
against your token.

---

## 6. WAF carve-outs — `/api/v1/waf/*` (FortiWeb)

File an exception on the Web Protection Profile in front of your application.

This is **not** a proxy to the FortiWeb configuration database. The type you may
author comes from a curated catalog, and only the *exception* half of it —
signature customisations edit a shared signature set and stay operator-only.
`GET /waf/exception-types` publishes the exact allow-list, with the required
fields and the enum values for each type; it is the same list the server
enforces.

Two capabilities decide what your token may do. They are granted by an
administrator on the token and **cannot be requested in the call**:

| capability | effect |
|---|---|
| `waf_exception_draft` | Records the carve-out as desired state and returns the exact device request that would be sent. **Never touches an appliance.** |
| `waf_exception_apply` | May additionally push it, with `"apply": true`. |

A draft-only token that sends `"apply": true` gets `403 capability_denied` and
nothing is written — it is never silently downgraded to a draft.

```bash
# 1. What may I author?
curl -sH "$AUTH" https://<your-satom-host>/api/v1/waf/exception-types | jq '.types[].key'

# 2. File one (draft — no device is touched)
curl -sX POST -H "$AUTH" -H 'Content-Type: application/json' \
  https://<your-satom-host>/api/v1/waf/exceptions -d '{
    "appliance_id": 3,
    "wpp_mkey": "wpp-app1",
    "exc_type": "allow_method_exception_item",
    "policies": ["pol-app1"],
    "reason": "CVE-2026-1234 mitigation needs PATCH on /api/v2/upload",
    "payload": {"request-type": "plain",
                "request-file": "/api/v2/upload",
                "allow-request": "put patch"}
  }'
# -> 201 {"created":true,"applied":false,"exception":{...},"plan":{...}}

# 3. With an apply-capable token, push it (target = the device object it goes in)
#    ... same body plus:  "target": "am-exc", "apply": true
```

`GET /waf/exceptions?appliance_id=3` lists **the carve-outs your token
authored**. `?all=1` widens to every carve-out on the appliance and needs the
`admin` scope. `DELETE /waf/exceptions/<id>` withdraws one you authored — from
desired state only: if it was already applied, the entry is still on the
appliance and the response says so.

**AppID-scoped tokens.** If your token is pinned to AppIDs you must list the
`policies` the carve-out is for, and they must be yours. You will also be
refused when the Web Protection Profile you named is bound to a policy outside
your scope: a profile is usually shared, so the exception would apply to every
application on it. Ask an operator for a dedicated profile (clone + rebind).

## 7. FortiADC rules — `/api/v1/adc/*`

Same capability model (`adc_rule_draft` / `adc_rule_apply`), same curated
allow-list (`GET /adc/rule-types`), one honest difference: FortiADC writes go
straight to the appliance because there is no desired-state store for it. So:

* `"apply": false` (the default) returns the exact request that *would* be sent,
  built locally — no session is opened.
* Creating a name that already exists is refused with `409 already_exists`
  rather than risking an overwrite of an object your token does not own.
* An applied create is **read back** from the appliance. The `201` answer
  carries `verify`: `verified` (the appliance holds the object with the fields
  you sent), or `unverified` with the reason (only secrets were sent, the
  re-read failed). An appliance that accepted the POST and does not hold the
  object answers `502 not_applied`, with `verify.mismatch` naming each field
  the appliance holds differently.
* **There is no DELETE.** Without a store there is no recorded author, so
  "delete only what you created" cannot be proven, and an endpoint that cannot
  tell your object from an operator's is a way to remove someone else's
  protection. Withdrawal is an operator action.
* An AppID-scoped token cannot use this surface at all: AppID scope resolves to
  FortiWeb server policies and is unprovable here.

### Additional error codes

| HTTP | `error` | When |
|---|---|---|
| 400 | `bad_request` | The body is not a JSON object |
| 400 | `type_not_allowed` | The carve-out type / ADC logical is not on the allow-list |
| 400 | `invalid_payload` | Required fields missing or badly formatted (`errors[]` says which) |
| 400 | `target_required` | `apply: true` without the device object to write into |
| 403 | `capability_denied` | The token lacks `*_draft` / `*_apply` |
| 403 | `appid_scope_unresolved` | An AppID-scoped token did not name its policies |
| 403 | `appid_scope_denied` | A named policy is outside the token's AppID scope |
| 403 | `wpp_shared_denied` | The profile is bound to a policy outside the scope |
| 403 | `wpp_scope_unprovable` | SATOM cannot prove the profile is unshared (no cache) |
| 403 | `not_appid_scopable` | An AppID-scoped token on the FortiADC surface |
| 409 | `template_locked` | The profile is template-managed; templates stay clean |
| 409 | `already_exists` | An ADC object of that name is already on the appliance |
| 500 | `registry_mismatch` | The rule type resolved to an endpoint SATOM cannot address — report it; retrying will not help |
| 502 | `device_unreachable` | SATOM could not open a session to the appliance |
| 502 | `device_error` | The appliance rejected or could not serve the write |
| 502 | `not_applied` | The appliance accepted the write, but reading it back shows it does not hold it (`verify` says what differs) |

---

*This manual is hand-written, and that is exactly why it is pinned by a test.*
`tests/test_api_v1_manual.py` fails when a route, an object-write capability or
an error code exists in the code and not in this page — a manual that quietly
loses an endpoint looks identical to one that is complete, and a reader who
cannot find a capability concludes the product does not have it.*

## 8. Sharing the console theme — `/api/v1/ui/*`

Another SATOM node calls `GET /ui/theme` when an admin uses **Settings →
Appearance → Import from a site… → Another SATOM node**. Mint a `read` token on
the node that HAS the theme and paste it on the node that wants it; the token is
used for that one request and is not stored there.

* `GET /ui/theme` returns the active theme; `GET /ui/theme?name=<theme name>`
  any other one (`404 not_found` if no theme has that name).
* The answer is the same document **Export** downloads (schema
  `satom.ui-theme/2`): `name`, `description`, `tokens` (overrides only) and
  `assets.logo` / `assets.favicon` as `{"type": "png"|"svg", "data": <base64>}`.
  The receiving node validates it exactly like an imported file: one bad token
  or an asset that is not an image refuses the whole document.
* `read` is enough on purpose: a theme is colours plus the logo the sign-in
  page already shows to anyone, and nothing on this surface writes.
* Rate-limited to 30/min.

## 9. SATOM node resources — `/api/v1/system/*`

CPU, memory and disk of the SATOM nodes themselves (not of the appliances):
the readings behind **Monitoring → SATOM health** and its **Resource history**
charts, for an outside monitoring system.

**Access.** A `read` token bound to the **global** ADOM. A token bound to a
product gets `403 wrong_product`, because SATOM health is Global-only and the
API gives no more than a session gets. A token restricted to named
capabilities also needs `metrics` (`403 capability_denied` otherwise). An
empty capability list is enough, as for every other `GET`. Rate-limited to
60/min. Node addresses are never in the answer.

### `GET /system/nodes`

Every node as it is now, graded against Settings → Thresholds (*SATOM machine*):

```json
{"status": "ok",
 "limits": {"disk_warn_pct": 80, "disk_crit_pct": 92, "mem_warn_pct": 80, ...},
 "nodes": [
  {"name": "satom-node-1", "role": "primary", "is_local": true,
   "reachable": true, "status": "ok", "reasons": [],
   "cpus": 4, "cpu_pct": 1.7,
   "mem_total_mb": 4096, "mem_used_mb": 1309, "mem_pct": 32.0,
   "disks": [{"mount": "/", "total_gb": 26.2, "used_gb": 20.4, "pct": 77.8}],
   "uptime_s": 824592},
  {"name": "satom-node-2", "role": null, "reachable": false,
   "status": "unknown", "cpu_pct": null, ...}]}
```

A node that did not answer is `reachable: false`, `status: "unknown"`, and its
readings are `null`. Its last known numbers are not repeated.

### `GET /system/nodes/history`

| Parameter | Values | Default |
|---|---|---|
| `range` | `1h`, `6h`, `24h`, `7d`, `30d`, `90d` | `24h` |
| `node` | a node name (`satom-node-1`) | every node |
| `metrics` | comma-separated: `cpu`, `mem`, `disk` (percent), `mem_used_mb`, `mem_total_mb`, `disk_used_gb`, `disk_total_gb`, `up` (1 answered, 0 did not) | `cpu,mem,disk` |

```json
{"ok": true, "range": "24h", "start": 1792454700, "end": 1792541100,
 "step_s": 240, "errors": [],
 "series": [
  {"key": "cpu", "metric": "satom_node_cpu_pct", "unit": "%",
   "node": "satom-node-1", "mount": null,
   "points": [[1792454700, 2.1], [1792454940, 1.8], ...]},
  {"key": "disk", "metric": "satom_node_disk_pct", "unit": "%",
   "node": "satom-node-1", "mount": "/", "points": [...]}]}
```

* `points` are `[unix seconds, value]`, one per `step_s`, at most 400 per
  series. Each is the **highest** reading in its step, so a peak is not
  averaged away on long ranges. Steps are never finer than the 3-minute sample
  cadence.
* A missing point is a gap: no sample in the step plus the six minutes before
  it (the node did not answer, or the action did not run). It is never filled
  in.
* Samples are written by the `metrics_scrape` scheduled action. A node only
  has history from the release that added these series onward.
* If the metrics store does not answer, the response is **`502
  store_unavailable`**, with the store's message under `errors`. It is never a
  `200` with empty series, which a poller would record as "no load".
* A bad `range`, `node` or `metrics` is `400 bad_request`.

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://<your-satom-host>/api/v1/system/nodes/history?range=7d&metrics=disk_used_gb"
```

## 10. The API as a document — `GET /openapi.json`

```bash
curl -s -H "Authorization: Bearer $TOKEN" https://<your-satom-host>/api/v1/openapi.json
```

An **OpenAPI 3.0** document of every path and method this API serves, built
**at request time** from the live routes: the scope each view enforces
(`x-satom-scope`), the explicit capabilities it asks for
(`x-satom-capabilities`), its path parameters and its documented responses.
It is not written by hand and it is not generated into a file at release
time, so it cannot lag behind the code: a route is in the document the
moment it is registered. Feed it to a client generator or a request
explorer; this page remains the prose explanation of *why* each gate exists.

The security scheme is `bearerAuth` (HTTP bearer). Scope and capabilities are
vendor extensions because OpenAPI's own security scopes describe OAuth, not
SATOM's owner-capped ladder.

---

## 11. Intent, read — `/api/v1/templates`, `/bindings`, `/baselines`

In the vocabulary of the NAF Framework this is the **Intent** block: the
desired state SATOM keeps as **Templates** (versioned, reviewed bodies),
**Template bindings** (which device a template family governs, with its
per-device values) and **Baselines** (a scoped assembly of approved
templates). Reading needs the `read` scope and an owner who may open the
Templates page (`operations.view`, else `403 owner_forbidden`). Everything
is scoped to the token's ADOM exactly like a console session of that ADOM:
another product's template or baseline is `404 not_found`, never a 403.

### `GET /templates`

Newest version first. Filters: `?kind=`, `?status=pending|approved|rejected`
(anything else is `400 bad_request`), `?name=`. Rows carry identity, status,
author, provenance and the build they were written for — **not the body**.

### `GET /templates/<id>`

The template with its `body`, `exceptions`, `validated_builds`, every
`versions[]` of its family (`id`, `version`, `status`, `author`,
`created_at`), the `review_history[]` (who approved, rejected or revoked,
when, why) and its `bindings[]`.

### `GET /bindings`

Bindings of every device the token may see; `?appliance=<id>` narrows to one
device (`404` when it is not in the ADOM). Each: `appliance_id`, `kind`,
`name`, `pinned_version` (`null` = follow the newest approved version),
`variables`, `note`, `created_by`.

### `GET /baselines` / `GET /baselines/<id>`

The baselines of the ADOM with their scope (`zone`, `line`, `department`);
the detail lists the `templates[]` that compose it (`id`, `kind`, `name`,
`version`, `section`, `position`).

---

## 12. Intent, write — templates, bindings and baselines

Two **explicit-only** capabilities, in the same model as §6: an empty
capability list authorises none of this, and the caller never picks its own
privilege.

| Capability | What it allows |
|---|---|
| `template_draft` | Create a template or a new version of one, delete an unlocked version, bind or unbind a device, author baselines. **Never touches an appliance.** The owner must hold `operations.template_save`. |
| `template_apply` | Approve, reject or revoke a template (owner must hold `operations.template_approve`, an administrator permission) and **push** a template to devices (owner must hold `operations.template_apply`). |

A token bound to one product may hold them for that product only; a
`global` token for every product. Every call is audited with the token's
public id, and the records it creates carry `api:<public_id>` as author or
reviewer. The write endpoints are rate-limited to 30/min; `apply` to 10/min.

### `POST /templates`

```json
{"kind": "web-protection-profile", "name": "api-wpp", "body": {...},
 "note": "", "exceptions": null, "source_firmware": "7.6.8"}
```

Creates a **pending** draft of the token's ADOM (`201`), or — when the
kind/name already exists — the next version of that family. `body` must be
a JSON object; an unknown kind, a missing name or an unknown build is `400
bad_request`. `source_firmware` is optional: it records the build the body
was written for, which is what lets a later build be *compared* against it.

### `PUT /templates/<id>`

Versions are immutable, as in the console: this saves a **new version** of
the same family (`body`, `note`, `exceptions`; fields absent keep the
predecessor's), pending, with the predecessor's build stamp. The answer is
the new version.

### `DELETE /templates/<id>`

Deletes one version. A locked (curated) template is `409 locked`.

### `POST /templates/<id>/approve` · `/reject` · `/unapprove`

The review lifecycle. Approval is the four-eyes rule of the console: the
token that authored the template may not approve it (`409 review_refused`).
`reject` takes `{"reason": "..."}`. Every verdict lands in the template's
review history with the token as reviewer.

### `POST /templates/<id>/apply`

```json
{"appliance_ids": [12, 13], "confirm": false, "override_reason": ""}
```

This is the console's own path and nothing else:

* **Without `confirm`** (or with anything but the boolean `true`): a
  **preview** — the per-device plan, the firmware-compatibility verdicts and
  any unresolved `{{ variable }}` — and **no device is contacted for real**.
* **With `confirm: true`**: the same gates run (unresolved variables and a
  refused firmware check are `409 apply_refused`, with the console's
  `compat` report), then the apply starts as the **background job** the
  console starts: canary device first, the rest only if the canary succeeds.
  The answer is `202 {"mode": "apply", "job_id": ...}`; the job's progress
  and its completion audit row are the console's. `override_reason` is
  honoured only for an owner holding `operations.template_approve`, exactly
  like the console's override.
* More than one device is a **fleet rollout**: the template must be
  approved (`409 apply_refused`) and the owner must hold `operations.apply`
  (`403 owner_forbidden`).
* An appliance outside the token's ADOM is `404 not_found` for the whole
  call.

There is no endpoint that writes a template to a device directly, and
`apply` never bypasses the dry-run → canary order.

### `POST /bindings` · `DELETE /bindings/<id>`

```json
{"template_id": 7, "appliance_id": 12, "pinned_version": null,
 "variables": {"hostname": "app.example"}, "note": ""}
```

Creates or updates the binding of a device to the template's family.
Desired state only: nothing is pushed. A device of another product
(`400 bad_request`: a FortiWeb template cannot govern a FortiADC) or a pinned
version that does not exist is refused. Deleting a binding leaves the device
as it is.

### `POST /baselines` · `PUT /baselines/<id>` · `DELETE /baselines/<id>`

```json
{"name": "zone-a", "zone": "A", "line": "", "department": "",
 "template_ids": [7, 9], "note": ""}
```

Only **approved** templates of the token's ADOM can compose a baseline
(`400 bad_request` otherwise). `PUT` changes the fields present and keeps
the others. Deleting a baseline leaves its templates untouched.

### Additional error codes

| HTTP | `error` | When |
|---|---|---|
| 403 | `owner_forbidden` | The owner lacks the permission the call needs (`operations.view`, `operations.template_save`, `operations.template_approve`, `operations.template_apply`, `operations.apply`) |
| 409 | `locked` | The template is locked (curated) and cannot be deleted |
| 409 | `review_refused` | The authoring token tried to approve its own template |
| 409 | `apply_refused` | Unresolved variables, an unapproved template for a fleet rollout, or the firmware-compatibility gate refused |

---

## 13. Observability — configuration history, findings, metrics

In the vocabulary of the NAF Framework this is the **Observability** block:
what SATOM has **recorded** about the estate. SATOM calls the configuration
history its *Source of Truth*; it is the history of the **actual** state of
every device. Everything here is read-only and needs the `read` scope.

### `GET /appliances/<id>/config-history`

The recorded configuration versions of one device, newest first (`?limit=`,
default 30, at most 200). A version is identified by its `sha256`: an
unchanged configuration records no new version, so the list is the list of
*changes*. Each row: `id`, `sha256`, `taken_at`, `last_seen_at`, `size_raw`,
`size_gz`, `total_objects`, `section_count`, `source`, and whether the
payload was `evacuated` to the backup server. Device secrets were stripped
when the version was recorded.

### `GET /appliances/<id>/config-diff?from=<ref>&to=<ref>`

What changed between two versions of the same device (`from` and `to` are
version ids or `sha256` hashes from `config-history`; a version of another
device is `404 not_found`). The answer lists `added[]`, `removed[]` and
`changed[]` object paths (`section/endpoint/key`), `changed_detail[]` with
per-field before/after for the first changed objects, `identical`, and
`truncated` when the lists were capped. A version whose payload is no longer
available is `410 blob_missing`.

### `GET /findings`

What the alert engine finds **right now**: every enabled check is evaluated
on the call (the same evaluation as *Settings → Alerts → Preview*), so the
call costs a check cycle and is rate-limited to 6/min. Each finding: `key`,
`family`, `severity` (`critical` / `warning` / `info`), `title`, `detail`
and, for a device finding, `product`. A token bound to a product receives
that product's findings only; the installation's own (certificates, host,
backups, code) need a `global` token. A token restricted to named
capabilities must hold `findings` (`403 capability_denied`).

### `GET /metrics/query?expr=…`

A read-only **MetricsQL** query over SATOM's metrics store. Instant query by
default; a range query with `start` and `end` (unix seconds, at most 90 days
apart) and `step` (`60s`, `5m`, `1h`…; default `60s`). The answer is the
store's own (`status`, `data.resultType`, `data.result`).

* Only SATOM's **own series** (`satom_*`) may be read. An expression naming
  any other series is `400 bad_request` and never reaches the store; so is an
  expression that names no series at all.
* The store answers within **10 s** or the call is `504 store_timeout`; a
  store error is `502 store_unavailable`. Never an empty `200`.
* A token bound to a product receives only the series labelled with its own
  devices (`device` / `kind`); the SATOM nodes' own readings and other
  products' devices are filtered out of the answer. A `global` token
  receives everything.
* The store itself stays on loopback with no account of its own; this route
  is the only way in from outside. A token restricted to named capabilities
  must hold `metrics`.

```bash
curl -s -H "Authorization: Bearer $TOKEN" --get \
  --data-urlencode 'expr=max by (device) (satom_box_cpu_pct)' \
  https://<your-satom-host>/api/v1/metrics/query
```

### Additional error codes

| HTTP | `error` | When |
|---|---|---|
| 410 | `blob_missing` | A version's payload is no longer available (pruned and not on the backup server) |
| 502 | `store_unavailable` | The metrics store answered an error |
| 504 | `store_timeout` | The metrics store did not answer within 10 s |

---

## 14. Processes — `/api/v1/processes/*`

Walk a **Process** (Administrator → Process: a diagram of checks, gates and
actions SATOM walks and judges) from outside, and read what a walk did. This is
the NAF Orchestrator's "startable by a machine" door, and it is as narrow as
the Run button.

**Access.** `read` lists and reads; `write` walks. The token's ADOM sees
exactly the processes the console would show it (a process is offered per
ADOM; a `global` token sees every one, drafts included). **A walk from the API
is a rehearsal by default**: every write step dry-runs and the run says so.
`"armed": true` additionally needs the explicit **`process_arm`** capability on
the token — tokens minted before this surface existed can rehearse and cannot
write. Rate-limited to 30/min like the other write endpoints.

### `GET /processes` / `GET /processes/<id>`

```json
{"processes": [
  {"id": 3, "key": "dr-failover-check", "name": "DR failover check",
   "products": ["fortiweb"], "enabled": true,
   "needs_appliance": true, "writes": true, "steps": 7,
   "trigger_event": "alert.fired",
   "trigger_filter": {"families": ["device"], "min_severity": "critical"},
   "armed_on_trigger": false, "trigger_rate_limit": 10,
   "updated_at": "2026-10-21T02:10:00"}]}
```

`GET /processes/<id>` adds `"graph"` (the nodes and arrows, as the editor
stores them).

### `POST /processes/<id>/run`

Body: `{"appliance_id": 7, "armed": false}` — both optional. `appliance_id` is
required when `needs_appliance` is true (400 `appliance_required`). The walk
runs inline and the answer is the finished run (or the run parked on a manual
gate — `status: "waiting"`, `waiting_node`), with its steps:

```json
{"id": 41, "process_key": "dr-failover-check", "appliance": "fw-dmz-02",
 "armed": false, "status": "done", "verdict": "ok",
 "summary": "5 step(s) ran and every one of them passed.",
 "trigger": "api", "trigger_key": "api-token:1f3a…", "started_by": "svc-noc",
 "counts": {"pass": 5, "fail": 0, "unknown": 0, "skipped": 0},
 "steps": [{"seq": 1, "key": "start", "kind": "start", "status": "pass",
            "detail": "process entered", "dry_run": false, "undo_recorded": false}, …]}
```

Arming a diagram that only reads is dropped silently, as on the Run button.
A disabled process answers 409 `disabled`; a diagram the editor would refuse
to run answers 400 `invalid_diagram` with the problems listed.

### `GET /process-runs/<id>`

The same document, for polling. A run whose process has been deleted is shown
to a `global` token only — the console applies the same rule.

```sh
# rehearse, then arm once the rehearsal is clean
curl -s -X POST -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d '{"appliance_id": 7}' https://<your-satom-host>/api/v1/processes/3/run
curl -s -X POST -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d '{"appliance_id": 7, "armed": true}' https://<your-satom-host>/api/v1/processes/3/run
#  -> 403 capability_denied unless the token holds process_arm
```

## 15. Events and triggers — `/api/v1/events`, `/api/v1/triggers`

An outside system (monitoring, CI, ticketing) starts SATOM's automations by
posting an event. Every enabled trigger on `api.event` whose conditions match
it (Administrator → Triggers) starts its automations (Automations → On a
trigger), as jobs; the call answers at once with what was queued and never
waits for a walk. The match is recorded like any other, with the token's id.

### `POST /events`

Scope `write`. Body:

```json
{"type": "deploy.done", "subject": "build-42", "appliance_id": 3,
 "data": {"service": "shop"}}
```

`type` is required (at most 120 characters); `subject` is what the trigger's
cooldown is counted on (`""` = the type); `data` is any JSON object up to
32 000 bytes. The event's ADOM is the token's; a Global token may name one in
`product`. Nothing the caller sends arms an automation: armed or not is set on
the automation, in the console. Answers `202`:

```json
{"event": "api.event", "type": "deploy.done", "matched": 1, "queued": 1,
 "rows": [{"trigger": "ci-deploy", "automation": "validate-shop",
           "status": "queued", "job_id": "…", "run_id": 17, "reason": ""}]}
```

`status` is `queued`, `suppressed` (cooldown, hourly budget or chain depth —
`reason` says which) or `error`. `400` for a body that is not an object, a
missing `type`, `data` that is not an object or is too large, or an unknown
`product`.

### `GET /triggers`

Scope `read`. Every trigger: `key`, `name`, `event`, `enabled`, `conditions`,
`cooldown_minutes`, `rate_limit_per_hour` and the keys of its enabled
`automations` — so a caller can see which `type` values anything listens to.

