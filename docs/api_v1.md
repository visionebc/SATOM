# API v1 — Integration Manual

The **SATOM** exposes a small, versioned, **token-authenticated**
HTTP API at `/api/v1` for third-party integrations and automation.

- **Base URL:** `https://satom.example.net/api/v1`
- **Auth:** every request carries `Authorization: Bearer <token>`
- **Format:** JSON in, JSON out (always — even on errors)

This surface is **deliberately narrow**. It cannot upgrade, flash or reboot a
device, and it cannot run any action flagged *destructive* — no token, of any
scope, can reach those.

There are exactly **two** ways to change anything, and they are not
interchangeable:

1. **Scheduled Actions** (§3) — operational moves an operator pre-created for
   you. You trigger one *by id*; you cannot alter the parameters it was saved
   with.
2. **Object authoring** (§6 FortiWeb, §7 FortiADC) — you write your own WAF
   carve-out or FortiADC rule. Only a type on a **curated allow-list**, and only
   if an administrator granted your token the matching **capability**.

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

> A `write` token is **not** scoped to a single action or a single device — it
> can run *any* non-destructive action enabled in its ADOM. Treat it as a
> credential for all non-destructive automation of that product.

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
| `GET`  | `/waf/exception-types` | read | — | The allow-list of WAF carve-out types (§6) |
| `GET`  | `/waf/exceptions` | read | — | Carve-outs this token authored (`?all=1` needs `admin`) |
| `GET`  | `/waf/exceptions/<id>` | read | — | One carve-out |
| `POST` | `/waf/exceptions` | write | `waf_exception_draft` (+ `waf_exception_apply` for `"apply": true`) | File a WAF carve-out (§6) |
| `DELETE` | `/waf/exceptions/<id>` | write | `waf_exception_draft` | Withdraw one **you** authored, from desired state only (§6) |
| `GET`  | `/adc/rule-types` | read | — | The allow-list of FortiADC rule types (§7) |
| `GET`  | `/adc/rules` | read | — | FortiADC rules of a type, read from the appliance (§7) |
| `POST` | `/adc/rules` | write | `adc_rule_draft` (+ `adc_rule_apply` for `"apply": true`) | Create a FortiADC rule (§7) |

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
BASE="https://satom.example.net/api/v1"

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
| 409 | `disabled` | The action is disabled |
| 409 | `already_running` | The action is already running |
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
curl -sH "$AUTH" https://satom/api/v1/waf/exception-types | jq '.types[].key'

# 2. File one (draft — no device is touched)
curl -sX POST -H "$AUTH" -H 'Content-Type: application/json' \
  https://satom/api/v1/waf/exceptions -d '{
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

---

*This manual is hand-written, and that is exactly why it is pinned by a test.*
`tests/test_api_v1_manual.py` fails when a route, an object-write capability or
an error code exists in the code and not in this page — a manual that quietly
loses an endpoint looks identical to one that is complete, and a reader who
cannot find a capability concludes the product does not have it.*
