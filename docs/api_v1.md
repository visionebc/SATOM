# API v1 — Integration Manual

The **OFortMAuT** exposes a small, versioned, **token-authenticated**
HTTP API at `/api/v1` for third-party integrations and automation.

- **Base URL:** `https://ofortmaut.example.net/api/v1`
- **Auth:** every request carries `Authorization: Bearer <token>`
- **Format:** JSON in, JSON out (always — even on errors)

This surface is **deliberately narrow and read-biased**. It cannot upgrade,
flash or reboot a device, and it cannot run any action flagged *destructive* —
no token, of any scope, can reach those. Mutations happen only through
pre-created **Scheduled Actions** that you trigger by id.

---

## 1. Getting a token

Tokens are issued by an administrator in the app (**API Tokens** section). You
**cannot** self-serve one from this page — ask an admin. When a token is created
you receive the plaintext **once**; it is stored only as a hash and can never be
shown again. A token looks like:

```
fmk_<public_id>_<secret>
```

Each token has three chained limits you should understand before you rely on it:

| Limit | Meaning |
|---|---|
| **Scope** | `read` ⊂ `write` ⊂ `admin`. Triggering an action needs `write`. |
| **Owner-capped** | The token never exceeds its owner's role. If the owner lacks `config_write`, the token's `write` scope does nothing. Disable the owner → the token dies with them. |
| **Product (ADOM)** | The token is bound to `fortiweb`, `fortiadc` or `global` and acts only on that product. |

> A `write` token is **not** scoped to a single action or a single device — it
> can run *any* non-destructive action enabled in its ADOM. Treat it as a
> credential for all non-destructive automation of that product.

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

| Method | Path | Scope | Purpose |
|---|---|---|---|
| `GET`  | `/ping` | read | Identity of the token (owner, scopes, product) |
| `GET`  | `/appliances` | read | Device inventory + cached status |
| `GET`  | `/appliances/<id>` | read | One device |
| `GET`  | `/actions` | read | Scheduled actions visible to the token |
| `POST` | `/actions/<id>/run` | write | Trigger a **non-destructive** action |
| `GET`  | `/actions/runs/<run_id>` | read | Poll the outcome of a run |

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
  "maintenance": false
}
```

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
BASE="https://ofortmaut.example.net/api/v1"

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

Every authenticated call and every run is **audited** (who, when, which token).

---

*This manual is generated from the live route definitions. Endpoints, scopes and
response shapes reflect the running version of the API.*
