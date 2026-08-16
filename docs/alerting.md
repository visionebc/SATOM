# Alerting and notification delivery

This document is the integration contract for everything SATOM emits when a
health check finds something. It exists because the delivery side of alerting
is where the expensive mistakes are silent ones: a filter that drops the wrong
finding, a signature a receiver rejects intermittently, a record with holes in
it. Every rule below is written down because getting it wrong produces
*silence*, and silence is indistinguishable from health.

The measurement side — what counts as bad, which thresholds, which checks —
is the health engine, and it is documented in the user guide. This document
starts at the moment a finding exists.

---

## 1. What a finding is

The engine produces findings. A finding is the unit everything downstream
routes, filters, throttles and formats.

| field | meaning |
|---|---|
| `key` | stable identity of the condition. The cooldown, and any dedupe on your side, key off this |
| `family` | derived from the key's prefix — never stored, never operator-editable |
| `severity` | `info`, `warning` or `critical` |
| `title` | one line, operator-facing |
| `detail` | the evidence |
| `product` | owning workspace, empty when the finding is fleet-wide |
| `node` | the node that evaluated it |

**The family is derived from the key prefix, and the two are not the same
string.** The engine emits `action.*` while the toggle, the settings key and
the label all say *actions*; those drifted apart years before the router
existed, and the map is explicit rather than clever:

| key prefix | family | settings label |
|---|---|---|
| `cert.` | `cert` | Cert expiry |
| `git.` | `git` | Git divergence |
| `device.` | `device` | Device health |
| `backup.` | `backup` | Backup freshness |
| `drift.` | `drift` | Config drift |
| `action.` | `actions` | Scheduled automation |
| `host.` | `host` | Host resources |

Two families are **unfilterable** and no sink configuration can drop them:

- `engine` — the alert engine itself failed. A channel silenced by a crashed
  check looks exactly like a healthy quiet one, which is the failure alerting
  exists to prevent.
- `unknown` — a key prefix this router has never heard of. A check added in a
  later release must not be invisible until somebody remembers to widen a mask.

---

## 2. Two paths, not five destinations

The five sinks do **not** form one list. They form two paths with different
rules, and treating them as one list makes one of the two wrong by
construction.

| | notification path | feed path |
|---|---|---|
| sinks | in-app bell, e-mail, webhook, integration hooks | syslog / CEF |
| answers | "who should be told about this?" | "is this on the record?" |
| cooldown | **yes** — suppressed for the configured hours | **no** |
| runs on the read-only standby | no | **yes** |
| counted in `dispatched` | yes | no |

**Why the feed carries no cooldown.** A recipient does not want the same
message every three minutes; a *record* queried after the fact cannot have
six-hour holes in it, because a hole reads as "nothing was wrong". Correlation,
retention and audit all rest on the series being complete.

**Why the feed also runs on the standby.** The standby evaluates its own
findings and cannot write, so without the feed its findings never leave the
node at all.

**Why the feed is not counted in `dispatched`.** A healthy record must not be
able to make a dead mailbox look alive.

---

## 3. The router: a floor and a mask

Every sink has exactly two knobs and no more:

- **minimum severity** — `info`, `warning` or `critical`;
- **family mask** — the seven maskable families above.

| sink | key | default |
|---|---|---|
| In-app bell | `in_app` | on, `info`, unmasked |
| Email | `email` | on, `info`, unmasked |
| Webhook (HTTP POST) | `webhook` | off |
| Integration hooks | `hooks` | off |
| Syslog / CEF feed | `syslog` | off |

A pattern language was deliberately not built. The rule everybody actually
writes is "everything", which is the two knobs above with far more surface to
get wrong.

**A sink with no family ticked delivers nothing, and the page says so.** An
unticked mask and a never-configured one are different intentions; collapsing
them would deliver the exact opposite of what the screen shows.

**The shipped defaults reproduce the behaviour that existed before the router
did.** An upgrade that quietly narrowed a delivery path nobody asked to narrow
is indistinguishable, from the operator's chair, from the alerting having
broken.

---

## 4. Cooldown, and what is allowed to stamp it

The cooldown is stamped per finding key, and **only if something actually
happened with it**. Two sets are tracked separately because they answer
different questions:

| set | question | feeds |
|---|---|---|
| delivered | did this reach a person? | the `dispatched` count |
| queued | did this leave the process? | the cooldown, and only the cooldown |

Integration hooks are **enqueued, not delivered**: firing one writes a request
file that a separate systemd unit executes. Counting an enqueue as a delivery
is how a run reports `dispatched: 2` with nothing in anybody's inbox. Not
stamping it at all is the opposite failure: a chat hook re-sending every
finding every fifteen minutes, forever.

**The case that is hardest to see:** the hooks sink is enabled and *no hook is
bound to* `alert.fired`. The dispatch call returns an empty list and no error.
Stamping the cooldown there would silence the finding for six hours on behalf
of a subscriber that does not exist, so nothing is stamped and the run says so.

An escalation from `warning` to `critical` bypasses the cooldown. The condition
got worse, and that is new information.

---

## 5. Webhook

One HTTP POST per evaluation, carrying every finding that sink accepted — not
one call per finding.

### Headers

| header | value |
|---|---|
| `X-SATOM-Signature` | `v1=<hex>` — **absent** when no secret is configured |
| `X-SATOM-Timestamp` | Unix epoch seconds, the same value that is inside the signature |
| `X-SATOM-Delivery` | delivery id, **derived** from node + findings + timestamp |

The delivery id is derived rather than random on purpose: a random component
would make every retry look like a new event, which is the opposite of what a
deduplication id is for. Dedupe on it.

**No secret means no signature header — never an empty one.** A receiver whose
check is "did a signature arrive?" must not be able to receive a value that
passes that check and proves nothing.

### Body — the SATOM envelope (`satom`)

```json
{
  "version": 1,
  "source": "satom",
  "event": "alert",
  "id": "9f2c1a…",
  "node": "manager-a",
  "sent_at": "2026-08-16T18:40:00+00:00",
  "count": 2,
  "max_severity": "critical",
  "findings": [
    {
      "key": "cert.expiry.manager-a",
      "family": "cert",
      "severity": "critical",
      "title": "TLS certificate expires in 3 days",
      "detail": "CN=… expires 2026-08-19T09:00:00Z",
      "product": ""
    }
  ]
}
```

`version` is bumped only for a breaking change to the shape, so a receiver can
branch on it instead of guessing from which keys are present.

The second encoding, **Slack-compatible**, sends `{"text": "…"}` and suits
Slack, Mattermost and Rocket.Chat. Teams and Discord want their own shapes and
are integration hooks instead — see §7.

### Verifying the signature

The signed string is `v1:<epoch>:<body>`, over the **exact bytes on the
wire**. The timestamp is *inside* the signed string, not merely alongside it: a
signature over the body alone is valid forever, and a captured POST could be
replayed at any time with the receiver unable to notice. The `v1` scheme label
is inside it for the same reason — so a future `v2` cannot be replayed as a
`v1`.

```python
import hmac, hashlib, time

def verify(raw_body: bytes, headers, secret: str, tolerance: int = 300) -> bool:
    sig = headers.get("X-SATOM-Signature", "")
    ts = headers.get("X-SATOM-Timestamp", "")
    if not sig.startswith("v1=") or not ts.isdigit():
        return False
    if abs(time.time() - int(ts)) > tolerance:      # replay window
        return False
    expected = hmac.new(
        secret.encode(), b"v1:%d:" % int(ts) + raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(sig[3:], expected)   # constant time
```

Verify against the **raw request body**, before any JSON parsing. Re-serialising
and hashing that is how a receiver ends up rejecting legitimate deliveries
intermittently, whenever key order or separators differ. SATOM serialises once
for the same reason: the bytes that are signed are the bytes that are sent.

### Retries

| status | behaviour |
|---|---|
| `2xx` | delivered |
| `408`, `425`, `429`, `500`, `502`, `503`, `504` | retried, bounded backoff (1 s, 3 s, 7 s) |
| any other `4xx` | **fails once**, reports the status, does not retry |
| transport error (DNS, TCP, TLS, timeout) | retried |

A wrong URL or a rejected signature is not a transient condition, and the
operator needs to read *"your endpoint refused this"* rather than *"we tried
and gave up"*. Attempts and backoff are bounded because the sweep fires on a
short interval, and a sink that can outlive its own interval stacks runs.

The signing secret is stored encrypted and never rendered back to the page, so
a blank field on save means **unchanged**; removing one takes an explicit
checkbox.

---

## 6. Syslog and CEF feed

Transport is UDP or TCP, facility `local0`…`local7`, one line per finding.

### RFC 5424

```
<PRI>1 2026-08-16T18:40:00.123Z <node> SATOM <family> [satom@32473 key="…" severity="…" family="…" node="…"] <title> - <detail>
```

`MSGID` is the family: at most 32 printable ASCII characters, and the one field
a collector can filter on **without parsing structured data**. The private
enterprise number in the SD-ID is composed at format time rather than written
as a literal.

### CEF

```
<PRI><Mon> <D> <HH:MM:SS> <node> CEF:0|Vision EBC|SATOM|<version>|<key>|<title>|<sev>|rt=<epoch_ms> dvchost=<node> cat=<family> msg=<detail>
```

| SATOM severity | syslog severity | CEF severity |
|---|---|---|
| `critical` | 3 | 9 |
| `warning` | 4 | 6 |
| `info` | 6 | 3 |

**The timezone trap, and why the header carries local time.** CEF rides on an
RFC 3164 header, and that header has **no timezone field**. A collector reads
it as the sender's local time. Emitting UTC therefore files every event at the
wrong hour — silently, correctly-formed, and only on installs that are not on
UTC. The header is written in the node's local time, and `rt=` carries
unambiguous epoch milliseconds for any collector that would rather be told than
assume.

This was found by reading bytes off a real socket. No unit test could see it:
the event was well-formed, and the defect lived in what a *receiver* would
conclude.

---

## 7. Integration hooks and `alert.fired`

A hook is a small Python script SATOM runs when it emits an event; the sandbox,
the secret store and the runner are documented in the user guide. Alerting adds
one event to that catalog.

`alert.fired` fires **once per finding**, only for findings fresh out of the
cooldown window, and **only from the writable primary**.

| field | meaning |
|---|---|
| `key` | stable identity — dedupe on this |
| `family` | `cert` · `git` · `device` · `backup` · `drift` · `actions` · `host` · `engine` · `unknown` |
| `severity` | `info` · `warning` · `critical` |
| `title` | one line, operator-facing |
| `detail` | the evidence |
| `product` | owning workspace, `''` when fleet-wide |
| `node` | the node that evaluated it |
| `fired_at` | ISO-8601 |

### Starters

**Starters, not vendor adapters.** Teams wants an Adaptive Card inside an
`attachments` envelope, Discord wants `content`, Opsgenie wants its own schema.
One adapter per vendor is unbounded work whose failure mode is a stale
integration nobody notices. A starter is the opposite bargain: a working
example that becomes **yours** the moment you save it.

| starter | event | declared secret |
|---|---|---|
| CRM change ticket | `change.requested` | `CRM_TOKEN` |
| Telegram | `alert.fired` | `TELEGRAM_BOT_TOKEN` |
| Slack | `alert.fired` | `SLACK_WEBHOOK_URL` |
| Microsoft Teams | `alert.fired` | `TEAMS_WEBHOOK_URL` |

Pick one from **Settings → Integrations → New hook**; it preselects the event
and lists the secret to declare.

Each starter encodes the part that is expensive to discover:

- **Teams** — the Adaptive Card must be wrapped in an `attachments` envelope.
  A bare card returns `202` and publishes nothing.
- **Telegram** — no `parse_mode`. A finding's detail is full of `_`, `*` and
  `[`, and Telegram answers `400` on unbalanced markup: the message simply
  disappears.
- **All three** — a non-2xx is reported through `ctx.result(...)`, never
  swallowed.

Starters are checked as code, not as prose: they must compile, define `run`,
declare every secret they read, and **every payload key they touch is checked
against the real `alert.fired` payload rather than against documentation**.

> **HA:** `satom-integrations.path` must be enabled on **both** nodes. A
> standby whose watcher is disabled accepts queued work and never runs it,
> silently.

---

## 8. Not implemented, and said so on the page

| | status |
|---|---|
| Syslog over TLS | not implemented — UDP and TCP only |
| LEEF encoding | not implemented — RFC 5424 and CEF only |
| Per-recipient routing (this person gets `cert`, that one gets `device`) | not implemented — the mask is per sink |
| Webhook adapters for Teams / Discord / Opsgenie | deliberately not shipped — see the starters above |

A capability that is absent is written down as absent. An operator planning a
SIEM integration needs to learn that TLS transport does not exist **before**
the change window, not during it.

---

## 9. Proving a delivery path works

In order of how much they prove, and none of them send mail behind your back:

1. **Preview now (no send)** — Settings → Email & Alerts. It evaluates every
   enabled check and reports what *would* fire, the resolved recipient list, a
   count **per sink**, and for each individual finding the list of sinks that
   would accept it. Nothing is sent. A finding that every sink drops is the one
   thing a plain list of findings cannot show you, which is why the per-sink
   counts are there. This is the right first move when a device is red and no
   mail arrived.
2. **The webhook card renders the exact sample payload** your endpoint will
   receive, in the encoding currently selected. Point your receiver's verifier
   at that shape before you enable the sink.
3. **Dry run** on an integration hook queues it against the event's sample
   payload through the same runner. It reports *queued*, not *ran*, because
   that is what happened; the outcome appears in the runs table a moment later.
   A dry run will queue a hook that is switched off — testing before enabling
   is the point.
4. **Send test e-mail** on the Email tab uses the *saved* settings — save
   first, then test. It exercises SMTP, not the router: a test mail proves the
   transport, not that any finding would ever reach the sink.

There is no per-sink "send a test alert" button. The preview above answers the
question a test delivery would ask — *would this finding reach this sink* —
without putting a synthetic event into anybody's record of what happened.

If a sink is on and nothing arrives, check in this order: the master alert
switch (the bell and the feed are the two that ignore it), the sink's minimum
severity, the sink's family mask — an empty mask delivers nothing — and then
the cooldown, which suppresses a key that already got through.
