"""Generic outbound webhook sink for the alert engine.

Why this is a first-class sink and not a hook
---------------------------------------------
:mod:`app.services.integration_hooks` can already run operator-written Python
against an event, and entrega ③ puts ``alert.fired`` in that catalogue.  So why
does an HTTP POST need product code at all?

Because three things in it are *ours*, not the integrator's:

* **The framing.** A stable, versioned envelope that a receiver can parse next
  year is a promise the product makes.  Five operators hand-rolling five JSON
  shapes is five contracts nobody documented.
* **The signature.** HMAC over the exact bytes on the wire, with the timestamp
  inside the signed string.  Every hand-rolled version of this gets replay
  wrong — it signs the body only, so a captured POST stays valid forever.
* **The retry policy.** Which failures are worth repeating is a judgement about
  HTTP, not about the operator's receiver.  Retrying a 400 is a hammer; not
  retrying a 502 loses the alert.

What is deliberately NOT here: an adapter per chat product.  Teams' Workflows
connector wants an Adaptive Card and Discord wants ``content``; maintaining one
of those per vendor is unbounded.  Two encodings ship — the SATOM envelope and
the flat ``{"text": ...}`` that Slack incoming webhooks, Mattermost and
Rocket.Chat all accept — and anything shaped differently is a hook.

This sink notifies a *person*
-----------------------------
Unlike :mod:`app.services.alert_syslog`, the webhook is on the notification
path: it carries the cooldown and it counts towards ``dispatched``.  A chat
channel is a recipient, not a record, and a recipient that gets the same
finding every fifteen minutes for six hours is a recipient that mutes the
channel.

One POST per evaluation, not one per finding
--------------------------------------------
The whole point of the router is that a channel stops being a hose.  Twelve
separate POSTs for one evaluation puts the hose back with extra steps.  Batch
delivery makes it all-or-nothing, exactly like email — and that is what
``delivered`` already models.

SSRF: the private network is the expected target
------------------------------------------------
The URL is admin-supplied and this process fetches it.  The scheme is checked
(``http``/``https`` only — ``file://`` is not a webhook), but RFC 1918 targets
are **allowed on purpose**: an n8n at ``10.0.0.x`` or a FortiSOAR on the
management LAN is the normal case in every install this ships to.  A blocklist
that broke the primary use case to defend against an actor who already holds
the admin console would be theatre.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from ..models import AppSetting
from . import alert_routing as routing

# ---- settings keys --------------------------------------------------------
K_URL = "alerts.webhook.url"
K_FORMAT = "alerts.webhook.format"      # "satom" | "slack"
K_TIMEOUT = "alerts.webhook.timeout"    # seconds, per attempt
K_RETRIES = "alerts.webhook.retries"    # extra attempts after the first
K_SECRET = "alerts.webhook.secret"      # Fernet-encrypted at rest

FORMATS = ("satom", "slack")
FORMAT_LABELS = {
    "satom": "SATOM envelope (JSON)",
    "slack": "Slack-compatible ({\"text\": ...})",
}

#: Envelope version.  Bumped only for a breaking change to the shape, so a
#: receiver can branch on it instead of guessing from which keys are present.
ENVELOPE_VERSION = 1

SIG_HEADER = "X-SATOM-Signature"
TS_HEADER = "X-SATOM-Timestamp"
ID_HEADER = "X-SATOM-Delivery"
#: Signature scheme label.  It is inside the signed string as well as in the
#: header value, so a future v2 cannot be replayed as a v1 by a verifier that
#: only looks at the hex.
SIG_SCHEME = "v1"

TIMEOUT_MIN, TIMEOUT_MAX, TIMEOUT_DEFAULT = 1, 30, 10
RETRIES_MIN, RETRIES_MAX, RETRIES_DEFAULT = 0, 3, 2

#: Backoff before attempt N+1, in seconds.  Short and finite: the alert timer
#: fires every 15 minutes and a sink that can outlive its own interval stacks
#: runs.  Worst case here is 3 * TIMEOUT_MAX + 1 + 3 + 7 = 101s.
_BACKOFF = (1, 3, 7)

#: HTTP statuses worth repeating.  Everything else in 4xx is the request being
#: wrong — a bad URL, a revoked token, a payload the receiver rejects — and
#: repeating it neither fixes it nor tells anyone.  It fails once, visibly.
RETRY_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})


def _get(key: str, default: str = "") -> str:
    val = AppSetting.get(key)
    return (val if val is not None else default) or ""


def _int(key: str, default: int, lo: int, hi: int) -> int:
    try:
        n = int(_get(key) or default)
    except (TypeError, ValueError):
        n = default
    return max(lo, min(hi, n))


# ---- secret ---------------------------------------------------------------
def secret() -> str:
    """The shared HMAC secret, decrypted, or ``""`` if unset.

    A vault that cannot be read is treated as no secret rather than raising:
    the alternative is that a rotated Fernet key stops alert delivery
    entirely, which trades a signature for the alerts themselves.
    """
    raw = _get(K_SECRET)
    if not raw:
        return ""
    try:
        from .encryption import decrypt
        return decrypt(raw) or ""
    except Exception:  # noqa: BLE001 — an unreadable vault is not a secret
        return ""


def set_secret(value: str) -> None:
    from .encryption import encrypt
    AppSetting.set(K_SECRET, encrypt(value) if value else "")


# ---- config ---------------------------------------------------------------
def url_problem(url: str) -> str:
    """Why this URL is unusable, or ``""``.

    Returned as a message rather than enforced at save time on purpose: a
    rejected value that silently vanishes from the form reads as "the save
    button did nothing".  Stored-and-flagged is visible and fixable.
    """
    u = (url or "").strip()
    if not u:
        return ""
    parts = urlsplit(u)
    if parts.scheme not in ("http", "https"):
        return "URL must start with http:// or https://"
    if not parts.netloc:
        return "URL has no host"
    return ""


def config() -> dict:
    """Render-ready config.  **Never carries the secret** — only whether one
    is set.  The template renders this dict into HTML; a secret that reaches a
    page reaches every screenshot, cache and proxy log of that page."""
    url = _get(K_URL)
    return {
        "url": url,
        "url_problem": url_problem(url),
        "format": _get(K_FORMAT) if _get(K_FORMAT) in FORMATS else "satom",
        "timeout": _int(K_TIMEOUT, TIMEOUT_DEFAULT, TIMEOUT_MIN, TIMEOUT_MAX),
        "retries": _int(K_RETRIES, RETRIES_DEFAULT, RETRIES_MIN, RETRIES_MAX),
        "secret_set": bool(secret()),
        "signature_header": SIG_HEADER,
        "timestamp_header": TS_HEADER,
    }


def save(form) -> None:
    """Persist the webhook config from the alert settings form."""
    def g(key, default=""):
        try:
            return (form.get(key, default) or "").strip()
        except AttributeError:
            return str(form.get(key, default) or "").strip()

    AppSetting.set(K_URL, g("webhook_url"))

    fmt = g("webhook_format")
    AppSetting.set(K_FORMAT, fmt if fmt in FORMATS else "satom")

    def clamp(name, lo, hi, default):
        try:
            n = int(g(name) or default)
        except ValueError:
            n = default
        return str(max(lo, min(hi, n)))

    AppSetting.set(K_TIMEOUT, clamp("webhook_timeout", TIMEOUT_MIN,
                                    TIMEOUT_MAX, TIMEOUT_DEFAULT))
    AppSetting.set(K_RETRIES, clamp("webhook_retries", RETRIES_MIN,
                                    RETRIES_MAX, RETRIES_DEFAULT))

    # The secret is never rendered back into the form, so a blank field means
    # "unchanged", not "delete".  Deleting therefore needs its own explicit
    # control — without it there is no way to remove a secret short of SQL.
    if form.get("webhook_secret_clear") in ("on", "1", "true", "True", True):
        set_secret("")
    else:
        typed = g("webhook_secret")
        if typed:
            set_secret(typed)


# ---- payload --------------------------------------------------------------
def _iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_SEV_RANK = {"info": 0, "warning": 1, "critical": 2}


def _max_severity(findings: list) -> str:
    best = "info"
    for f in findings:
        sev = f.get("severity", "info")
        if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(best, 0):
            best = sev
    return best


def delivery_id(node: str, findings: list, ts: datetime) -> str:
    """A stable id for one delivery, so a receiver can dedupe a retry.

    Derived from the node, the minute and the finding keys — a retry of the
    same batch produces the same id, while the next evaluation does not.  The
    id must NOT include a random component: that is exactly what would make a
    duplicate POST look like a new event to the receiver.
    """
    keys = ",".join(sorted(str(f.get("key", "")) for f in findings))
    digest = hashlib.sha256(
        ("%s|%s|%s" % (node, ts.strftime("%Y%m%d%H%M"), keys)).encode("utf-8")
    ).hexdigest()[:16]
    return "%s-%s" % (node or "satom", digest)


def _finding_json(f: dict) -> dict:
    return {
        "key": f.get("key", ""),
        "family": routing.family_of(f.get("key", "")),
        "severity": f.get("severity", "info"),
        "title": f.get("title", ""),
        "detail": f.get("detail", ""),
        "product": f.get("product") or "",
    }


def envelope(findings: list, node: str, ts: datetime, did: str) -> dict:
    return {
        "version": ENVELOPE_VERSION,
        "source": "satom",
        "event": "alert",
        "id": did,
        "node": node or "",
        "sent_at": _iso(ts),
        "count": len(findings),
        "max_severity": _max_severity(findings),
        "findings": [_finding_json(f) for f in findings],
    }


def _slack_text(findings: list, node: str) -> str:
    head = "*SATOM %s* — %d alert(s), max severity `%s`" % (
        node or "?", len(findings), _max_severity(findings))
    lines = [head]
    for f in findings:
        lines.append("• `%s` *%s* — %s" % (
            f.get("severity", "info"), f.get("title", ""),
            (f.get("detail", "") or "").replace("\n", " ")[:300]))
    return "\n".join(lines)


def build_body(findings: list, cfg: dict, node: str, ts: datetime,
               did: str) -> bytes:
    """The exact bytes that go on the wire — and the exact bytes that get
    signed.  Serialising once is not a micro-optimisation: signing one dump
    and sending another means any key-order or separator difference produces a
    signature the receiver correctly rejects, intermittently."""
    if cfg.get("format") == "slack":
        doc = {"text": _slack_text(findings, node)}
    else:
        doc = envelope(findings, node, ts, did)
    return json.dumps(doc, ensure_ascii=False, sort_keys=False,
                      separators=(",", ":")).encode("utf-8")


def sign(body: bytes, ts_epoch: int, key: str) -> str:
    """``v1=<hex>`` over ``v1:<epoch>:<body>``.

    The timestamp is inside the signed string, not merely alongside it.  A
    signature over the body alone is valid forever, so a captured POST can be
    replayed at any time and still verify — the receiver has no way to notice.
    """
    mac = hmac.new(key.encode("utf-8"),
                   b"%s:%d:" % (SIG_SCHEME.encode("ascii"), ts_epoch) + body,
                   hashlib.sha256)
    return "%s=%s" % (SIG_SCHEME, mac.hexdigest())


def headers_for(body: bytes, ts: datetime, did: str, key: str) -> dict:
    ts_epoch = int(ts.timestamp())
    h = {
        "Content-Type": "application/json",
        "User-Agent": "SATOM-Alerts/%d" % ENVELOPE_VERSION,
        TS_HEADER: str(ts_epoch),
        ID_HEADER: did,
    }
    # No secret means NO signature header, never an empty or unkeyed one: a
    # receiver whose check is "is a signature present" must not be handed a
    # value that passes that check and proves nothing.
    if key:
        h[SIG_HEADER] = sign(body, ts_epoch, key)
    return h


# ---- delivery -------------------------------------------------------------
def _post(url: str, body: bytes, headers: dict, timeout: int, retries: int,
          sleep=time.sleep) -> dict:
    """POST with a bounded, selective retry.  Never raises."""
    import httpx  # lazy — keeps the import graph light for tests

    attempts = 0
    last = ""
    started = time.monotonic()
    for i in range(retries + 1):
        attempts = i + 1
        try:
            resp = httpx.post(url, content=body, headers=headers,
                              timeout=timeout, follow_redirects=False)
        except Exception as exc:  # noqa: BLE001 — transport errors are retryable
            last = "%s: %s" % (type(exc).__name__, exc)
        else:
            if 200 <= resp.status_code < 300:
                return {"ok": True, "sent": 1, "status": resp.status_code,
                        "attempts": attempts,
                        "elapsed_ms": int((time.monotonic() - started) * 1000)}
            last = "HTTP %d %s" % (
                resp.status_code, (resp.text or "")[:200].replace("\n", " "))
            if resp.status_code not in RETRY_STATUSES:
                # Permanent by construction: say so, so the operator reads
                # "your URL is wrong" instead of "it retried and gave up".
                return {"ok": False, "sent": 0, "status": resp.status_code,
                        "attempts": attempts, "retryable": False,
                        "detail": last,
                        "elapsed_ms": int((time.monotonic() - started) * 1000)}
        if i < retries:
            sleep(_BACKOFF[min(i, len(_BACKOFF) - 1)])
    return {"ok": False, "sent": 0, "attempts": attempts, "retryable": True,
            "detail": last or "no response",
            "elapsed_ms": int((time.monotonic() - started) * 1000)}


def emit(findings: list, node: str, *, dry_run: bool = False,
         now: datetime | None = None, sleep=time.sleep) -> dict | None:
    """Deliver every matching finding in ONE POST.

    Returns ``None`` when the sink is off, so a caller can tell "disabled"
    from "enabled and delivered nothing" — only the second is a problem.
    """
    if not routing.is_enabled(routing.SINK_WEBHOOK):
        return None
    cfg = config()
    selected = routing.route(findings, routing.SINK_WEBHOOK)
    if not cfg["url"]:
        return {"ok": False, "sent": 0, "matched": len(selected),
                "detail": "sink enabled but no endpoint URL configured"}
    if cfg["url_problem"]:
        return {"ok": False, "sent": 0, "matched": len(selected),
                "detail": cfg["url_problem"]}

    ts = now or datetime.now(timezone.utc)
    did = delivery_id(node, selected, ts)
    if not selected:
        return {"ok": True, "sent": 0, "matched": 0,
                "detail": "nothing matched this sink's filter"}

    body = build_body(selected, cfg, node, ts, did)
    headers = headers_for(body, ts, did, secret())
    if dry_run:
        return {"ok": True, "sent": 0, "matched": len(selected),
                "dry_run": True, "delivery_id": did,
                "signed": SIG_HEADER in headers,
                "sample": body.decode("utf-8", "replace")[:2000]}

    res = _post(cfg["url"], body, headers, cfg["timeout"], cfg["retries"],
                sleep=sleep)
    res["matched"] = len(selected)
    res["delivery_id"] = did
    res["signed"] = SIG_HEADER in headers
    return res


#: A worked example for the settings page. Built by calling the SAME builder
#: the wire uses, never by pasting a hand-written string: a documented shape
#: maintained separately from the code that emits it drifts, and the operator
#: only finds out when their verifier rejects a real delivery.
_SAMPLE_FINDINGS = [
    {"key": "cert.expiry.satom-node-1", "severity": "critical",
     "title": "TLS certificate expires in 3 days",
     "detail": "CN=satom-node-1.example.com expires 2026-08-16T09:00:00Z",
     "product": ""},
    {"key": "device.unreachable.fortiweb08", "severity": "warning",
     "title": "fortiweb08 is not answering",
     "detail": "3 consecutive probe failures", "product": "fortiweb"},
]


def sample_payload() -> str:
    """Pretty-printed example of the SATOM envelope, generated from the real
    builder so it cannot drift from what is actually sent."""
    ts = datetime(2026, 8, 13, 21, 40, tzinfo=timezone.utc)
    did = delivery_id("satom-node-1", _SAMPLE_FINDINGS, ts)
    return json.dumps(envelope(_SAMPLE_FINDINGS, "satom-node-1", ts, did),
                      ensure_ascii=False, indent=2)


__all__ = [
    "FORMATS", "FORMAT_LABELS", "ENVELOPE_VERSION", "RETRY_STATUSES",
    "sample_payload",
    "SIG_HEADER", "TS_HEADER", "ID_HEADER", "SIG_SCHEME",
    "config", "save", "emit", "envelope", "build_body", "sign",
    "headers_for", "delivery_id", "secret", "set_secret", "url_problem",
]
