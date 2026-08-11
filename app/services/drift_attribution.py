"""Who made this config change — SATOM, or somebody on the device?

The drift alert has always ended with the sentence *"If nobody edited it via
SATOM, a device-side (CLI/GUI) change has drifted from the baseline"*. That
sentence hands the operator a correlation SATOM had already done and thrown
away: on 2026-08-11 fortiweb08 drifted at 09:03 UTC and the cause was an
allow-method exception this product had inserted at 08:37 UTC, from Attack
Search, by ``admin``, recorded in ``audit_logs`` rows 1253-1256. The alert
still asked the reader to remember it.

Nothing was broken. No test failed. The console simply asserted something
weaker than what it knew — the same class as the four monitor defects fixed
that morning, and the reason this module exists.

The window
----------
A drift is bounded by two facts of the source-of-truth store, and the
content-addressed design is what makes the bound tight:

* the change is NOT in the previous version, which the harvest last CONFIRMED
  unchanged at ``prev.last_seen_at`` -- **not** ``prev.taken_at``. An unchanged
  device mints no row (``sot_store``), it advances ``last_seen_at`` instead, so
  for fortiweb08 the two differ by seven hours. Using ``taken_at`` would open a
  seven-hour window and let an unrelated morning write claim an evening drift.
* the change IS in the new version, harvested at ``new.taken_at``.

So the change happened inside ``[prev.last_seen_at, new.taken_at]`` and only a
SATOM write stamped inside that interval can explain it.

Known bound: the harvest reads the device some seconds before it stores the
snapshot. A write landing in that gap is inside the window but is reflected in
the NEXT version, so it can be credited with a drift it did not cause. The
race is as wide as one harvest and is documented rather than engineered
around.

The conservative direction
--------------------------
**When in doubt, do not count it as a receipt.** The two errors are not
symmetric: failing to attribute a real SATOM write leaves a WARNING that says
"nobody recorded a write" — noisy, and the operator finds the write in two
clicks. Wrongly attributing a device-side change to SATOM downgrades a genuine
drift to a nod of approval and buries the one alert that mattered. Every rule
below therefore requires positive evidence — an appliance id, a mutating verb,
an empty error field — and treats anything unparseable as "no receipt".

Why ``audit_logs`` and not ``change_history``
---------------------------------------------
``change_history`` is richer (before/after snapshots) but FortiWeb-only, and it
records failed writes indistinguishably from successful ones — it has no error
column, so a write the device REFUSED looks exactly like one it accepted. A
refused write changed nothing and must never explain a drift. ``audit_logs``
carries every product (``adc.*``, ``faz.*``, ``*_api.execute``), the acting
user, the real client IP, and — for the paths that can fail after logging —
the error, so it can answer the question this module asks.
"""
from __future__ import annotations

import ast
import re
from datetime import datetime

# Audit actions that mean "SATOM wrote to this device". Split by how the row
# names its appliance, because that was read off each call site rather than
# guessed:
#
#   _BY_ID     -- ``log_action(..., appliance_id=appliance.id)``; the id is
#                 authoritative and can never leak onto a neighbour.
#   _BY_TARGET -- ``target`` is ``appliance.name`` (optionally ``name:/path``);
#                 matched on the FIRST token only.
#
# Deliberately NOT here: ``provision.device.*``, ``template.apply*``,
# ``advisor.proposal_apply``, ``attack_search.exception_*`` and the rest of the
# high-level workflows. Every one of them reaches the device through
# ``fortiweb_ops``, which already emits ``config.*`` — counting the wrapper too
# would double-report, and counting a wrapper that DOESN'T reach the device
# would attribute a drift to a click that never left the node.
_BY_ID_PREFIXES = ("config.", "adc.", "faz.")
_BY_TARGET_EXACT = frozenset({
    "appliance.upgrade",
    "fac_api.execute", "faz_api.execute", "adc_api.execute",
})

# ``faz.device.authorize.failed`` is logged by the SAME helper as its success
# twin and would sail through the ``faz.`` prefix.
_FAILED_SUFFIX = ".failed"

_MUTATING = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# ``fortiweb_ops._record`` folds its status into one free-text detail string:
#   'mkey=am-exc dry_run=False error='
# so both facts must be read out of it. An unparseable detail is not a receipt.
_DRY_RE = re.compile(r"\bdry_run=(True|False)\b")
_ERR_RE = re.compile(r"\berror=(.*)$", re.S)

_TOKEN_RE = re.compile(r"[^A-Za-z0-9_.\-]+")


def _extra(raw) -> dict:
    """``audit_logs.extra`` is ``str(dict)`` — a Python repr, NOT JSON.

    ``json.loads`` fails on every row ever written (single quotes, ``True``),
    which would silently make every device look unattributed. ``literal_eval``
    is the matching reader and is safe on hostile input (it evaluates literals
    only).
    """
    if isinstance(raw, dict):
        return raw
    try:
        val = ast.literal_eval(str(raw or "{}"))
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        return {}
    return val if isinstance(val, dict) else {}


def _first_token(target: str) -> str:
    return _TOKEN_RE.split((target or "").strip(), maxsplit=1)[0]


def _is_write_action(action: str) -> bool:
    if not action or action.endswith(_FAILED_SUFFIX):
        return False
    return action in _BY_TARGET_EXACT or action.startswith(_BY_ID_PREFIXES)


def _matches_appliance(action: str, row, appliance) -> bool:
    if action in _BY_TARGET_EXACT:
        return _first_token(row.target or "") == appliance.name
    return _extra(row.extra).get("appliance_id") == appliance.id


def _succeeded(action: str, extra: dict) -> bool:
    """Positive evidence that the write reached the device and was accepted.

    Each branch was read off the call site:

    * ``config.*`` — ``fortiweb_ops._record`` logs BOTH previews and refusals,
      so the detail string is the only witness; an unreadable one is a no.
    * ``fac_api.execute`` / ``appliance.upgrade`` — logged even when the call
      errored, so the ``error`` key decides.
    * ``adc.*`` / ``faz.*`` / ``faz_api`` / ``adc_api`` — the call site returns
      502 *before* logging, so the row's existence IS the success.
    """
    if action.startswith("config."):
        detail = extra.get("detail")
        if not isinstance(detail, str):
            return False
        m = _DRY_RE.search(detail)
        if m is None or m.group(1) != "False":
            return False            # a preview never touched the device
        e = _ERR_RE.search(detail)
        return bool(e) and not e.group(1).strip()
    if extra.get("error"):
        return False
    if action == "appliance.upgrade" and extra.get("dry_run"):
        return False
    if action in ("fac_api.execute", "faz_api.execute", "adc_api.execute"):
        # The FAZ/ADC consoles log EVERY verb including GET; a read is not a
        # write, and treating one as a receipt would silence a real drift.
        return str(extra.get("method", "")).upper() in _MUTATING
    return True


def window(prev, new) -> tuple[datetime | None, datetime | None]:
    """The interval in which the change must have happened.

    ``last_seen_at`` is the left edge (see module docstring). ``max`` guards a
    legacy row whose ``last_seen_at`` predates its ``taken_at``; widening
    leftwards there would only invent attributions.
    """
    if prev is None or new is None:
        return None, None
    left = prev.last_seen_at or prev.taken_at
    if prev.taken_at and left and prev.taken_at > left:
        left = prev.taken_at
    return left, new.taken_at


def receipts(appliance, start, end) -> list[dict]:
    """Every recorded SATOM write to ``appliance`` inside ``[start, end]``."""
    from ..models import AuditLog

    if appliance is None or start is None or end is None or start > end:
        return []
    rows = (AuditLog.query
            .filter(AuditLog.timestamp >= start, AuditLog.timestamp <= end)
            .order_by(AuditLog.timestamp.asc())
            .all())
    out: list[dict] = []
    for r in rows:
        action = r.action or ""
        if not _is_write_action(action):
            continue
        if not _matches_appliance(action, r, appliance):
            continue
        extra = _extra(r.extra)
        if not _succeeded(action, extra):
            continue
        out.append({
            "at": r.timestamp,
            "username": r.username or "unknown",
            "ip": r.ip_address or "",
            "action": action,
            "target": r.target or "",
        })
    return out


def describe(rec: dict) -> str:
    at = rec.get("at")
    stamp = at.strftime("%Y-%m-%d %H:%M:%S") if isinstance(at, datetime) else "?"
    who = rec.get("username") or "unknown"
    if rec.get("ip"):
        who = f"{who} from {rec['ip']}"
    tail = f" {rec['target']}" if rec.get("target") else ""
    return f"{stamp} UTC  {who}  {rec.get('action', '?')}{tail}"


def attribute(appliance, prev, new) -> dict:
    """``{start, end, receipts}`` — the evidence the alert renders.

    Never raises: a broken audit read degrades to "unattributed", which is the
    louder of the two outcomes and therefore the safe one.
    """
    start, end = window(prev, new)
    try:
        found = receipts(appliance, start, end)
    except Exception:  # noqa: BLE001 — attribution never sinks the drift alert
        found = []
    return {"start": start, "end": end, "receipts": found}


__all__ = ["attribute", "receipts", "window", "describe"]
