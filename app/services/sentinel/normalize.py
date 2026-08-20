"""Device record → :class:`SentinelEvent`. One shape, whatever the transport.

Field names here are the ones a FortiWeb 7.6.8 attack-log row actually carries
(``rel_time``, ``main_type``, ``sub_type``, ``srccountry``, ``http_url``,
``signature_cve_id`` …), taken from :mod:`app.services.attack_log`, which
recovered them from the appliance's own GUI bundle rather than from
documentation. That provenance matters: the documented REST surface for this
product has 22 routes that answer ``-20001 invalid URL``, so "the manual says
this field exists" is not evidence that it does.

The single most valuable derivation in this module is :func:`_action_blocked`
via ``SentinelEvent.blocked``. A design that merely counts attack events treats
a source the WAF stopped and a source the WAF let through as the same signal.
They are opposite facts, and telling them apart is what lets a real evasion
outrank a wall of successfully-blocked noise.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

from ...models_sentinel import SentinelEvent

#: Attack family, derived from the device's own type/subclass text.
#: Ordered: the FIRST matching pattern wins, so the specific patterns
#: (sql injection) precede the generic ones (injection).
_FAMILY_PATTERNS: list[tuple[str, str]] = [
    ("sqli", r"sql\s*injection|sqli"),
    ("xss", r"cross[\s-]*site\s*scripting|\bxss\b"),
    ("rce", r"remote\s*(code|command)\s*exec|\brce\b|command\s*injection|"
            r"os\s*command"),
    ("traversal", r"path\s*traversal|directory\s*traversal|local\s*file\s*"
                  r"inclusion|\blfi\b|remote\s*file\s*inclusion|\brfi\b"),
    ("scanner", r"scanner|vulnerability\s*scan|crawler|spider|"
                r"known\s*attack\s*tool"),
    ("bot", r"\bbot\b|bot\s*detection|bot\s*mitigation|robot"),
    ("dos", r"\bdos\b|\bddos\b|flood|rate\s*limit|http\s*flood|tcp\s*flood|"
            r"access\s*limit"),
    ("bruteforce", r"brute\s*force|credential\s*stuffing|password\s*guess|"
                   r"login\s*attempt"),
    ("auth", r"authentic|authoriz|session\s*(hijack|fixation)|cookie\s*"
             r"(poison|tamper)|csrf"),
    ("protocol", r"protocol\s*constraint|http\s*(protocol|method)|malformed|"
                 r"illegal\s*(byte|method|request)|url\s*access|"
                 r"parameter\s*validation"),
    ("deserialization", r"deserializ|object\s*injection|xxe|xml\s*external"),
    ("infoleak", r"information\s*(leak|disclosure)|data\s*leak|"
                 r"credit\s*card|server\s*information"),
]

#: Device severity vocabulary → ours. FortiWeb writes both ``severity_level``
#: ("High") and ``threat_level`` (a number); neither alone is reliable across
#: firmware, so both are consulted and the WORSE of the two wins. Under-
#: reporting severity is the expensive direction of this error.
_SEVERITY_WORDS = {
    "info": "info", "informational": "info", "low": "low", "note": "low",
    "medium": "medium", "moderate": "medium", "warning": "medium",
    "high": "high", "severe": "high", "error": "high",
    "critical": "critical", "alert": "critical", "emergency": "critical",
}

#: Actions that mean the request was STOPPED. ``alert`` and ``monitor`` mean
#: the opposite: the WAF saw it, wrote it down, and let it through.
_BLOCKING_RE = re.compile(
    r"deny|block|drop|reset|redirect|period|captcha|challenge|erase|"
    r"send_403|remove", re.I)


def _text(row: dict, *keys: str) -> str:
    for k in keys:
        v = row.get(k)
        if v not in (None, "", "N/A"):
            return str(v).strip()
    return ""


def _int(row: dict, *keys: str):
    for k in keys:
        v = row.get(k)
        if v in (None, "", "N/A"):
            continue
        try:
            return int(float(str(v).strip()))
        except (TypeError, ValueError):
            continue
    return None


def attack_family(row: dict) -> str:
    """Classify a row into one of the families the scoring and UI speak.

    Reads several fields on purpose: firmware moves the descriptive text
    between ``sub_type``, ``signature_subclass`` and ``msg`` — this product has
    already been burnt by trusting one field's presence. An unmatched row is
    ``other``, never a guess: a wrong family sends the incident down the wrong
    runbook.
    """
    blob = " ".join(filter(None, (
        _text(row, "sub_type"), _text(row, "main_type"),
        _text(row, "signature_subclass"), _text(row, "owasp_top10"),
        _text(row, "msg"),
    ))).lower()
    if not blob:
        return "other"
    for family, pattern in _FAMILY_PATTERNS:
        if re.search(pattern, blob):
            return family
    return "other"


def severity(row: dict) -> str:
    """Worst of the word severity and the numeric threat level."""
    ranks = SentinelEvent.SEVERITY_RANK
    best = "info"
    word = _text(row, "severity_level", "severity", "level").lower()
    mapped = _SEVERITY_WORDS.get(word)
    if mapped:
        best = mapped
    threat = _int(row, "threat_level")
    if threat is not None:
        # FortiWeb's threat_level is 0..100-ish; the bands below were chosen to
        # line up with the word severities the same rows carry.
        numeric = ("info" if threat < 10 else "low" if threat < 30 else
                   "medium" if threat < 60 else "high" if threat < 90 else
                   "critical")
        if ranks.get(numeric, 0) > ranks.get(best, 0):
            best = numeric
    return best


def _action_blocked(action: str) -> bool:
    return bool(_BLOCKING_RE.search(action or ""))


def parse_ts(row: dict) -> datetime:
    """``rel_time`` is Unix epoch SECONDS in a string, and is the only
    unambiguous timestamp the row carries — ``date``/``time`` are in the
    appliance's own timezone, which disagrees with every other clock in SATOM.
    Returned naive-UTC to match every other datetime column in this schema."""
    raw = _text(row, "rel_time", "itime", "eventtime")
    if raw:
        try:
            epoch = int(float(raw))
            # Millisecond epochs appear on some firmware; 1e11 seconds is the
            # year 5138, so anything above it is not seconds.
            if epoch > 1e11:
                epoch /= 1000.0
            return datetime.fromtimestamp(epoch, tz=timezone.utc).replace(tzinfo=None)
        except (TypeError, ValueError, OverflowError, OSError):
            pass
    return datetime.utcnow()


def dedup_key(device: str, row: dict, ts: datetime) -> str:
    """Content identity for one event, bucketed to the second.

    Identity is content, not arrival — the SoT lesson. Two sweeps that both
    read the same appliance page must not double-count the same block; the
    device's ``msg_id`` is included when present because it is the appliance's
    own identifier for the entry.
    """
    parts = [
        device or "", _text(row, "msg_id"), _text(row, "src"),
        _text(row, "dst"), _text(row, "http_url", "url"),
        _text(row, "signature_id"), _text(row, "sub_type"),
        _text(row, "action"), ts.strftime("%Y%m%d%H%M%S"),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:40]


def from_attack_log(appliance, row: dict) -> "SentinelEvent":
    """Build (do NOT persist) a :class:`SentinelEvent` from one attack-log row.

    ``device`` is denormalised deliberately: the FK is ``ON DELETE SET NULL``,
    and an incident whose device row was deleted must still say which box it
    happened on. Losing that turns history into anonymous rows.
    """
    ts = parse_ts(row)
    device = getattr(appliance, "name", "") or ""
    action = _text(row, "action")
    ev = SentinelEvent(
        ts=ts,
        appliance_id=getattr(appliance, "id", None),
        device=device,
        source="attack_log",
        policy=_text(row, "policy", "policy_name"),
        src_ip=_text(row, "src", "src_ip"),
        src_port=_int(row, "src_port"),
        dst_ip=_text(row, "dst", "dst_ip"),
        dst_port=_int(row, "dst_port"),
        # Kept VERBATIM. This is the string the geo block list has to be
        # handed back later, so any tidying here is a block that fails at 3am.
        country=_text(row, "srccountry", "src_country")[:64],
        http_method=_text(row, "http_method", "method")[:16],
        uri=_text(row, "http_url", "url", "http_uri"),
        http_status=_int(row, "http_status", "status", "http_response_code"),
        signature_id=_text(row, "signature_id", "sigid")[:64],
        signature=(_text(row, "signature_subclass", "sub_type", "msg"))[:300],
        attack_family=attack_family(row),
        severity=severity(row),
        action=action[:32],
        count=max(1, _int(row, "count", "cnt") or 1),
    )
    ev.dedup_key = dedup_key(device, row, ts)
    ev.raw = {k: v for k, v in (row or {}).items() if not k.startswith("_")}
    return ev


def cve_ids(row: dict) -> list:
    """CVE ids the DEVICE itself attached to the entry.

    FortiWeb carries ``signature_cve_id`` on signature hits. This is strictly
    better evidence than any local signature→CVE table: it is the vendor's own
    statement about its own signature. The mapping table exists as the fallback
    for entries that carry none, not the other way round.
    """
    blob = " ".join(filter(None, (
        _text(row, "signature_cve_id"), _text(row, "cve_id"),
        _text(row, "cve"), _text(row, "msg"),
    )))
    found = re.findall(r"CVE-\d{4}-\d{4,7}", blob, re.I)
    seen, out = set(), []
    for c in found:
        c = c.upper()
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out
