"""Context enrichment — what turns a signature hit into a judgement.

Everything here is the difference between "a WAF rule fired" and "this matters".
An authorised scanner during its own maintenance window produces exactly the
same attack log as a real intrusion; the log cannot tell them apart, and no
amount of severity weighting will. Only context can.

What this module refuses to do
------------------------------
It does not call out to the internet. Not for GeoIP, not for ASN, not for
reputation. The country already arrives on the event — the appliance resolved
it — and anything richer either exists locally or is honestly reported as
unknown. ``asn_known: False`` is a fact an operator can act on; a silently
guessed ASN is a fact they cannot.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime

from ...models_sentinel import (SentinelMaintenanceWindow, SentinelTopology,
                                SentinelTrustedSource)
from . import config


def _ip(value: str):
    try:
        return ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None


def trusted_match(src_ip: str, when: datetime | None = None):
    """The active trusted-source entry covering this IP, or ``None``.

    Expiry is enforced HERE rather than by a cleanup job: a job that fails to
    run would leave an expired authorisation silently in force, and the whole
    reason expiry is mandatory is that a stale trust entry is a permanent
    blind spot nobody remembers creating.
    """
    ip = _ip(src_ip)
    if ip is None:
        return None
    when = when or datetime.utcnow()
    for row in SentinelTrustedSource.query.all():
        if row.expires_at is not None and row.expires_at <= when:
            continue
        try:
            net = ipaddress.ip_network(row.cidr, strict=False)
        except ValueError:
            continue      # a malformed entry cannot silently trust everything
        if ip.version == net.version and ip in net:
            return row
    return None


def active_windows(when: datetime | None = None, device: str = "") -> list:
    when = when or datetime.utcnow()
    return [w for w in SentinelMaintenanceWindow.query.all()
            if w.covers(when, device)]


def in_maintenance(when: datetime | None = None, device: str = "") -> bool:
    return bool(active_windows(when, device))


def baseline_frozen(when: datetime | None = None, device: str = "") -> bool:
    return any(w.freeze_baseline for w in active_windows(when, device))


def actions_suppressed(when: datetime | None = None, device: str = "") -> bool:
    return any(w.suppress_actions for w in active_windows(when, device))


def is_protected(src_ip: str) -> bool:
    """Whether this source may NEVER be the target of a blocking action.

    Own-infrastructure ranges. This is checked before policy, before
    confidence, before level — a correlation bug that decides the fleet's own
    monitoring host is an attacker must be unable to act on that conclusion.
    """
    ip = _ip(src_ip)
    if ip is None:
        return True     # cannot parse => cannot prove it is safe to block
    return any(ip.version == n.version and ip in n
               for n in config.protected_networks())


def topology_for(appliance_id: int):
    if not appliance_id:
        return None
    return SentinelTopology.query.filter_by(appliance_id=appliance_id).first()


def cpe_hints(topo, appliance=None) -> list:
    """What we believe the target runs, for the CVE ∩ product cross-check.

    Sources, in order of trust: an explicit ``cpe`` on a topology backend
    entry, then a free-text ``product`` on it. Nothing is inferred from the
    hostname — a guess here does not fail loudly, it flips
    ``target_vulnerable`` on evidence nobody entered.
    """
    hints = []
    for b in (getattr(topo, "backends", None) or []):
        if isinstance(b, dict):
            for key in ("cpe", "product"):
                v = (b.get(key) or "").strip()
                if v:
                    hints.append(v)
        elif isinstance(b, str) and b.strip():
            hints.append(b.strip())
    return hints


def source_context(src_ip: str, *, device: str = "",
                   when: datetime | None = None) -> dict:
    """Everything deterministic we know about a source, in one dict."""
    when = when or datetime.utcnow()
    trust = trusted_match(src_ip, when)
    windows = active_windows(when, device)
    return {
        "ip": src_ip or "",
        "trusted": trust is not None,
        "trusted_kind": trust.kind if trust else "",
        "trusted_label": trust.label if trust else "",
        "trusted_expires": (trust.expires_at.isoformat(timespec="seconds")
                            if trust and trust.expires_at else ""),
        "protected": is_protected(src_ip),
        "maintenance": bool(windows),
        "maintenance_labels": [w.label or f"window {w.id}" for w in windows],
        "actions_suppressed": any(w.suppress_actions for w in windows),
        "asn_known": False,   # no local ASN source wired; see module docstring
        "asn": None,
    }
