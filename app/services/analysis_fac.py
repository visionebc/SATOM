"""Identity analytics for the FortiAuthenticator ADOM — DB-first.

``services.analysis`` answers WAF questions: which policies use which
protection profile, which signatures are excepted, how many back-ends sit
behind a VIP. Every one of those reads ``DeviceServerPool`` /
``DeviceWebProtectionProfile``, which are FortiWeb projections. Scoped to a
FortiAuthenticator ADOM those tables are legitimately empty, so the page
rendered a full WAF dashboard with every chart blank — the failure mode this
repo has corrected three times: a page that cannot say anything still looking
like it is saying nothing is wrong.

An authenticator is not a traffic device. It has no throughput to plot and no
policy fan-out to map. The questions that matter are:

* **Entitlement.** It does not run out of bandwidth, it runs out of licence.
  ``users_usage_detail {max: 5}`` on an unlicensed unit means the sixth user is
  refused outright — a cliff no CPU series would ever show.
* **What identity actually exists.** Users, groups, RADIUS/TACACS+ clients,
  certificates, tokens.
* **Authentication posture.** Lockout, password policy, scheduled backup —
  the settings whose *absence* is the finding.

Three rules carry the correctness here.

**Never touch an appliance.** Same contract as ``services.analysis``: the
cache, the manager's own tables, and the node-local metrics store. The page
opens with the unit powered off.

**"Not harvested" is not "zero".** A counter the sweep never collected and a
counter that collected nothing look identical once they are both rendered as
``0``, and they demand opposite actions — fix the harvest, or nothing. Every
row carries ``harvested`` and the template prints them differently.

**Entitlement is not graded here.** The licence/token probes already own
thresholds, history and alerting. Re-deriving a verdict from the same numbers
is how two engines end up disagreeing about the same box. This module reports
the numbers and joins the probe's verdict; where no probe exists it says
``unmonitored`` — which is lost coverage, not health.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from ..extensions import db
from ..models import Appliance, MonitorProbe, visible_appliances
from ..models_cache import DeviceObject

#: Endpoints excluded from the config harvest, mirrored from ``device_sync``.
#: Counting them would promise inventory the sweep never collects.
from .device_sync import _FAC_SOT_EXCLUDE  # noqa: PLC2701 — single source

PRODUCT = "fortiauthenticator"

#: Registry endpoints that describe *scale* rather than settings. Only these
#: get an inventory row; a singleton like ``policy_user_lockout`` is always
#: exactly one object and "1" tells the operator nothing.
_COUNTABLE_PREFIX = ("auth_", "radius_", "tacplus_", "sso_", "cert_", "token_")

#: Singletons whose FIELDS are read for posture findings. Anything not listed
#: is inventoried but not interpreted — inventing a verdict from a payload
#: nobody verified is worse than staying quiet.
_POSTURE_SOURCES = ("policy_user_lockout", "system_scheduled_backup",
                    "system_log_settings", "system_smtp_servers")


# --------------------------------------------------------------------------- #
#  Helpers                                                                     #
# --------------------------------------------------------------------------- #
def _scoped_appliances(device_ids: list[int] | None = None) -> list:
    q = visible_appliances().filter(Appliance.kind == PRODUCT)
    rows = q.all()
    if device_ids:
        want = set(device_ids)
        rows = [a for a in rows if a.id in want]
    return rows


def _label(name: str) -> str:
    """``auth_local_users`` -> ``Local users``. The registry key is the label
    source so a new endpoint needs no second edit to show up named."""
    parts = name.split("_")
    if len(parts) > 1:
        parts = parts[1:]
    text = " ".join(parts).replace("-", " ")
    return text[:1].upper() + text[1:]


def _cached(appliance_ids: list[int]) -> dict:
    """``{(appliance_id, logical_name): count}`` over the config layer."""
    if not appliance_ids:
        return {}
    rows = (db.session.query(DeviceObject.appliance_id,
                             DeviceObject.logical_name,
                             db.func.count(DeviceObject.id))
            .filter(DeviceObject.appliance_id.in_(appliance_ids),
                    DeviceObject.layer == "config")
            .group_by(DeviceObject.appliance_id, DeviceObject.logical_name)
            .all())
    return {(a, n): c for a, n, c in rows}


def _payload(appliance_id: int, logical: str) -> dict:
    row = (DeviceObject.query
           .filter_by(appliance_id=appliance_id, logical_name=logical,
                      layer="config")
           .first())
    payload = getattr(row, "payload", None)
    return payload if isinstance(payload, dict) else {}


def _sections() -> dict:
    """``logical_name -> menu section``, straight from the live FAC menu."""
    out: dict[str, str] = {}
    try:
        from . import fac_menu
        for group in fac_menu.visible_menu():
            for item in group.items:
                for logical, _lbl in item.logicals:
                    out.setdefault(logical, group.label)
    except Exception:  # noqa: BLE001 — the menu is cosmetic here
        pass
    return out


# --------------------------------------------------------------------------- #
#  Inventory                                                                   #
# --------------------------------------------------------------------------- #
def inventory(appliances: list) -> dict:
    """What identity objects the cache holds, per endpoint, per device.

    The row set is DERIVED FROM THE REGISTRY, not from a list written here. A
    hand-written list is a copy, and the first endpoint a release adds would be
    missing from this page with nothing failing to say so — the same contract
    as ``registry_endpoints`` itself.
    """
    from ..registry import loader

    try:
        reg = loader.load_fac_registry()
    except Exception:  # noqa: BLE001 — registry unreadable is not a crash here
        reg = {}
    ids = [a.id for a in appliances]
    counts = _cached(ids)
    seen_ep = {n for (_a, n) in counts}
    sect = _sections()

    rows = []
    for name in sorted(reg):
        if name in _FAC_SOT_EXCLUDE:
            continue
        if not name.startswith(_COUNTABLE_PREFIX):
            continue
        per = []
        for a in appliances:
            per.append({"device": a.name, "device_id": a.id,
                        "count": int(counts.get((a.id, name), 0)),
                        # Harvested is a statement about the SWEEP, not about
                        # this endpoint: the sweep stores a section only when
                        # it returned rows, so "absent" here means either
                        # empty-on-device or never-collected. It is resolved by
                        # whether the device produced ANY cached object at all.
                        "harvested": (a.id, name) in counts})
        rows.append({"endpoint": name, "label": _label(name),
                     "section": sect.get(name, "Other"),
                     "total": sum(p["count"] for p in per),
                     "devices": per})
    return {"rows": rows, "endpoints_known": len(reg),
            "endpoints_present": len(seen_ep)}


# --------------------------------------------------------------------------- #
#  Entitlement                                                                 #
# --------------------------------------------------------------------------- #
def _probe_verdicts(appliances: list) -> dict:
    """``(device, resource) -> probe status``, for licence/token probes.

    The probe target is the resource key, so this joins cleanly onto the
    metrics-store labels without a second naming convention.
    """
    ids = [a.id for a in appliances]
    if not ids:
        return {}
    by_id = {a.id: a.name for a in appliances}
    out = {}
    for p in (MonitorProbe.query
              .filter(MonitorProbe.appliance_id.in_(ids),
                      MonitorProbe.kind.in_(("licence", "tokens")))
              .all()):
        key = (by_id.get(p.appliance_id, ""), (p.target or "").strip())
        out[key] = {"status": (p.last_status or "unknown") if p.enabled
                    else "disabled",
                    "enabled": bool(p.enabled), "probe_id": p.id,
                    "kind": p.kind}
    return out


def entitlement(appliances: list) -> dict:
    """Licence and FortiToken headroom, read from the metrics store.

    NOT from the config cache: ``system_info`` is excluded from the SoT harvest
    because it changes between two reads of an idle unit and would defeat the
    snapshot dedupe. The capacity collector writes these series every sweep,
    which is exactly why it exists.

    A store that is down reports ``available: False`` with the reason. It never
    reports zeros — "no licence in use" and "we could not ask" are opposite
    facts and only one of them is an emergency.
    """
    out = {"available": False, "detail": "", "rows": [],
           "generated_at": datetime.utcnow().isoformat() + "Z"}
    if not appliances:
        out["detail"] = "no FortiAuthenticator appliance in scope"
        return out
    try:
        from . import vm_store
    except Exception as exc:  # noqa: BLE001
        out["detail"] = "metrics store unavailable: %s" % type(exc).__name__
        return out

    health = vm_store.health()
    if not health.get("up"):
        out["detail"] = health.get("detail") or "metrics store unreachable"
        return out

    names = {a.name for a in appliances}
    verdicts = _probe_verdicts(appliances)
    agg: dict = {}
    families = (
        ("licence", "resource", "satom_fac_licence_used",
         "satom_fac_licence_total", "satom_fac_licence_pct"),
        ("tokens", "pool", "satom_fac_token_used",
         "satom_fac_token_total", "satom_fac_token_pct"),
    )
    for family, label_key, m_used, m_total, m_pct in families:
        for field, metric in (("used", m_used), ("total", m_total),
                              ("pct", m_pct)):
            res = vm_store.query('%s{kind="%s"}' % (metric, PRODUCT))
            for item in (res.get("data") or {}).get("result", []):
                lbl = item.get("metric") or {}
                dev = lbl.get("device") or ""
                if dev not in names:
                    continue
                res_name = lbl.get(label_key) or ""
                key = (dev, family, res_name)
                try:
                    agg.setdefault(key, {})[field] = float(item["value"][1])
                except (KeyError, IndexError, TypeError, ValueError):
                    continue

    for (dev, family, res_name), vals in sorted(agg.items()):
        verdict = verdicts.get((dev, res_name))
        used, total = vals.get("used"), vals.get("total")
        out["rows"].append({
            "device": dev, "family": family, "resource": res_name,
            "label": _label(res_name) if "_" in res_name else res_name,
            "used": used, "total": total, "pct": vals.get("pct"),
            "free": (None if used is None or not total else total - used),
            # A counter with no ceiling emits no percentage; saying so beats
            # printing a 0 % that looks like plenty of room.
            "capped": vals.get("pct") is not None,
            "probe_status": (verdict or {}).get("status", "unmonitored"),
            "probe_id": (verdict or {}).get("probe_id"),
        })
    out["available"] = True
    if not out["rows"]:
        out["detail"] = ("the store holds no FortiAuthenticator capacity "
                         "series yet — the 'capacity' collector has not run")
    return out


# --------------------------------------------------------------------------- #
#  Posture                                                                     #
# --------------------------------------------------------------------------- #
def _lockout_findings(device: str, cfg: dict) -> list:
    out = []
    if "failed_login_lockout" in cfg:
        if not cfg.get("failed_login_lockout"):
            out.append(("warn", "Failed-login lockout is off",
                        "An attacker can try passwords without limit."))
        else:
            attempts = cfg.get("failed_login_lockout_max_attempts")
            period = cfg.get("failed_login_lockout_period")
            detail = "Locks after %s attempt(s)" % attempts
            if cfg.get("failed_login_lockout_permanent"):
                detail += "; lockout is PERMANENT and needs an admin to clear"
            elif period is not None:
                detail += " for %s second(s)" % period
            out.append(("ok", "Failed-login lockout is on", detail))
    if "inactivity_lockout" in cfg and not cfg.get("inactivity_lockout"):
        out.append(("info", "Inactivity lockout is off",
                    "Dormant accounts stay usable indefinitely."))
    return out


def _backup_findings(device: str, cfg: dict) -> list:
    if "enabled" not in cfg:
        return []
    if cfg.get("enabled"):
        return [("ok", "Configuration backup is scheduled",
                 "%s at %s" % (cfg.get("frequency") or "?",
                               cfg.get("time") or "?"))]
    return [("warn", "No scheduled configuration backup",
             "The unit holds the identity store; nothing is exporting it.")]


def _smtp_findings(device: str, cfg: dict) -> list:
    if not cfg:
        return []
    addr = str(cfg.get("address") or "")
    if addr in ("localhost", "127.0.0.1"):
        return [("info", "SMTP relay is the unit itself",
                 "Token and password mail leaves via the local MTA (%s)."
                 % addr)]
    return [("ok", "SMTP relay configured", addr)] if addr else []


_POSTURE_READERS = {
    "policy_user_lockout": _lockout_findings,
    "system_scheduled_backup": _backup_findings,
    "system_smtp_servers": _smtp_findings,
}


def posture(appliances: list) -> dict:
    """Findings derived ONLY from fields that are actually present.

    Every reader guards on membership before it reads. A default assumed for a
    missing key produces a confident verdict about a setting nobody looked at,
    and that is worse than a gap: the operator stops checking.
    """
    findings = []
    unread = []
    for a in appliances:
        for logical in _POSTURE_SOURCES:
            cfg = _payload(a.id, logical)
            reader = _POSTURE_READERS.get(logical)
            if not cfg:
                unread.append({"device": a.name, "source": logical,
                               "reason": "not in cache"})
                continue
            if reader is None:
                continue
            for sev, title, detail in reader(a.name, cfg):
                findings.append({"device": a.name, "severity": sev,
                                 "title": title, "detail": detail,
                                 "source": logical})
    order = {"warn": 0, "info": 1, "ok": 2}
    findings.sort(key=lambda f: (order.get(f["severity"], 3), f["device"]))
    return {"findings": findings, "unread": unread}


# --------------------------------------------------------------------------- #
#  Freshness                                                                   #
# --------------------------------------------------------------------------- #
def freshness(appliances: list) -> dict:
    from . import device_health

    rows = []
    for a in appliances:
        meta = {}
        try:
            meta = device_health.cache_meta(a) or {}
        except Exception:  # noqa: BLE001
            meta = {}
        rows.append({
            "device": a.name, "device_id": a.id,
            "host": a.host, "maintenance": bool(getattr(a, "maintenance", False)),
            "cached": bool(meta.get("cached")),
            "generated_at": meta.get("generated_at") or "",
            "age_hours": meta.get("age_hours"),
            "layer": meta.get("layer") or "",
        })
    return {"rows": rows}


# --------------------------------------------------------------------------- #
#  Composite                                                                   #
# --------------------------------------------------------------------------- #
def analyze(filters: dict | None = None) -> dict:
    filters = filters or {}
    appliances = _scoped_appliances(filters.get("device_ids") or None)
    return {
        "product": PRODUCT,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "devices": [{"id": a.id, "name": a.name, "host": a.host,
                     "status": a.last_status or "unknown"}
                    for a in appliances],
        "entitlement": entitlement(appliances),
        "inventory": inventory(appliances),
        "posture": posture(appliances),
        "freshness": freshness(appliances),
    }


def filter_options() -> dict:
    rows = _scoped_appliances()
    return {"devices": [{"id": a.id, "name": a.name} for a in rows]}
