"""Monitoring › Service checks — create, run, sweep, alert (2026-11-17).

The protocol work is :mod:`service_probes` (a pure library: "did the SERVICE
answer, at its own protocol level, and what certificate did it show").
This module is everything around it:

* **Targets are free by nature.** A partner's VPN head-end is not in the
  inventory, so every destination goes through :mod:`net_guard` in FREE mode —
  at save time (the operator must hold ``monitoring.probe_free``, like the
  certificate inspector and the tracer) and again before EVERY socket of every
  run (the ``guard`` callable), because DNS can change between the two.
* **Secrets never sit in a column.** OpenVPN static keys and WireGuard keys go
  to the vault / Fernet app settings (services.prefixed_secret) under
  ``svccheck.<id>.<field>``; the target JSON keeps the other fields only.
* **One sweep, the monitor sweep.** :func:`sweep` runs from the existing
  ``deep_monitor`` scheduled action (every 3 minutes), after the device probes
  — no second schedule to arm, and the action's "ok" means "the sweep ran"
  exactly as it does for the probes. A check is due when its interval elapsed;
  intervals are multiples of 3 for that reason.
* **Screenshots** (web kinds, :mod:`web_screenshot`) are taken at most every
  ``screenshot_every_min`` minutes, kept per check (last :data:`KEEP_SHOTS`)
  under ``data/service_checks/<id>/`` — inside ``data/``, so the standby's
  datasync carries them.
* **Alerts** go through SATOM's engine (services.alerts, check
  ``alert_checks.service_checks``): one finding per check that is down
  (critical) or degraded (warning), unless the check is muted.
* **IPsec through a FortiGate** (optional): the IKE probe proves the daemon
  answers; naming a managed FortiGate and a tunnel adds the tunnel's own state
  read from the box's monitor API (GET only).
"""
from __future__ import annotations

import json
import os
import shutil
import time
from datetime import datetime, timedelta

from flask import current_app

from ..extensions import db
from ..models_service_checks import ServiceCheck, ServiceCheckResult
from . import service_probes as sp

#: Kind groups — the tabs of the page.
GROUPS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("web", "Web", ("https", "http")),
    ("vpn", "VPN", ("sslvpn", "openvpn", "ipsec", "wireguard")),
    ("ports", "Ports & protocols", ("tls", "tcp", "dns", "ssh", "smtp")),
)
WEB_KINDS = frozenset({"http", "https", "sslvpn"})
#: Target fields that are secrets: never stored in target_json.
SECRET_FIELDS = {
    "openvpn": ("tls_auth_key", "tls_crypt_key"),
    "wireguard": ("client_private_key", "preshared_key"),
}
INTERVALS = (3, 6, 9, 15, 30, 60, 180, 360, 720, 1440)
KEEP_RESULTS = 2000          # rows per check (~4 days at 3 min)
KEEP_DAYS = 90               # and never older than this
KEEP_SHOTS = 5
SWEEP_BUDGET_S = 110         # the monitor sweep's slot is 3 minutes
SECRET_PLACEHOLDER = "__kept__"


class CheckError(ValueError):
    """Refused input; the message is shown to the operator."""


# ── secrets ────────────────────────────────────────────────────────────────

def _secret_key(cid: int, field: str) -> tuple[str, str]:
    return "svccheck.%d.%s" % (cid, field), "service_checks/%d/%s" % (cid, field)


def _secret_get(cid: int, field: str) -> str:
    from .prefixed_secret import state
    key, path = _secret_key(cid, field)
    val, _problem = state(key, path)
    return val or ""


def _secret_put(cid: int, field: str, value: str) -> None:
    from .prefixed_secret import store
    key, path = _secret_key(cid, field)
    store(key, path, value or "")


def full_target(check: ServiceCheck) -> dict:
    """The target with its secrets put back (for a run only, never shown)."""
    t = dict(check.target)
    for f in check.secret_list:
        v = _secret_get(check.id, f)
        if v:
            t[f] = v
    return t


# ── authorisation of destinations ──────────────────────────────────────────

def _host_port(kind: str, t: dict) -> tuple[str, int]:
    if kind in ("http", "https"):
        from urllib.parse import urlsplit
        u = urlsplit(t["url"])
        return u.hostname or "", u.port or (443 if u.scheme == "https" else 80)
    return t.get("host", ""), int(t.get("port") or 0)


#: Ports of net_guard's HTTP/TLS-only denial a kind may use, because the
#: probe speaks that port's own protocol (net_guard.LIFTABLE_PORTS). A tcp
#: check only READS a banner, it sends nothing.
PROTOCOL_PORTS = {"ssh": (22,), "smtp": (25, 465, 587), "tcp": (22, 25, 465, 587)}


def guard_for(kind: str):
    """net_guard in FREE mode, before every socket a run of *kind* opens."""
    lift = PROTOCOL_PORTS.get(kind, ())

    def guard(host: str, port: int) -> None:
        from . import net_guard
        try:
            net_guard.resolve_target(host, port, mode=net_guard.MODE_FREE,
                                     protocol_ports=lift)
        except net_guard.TargetError as exc:
            raise PermissionError("SATOM refuses %s:%s — %s" % (host, port, exc)) from None
    return guard


guard = guard_for("")


# ── create / update ────────────────────────────────────────────────────────

def _int(form: dict, key: str, default: int, lo: int, hi: int) -> int:
    try:
        v = int(str(form.get(key, default)).strip() or default)
    except (TypeError, ValueError):
        raise CheckError("%s must be a whole number" % key) from None
    if not lo <= v <= hi:
        raise CheckError("%s must be between %d and %d" % (key, lo, hi))
    return v


def normalise(form: dict, existing: ServiceCheck | None = None) -> tuple[dict, dict, dict]:
    """``(columns, target_without_secrets, secrets)`` from a submitted form.

    ``form["target"]`` is a dict. A secret field sent empty or as
    :data:`SECRET_PLACEHOLDER` keeps the stored one (the page never receives
    secrets back, so "unchanged" must not mean "erase").
    """
    name = str(form.get("name") or "").strip()
    if not name:
        raise CheckError("a name is required")
    if len(name) > 120:
        raise CheckError("the name is longer than 120 characters")
    kind = str(form.get("kind") or "").strip().lower()
    if kind not in sp.KINDS:
        raise CheckError("unknown kind %r" % kind)
    raw = dict(form.get("target") or {})
    secrets: dict = {}
    for f in SECRET_FIELDS.get(kind, ()):
        v = raw.pop(f, None)
        v = (v or "").strip() if isinstance(v, str) else ""
        if v and v != SECRET_PLACEHOLDER:
            secrets[f] = v
        elif existing is not None and existing.kind == kind and f in existing.secret_list:
            secrets[f] = _secret_get(existing.id, f)       # unchanged
    try:
        validated = sp.validate_target(kind, dict(raw, **secrets))
    except ValueError as exc:
        raise CheckError(str(exc)) from None
    target = {k: v for k, v in validated.items() if k not in SECRET_FIELDS.get(kind, ())}
    kept = {k: v for k, v in validated.items() if k in SECRET_FIELDS.get(kind, ()) and v}
    # Stored as their TEXT, not the parsed bytes the validator may return.
    kept = {k: secrets.get(k, "") for k in kept}
    host, port = _host_port(kind, validated)
    from . import net_guard
    if kind == "dns" or port:
        try:
            net_guard.resolve_target(host, port or 53, mode=net_guard.MODE_FREE,
                                     protocol_ports=PROTOCOL_PORTS.get(kind, ()))
        except net_guard.TargetError as exc:
            raise CheckError(str(exc)) from None
    interval = _int(form, "interval_min", 3, 3, 1440)
    if interval % 3:
        raise CheckError("the interval must be a multiple of 3 minutes (the monitor sweep's cadence)")
    cols = {
        "name": name, "kind": kind,
        "enabled": str(form.get("enabled", "1")).lower() not in ("0", "false", "off", ""),
        "interval_min": interval,
        "timeout_s": _int(form, "timeout_s", 10, 2, 60),
        "cert_warn_days": _int(form, "cert_warn_days", 21, 0, 365),
        "screenshot_every_min": (_int(form, "screenshot_every_min", 60, 0, 1440)
                                 if kind in WEB_KINDS else 0),
        "fgt_appliance_id": None, "fgt_tunnel": "",
    }
    if kind == "ipsec":
        fid = str(form.get("fgt_appliance_id") or "").strip()
        if fid:
            from ..models import visible_appliances
            ok = {a.id: a for a in visible_appliances() if a.kind == "fortigate"}
            try:
                fid_i = int(fid)
            except ValueError:
                raise CheckError("fgt_appliance_id must be a FortiGate id") from None
            if fid_i not in ok:
                raise CheckError("that FortiGate is not one you can see")
            tunnel = str(form.get("fgt_tunnel") or "").strip()
            if not tunnel:
                raise CheckError("name the tunnel (phase 1) to read on the FortiGate")
            cols.update(fgt_appliance_id=fid_i, fgt_tunnel=tunnel[:120])
    return cols, target, kept


def create(form: dict, *, product: str, author: str) -> ServiceCheck:
    cols, target, secrets = normalise(form)
    c = ServiceCheck(product=product or "global", created_by=author[:80], **cols)
    c.target_json = json.dumps(target, sort_keys=True)
    c.secret_fields = ",".join(sorted(secrets))
    db.session.add(c)
    db.session.flush()
    for f, v in secrets.items():
        _secret_put(c.id, f, v)
    db.session.commit()
    return c


def update(c: ServiceCheck, form: dict) -> ServiceCheck:
    cols, target, secrets = normalise(form, existing=c)
    for f in set(c.secret_list) - set(secrets):
        _secret_put(c.id, f, "")
    for k, v in cols.items():
        setattr(c, k, v)
    c.target_json = json.dumps(target, sort_keys=True)
    c.secret_fields = ",".join(sorted(secrets))
    for f, v in secrets.items():
        _secret_put(c.id, f, v)
    c.updated_at = datetime.utcnow()
    db.session.commit()
    return c


def delete(c: ServiceCheck) -> None:
    for f in c.secret_list:
        _secret_put(c.id, f, "")
    shutil.rmtree(shot_dir(c.id), ignore_errors=True)
    ServiceCheckResult.query.filter_by(check_id=c.id).delete()
    db.session.delete(c)
    db.session.commit()


# ── screenshots ────────────────────────────────────────────────────────────

def shot_dir(cid: int) -> str:
    from .api_pack import data_root
    return str(data_root() / "service_checks" / str(int(cid)))


def shot_path(cid: int, name: str) -> str | None:
    """Absolute path of a stored screenshot, or None (no traversal: the name
    must be one this module wrote)."""
    if not name or "/" in name or "\\" in name or not name.startswith("shot-") \
            or not name.endswith(".png"):
        return None
    p = os.path.join(shot_dir(cid), name)
    return p if os.path.isfile(p) else None


def _prune_shots(cid: int) -> None:
    d = shot_dir(cid)
    try:
        files = sorted(f for f in os.listdir(d) if f.startswith("shot-") and f.endswith(".png"))
    except OSError:
        return
    for f in files[:-KEEP_SHOTS]:
        try:
            os.remove(os.path.join(d, f))
        except OSError:
            pass


def _shot_url(c: ServiceCheck, t: dict) -> str | None:
    if c.kind in ("http", "https"):
        return t.get("url")
    if c.kind == "sslvpn":
        return "https://%s:%s/" % (t["host"], t.get("port") or 443)
    return None


def _screenshot_due(c: ServiceCheck, now: datetime, force: bool) -> bool:
    if c.kind not in WEB_KINDS or not c.screenshot_every_min:
        return False
    if force or not c.last_shot_at:
        return True
    return now - c.last_shot_at >= timedelta(minutes=c.screenshot_every_min)


# ── FortiGate tunnel state (IPsec, optional) ───────────────────────────────

def _fgt_tunnel_state(c: ServiceCheck) -> dict:
    """``{"ok": bool, "up": bool|None, "detail": str}`` from the FortiGate's
    monitor API (GET /api/v2/monitor/vpn/ipsec). Never raises."""
    from ..models import Appliance
    a = db.session.get(Appliance, c.fgt_appliance_id)
    if a is None:
        return {"ok": False, "up": None, "detail": "the FortiGate is no longer in the inventory"}
    if a.kind != "fortigate":
        return {"ok": False, "up": None, "detail": "%s is not a FortiGate" % a.name}
    try:
        from ..clients.fortigate import FortiGateClient
        cli = FortiGateClient(a, timeout=float(c.timeout_s or 10))
        payload, err = cli._call("GET", "/api/v2/monitor/vpn/ipsec")
    except Exception as exc:  # noqa: BLE001 — a read failure is a finding, not a crash
        return {"ok": False, "up": None, "detail": "FortiGate read failed: %s" % str(exc)[:200]}
    if err:
        return {"ok": False, "up": None, "detail": "FortiGate read failed: %s" % str(err)[:200]}
    rows = payload.get("results") if isinstance(payload, dict) else payload
    for row in rows or []:
        if str(row.get("name") or "") != c.fgt_tunnel:
            continue
        p2 = row.get("proxyid") or []
        up = [p for p in p2 if str(p.get("status")) == "up"]
        return {"ok": True, "up": bool(up),
                "detail": "tunnel %s on %s: %d of %d phase-2 selector(s) up"
                          % (c.fgt_tunnel, a.name, len(up), len(p2))}
    return {"ok": True, "up": False,
            "detail": "tunnel %s not found on %s (monitor/vpn/ipsec)" % (c.fgt_tunnel, a.name)}


# ── running ────────────────────────────────────────────────────────────────

def run_one(c: ServiceCheck, *, force_shot: bool = False, commit: bool = True) -> ServiceCheckResult:
    """Run one check now and record the result."""
    now = datetime.utcnow()
    t = full_target(c)
    try:
        res = sp.run(c.kind, t, timeout=float(c.timeout_s or 10), guard=guard_for(c.kind),
                     cert_warn_days=int(c.cert_warn_days or 0))
        out = res.as_dict()
    except Exception as exc:  # noqa: BLE001 — a library bug must not stop the sweep
        out = {"status": "error", "latency_ms": None, "summary": "check failed: %s" % exc,
               "detail": {}, "cert": None}
    detail = dict(out.get("detail") or {})
    status, summary = out["status"], out["summary"]

    if c.kind == "ipsec" and c.fgt_appliance_id:
        fg = _fgt_tunnel_state(c)
        detail["fortigate"] = fg
        if fg["ok"] and fg["up"] is False and status == "up":
            status, summary = "down", summary + " — but " + fg["detail"]
        elif fg["ok"] and fg["up"]:
            summary = summary + " · " + fg["detail"]
        elif not fg["ok"] and status == "up":
            status, summary = "degraded", summary + " — " + fg["detail"]

    shot = ""
    if _screenshot_due(c, now, force_shot) and status != "error":
        url = _shot_url(c, t)
        if url:
            from . import web_screenshot
            try:
                from urllib.parse import urlsplit
                u = urlsplit(url)
                guard(u.hostname or "", u.port or (443 if u.scheme == "https" else 80))
                cap = web_screenshot.capture(url, shot_dir(c.id),
                                             verify_tls=bool(t.get("verify_tls", True)),
                                             timeout=float(c.timeout_s or 10))
            except PermissionError as exc:
                cap = {"ok": False, "error": str(exc)}
            detail["screenshot"] = {k: cap.get(k) for k in ("ok", "error", "took_ms", "bytes")}
            c.last_shot_at = now
            if cap.get("ok"):
                shot = cap["file"]
                c.last_shot = shot
                _prune_shots(c.id)

    cert = out.get("cert") or None
    r = ServiceCheckResult(check_id=c.id, at=now, status=status,
                           latency_ms=out.get("latency_ms"), summary=summary[:2000],
                           detail_json=json.dumps(detail, default=str)[:60000],
                           cert_json=json.dumps(cert, default=str) if cert else "",
                           cert_days_left=(cert or {}).get("days_left"), shot=shot)
    db.session.add(r)
    if status != c.last_status:
        c.last_changed_at = now
    c.last_status, c.last_summary, c.last_checked_at = status, summary[:2000], now
    if commit:
        db.session.commit()
    return r


def due(now: datetime | None = None) -> list[ServiceCheck]:
    now = now or datetime.utcnow()
    out = []
    for c in ServiceCheck.query.filter_by(enabled=True).order_by(ServiceCheck.last_checked_at.asc()
                                                                  .nullsfirst()).all():
        if not c.last_checked_at or now - c.last_checked_at >= timedelta(minutes=c.interval_min) \
                - timedelta(seconds=20):
            out.append(c)
    return out


def sweep(*, force: bool = False, budget_s: float = SWEEP_BUDGET_S) -> dict:
    """Run every due check (all of them with ``force``) within the budget."""
    started = time.monotonic()
    todo = (ServiceCheck.query.filter_by(enabled=True).all() if force else due())
    ran, counts, results, skipped = 0, {}, [], 0
    for c in todo:
        if time.monotonic() - started > budget_s:
            skipped += 1
            continue
        r = run_one(c)
        ran += 1
        counts[r.status] = counts.get(r.status, 0) + 1
        results.append({"check": c.name, "kind": c.kind, "status": r.status, "summary": r.summary})
    prune()
    return {"ran": ran, "counts": counts, "results": results, "unchecked": skipped,
            "took_s": round(time.monotonic() - started, 1)}


def prune() -> None:
    """Keep at most KEEP_RESULTS rows per check and nothing older than KEEP_DAYS."""
    cutoff = datetime.utcnow() - timedelta(days=KEEP_DAYS)
    ServiceCheckResult.query.filter(ServiceCheckResult.at < cutoff).delete(synchronize_session=False)
    for (cid,) in db.session.query(ServiceCheck.id).all():
        ids = [i for (i,) in db.session.query(ServiceCheckResult.id)
               .filter_by(check_id=cid).order_by(ServiceCheckResult.at.desc())
               .offset(KEEP_RESULTS).limit(5000).all()]
        if ids:
            ServiceCheckResult.query.filter(ServiceCheckResult.id.in_(ids)).delete(
                synchronize_session=False)
    db.session.commit()


# ── reading ────────────────────────────────────────────────────────────────

def visible_checks():
    from .product_scope import scope_query
    return scope_query(ServiceCheck.query, ServiceCheck.product).order_by(ServiceCheck.name).all()


def visible_check_or_404(cid: int) -> ServiceCheck:
    from flask import abort
    from .product_scope import visible_product
    c = db.session.get(ServiceCheck, cid)
    if c is None or not visible_product(c.product):
        abort(404)
    return c


def history(c: ServiceCheck, hours: int = 24, limit: int = 500) -> list[dict]:
    since = datetime.utcnow() - timedelta(hours=max(1, min(int(hours), 24 * 90)))
    rows = (ServiceCheckResult.query.filter(ServiceCheckResult.check_id == c.id,
                                            ServiceCheckResult.at >= since)
            .order_by(ServiceCheckResult.at.desc()).limit(limit).all())
    return [r.as_dict() for r in rows]


def latest(c: ServiceCheck) -> ServiceCheckResult | None:
    return (ServiceCheckResult.query.filter_by(check_id=c.id)
            .order_by(ServiceCheckResult.at.desc()).first())


def uptime(c: ServiceCheck, hours: int = 24) -> float | None:
    since = datetime.utcnow() - timedelta(hours=hours)
    rows = [s for (s,) in db.session.query(ServiceCheckResult.status)
            .filter(ServiceCheckResult.check_id == c.id, ServiceCheckResult.at >= since).all()]
    if not rows:
        return None
    good = sum(1 for s in rows if s in ("up", "degraded"))
    return round(100.0 * good / len(rows), 2)


# ── alerts (services.alerts) ───────────────────────────────────────────────

def alert_findings() -> list[dict]:
    """One finding per check that is down (critical) or degraded (warning)."""
    out = []
    for c in ServiceCheck.query.filter_by(enabled=True, muted=False).all():
        if c.last_status not in ("down", "degraded"):
            continue
        sev = "critical" if c.last_status == "down" else "warning"
        out.append({"key": "svccheck.%d" % c.id, "severity": sev,
                    "title": "Service check %s: %s (%s)" % (c.name, c.last_status,
                                                            sp.KIND_LABEL.get(c.kind, c.kind)),
                    "detail": c.last_summary,
                    "link": "/observability/monitoring/checks/#check-%d" % c.id})
    return out


def overview() -> dict:
    checks = visible_checks()
    counts: dict = {}
    for c in checks:
        counts[c.last_status] = counts.get(c.last_status, 0) + 1
    return {"total": len(checks), "counts": counts}
