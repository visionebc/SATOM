"""Everything Observability reads from SATOM goes through here.

* :func:`sync_sources` — the sources ARE SATOM's appliances (FortiWeb and
  FortiGate read live + cache; FortiADC, FortiAuthenticator, FortiAnalyzer
  from SATOM's cache only). No secret is copied:
  :func:`credentials` reads it from SATOM when a connector opens.
* :func:`cache_rows` — SATOM's device cache (``device_objects``) in the shape
  the device's REST API answers, children folded back into their parent.
* :func:`on_request` / the collector thread — the scheduled collection that a
  systemd timer runs in the standalone product. One collection at a time across
  the gunicorn workers (Postgres advisory lock), never on a read-only standby.

Every SATOM read runs in SATOM's own application context.
"""
from __future__ import annotations

import logging
import threading
import time

from sqlalchemy import text

from .extensions import db

log = logging.getLogger(__name__)

#: SATOM appliance kinds with a connector here; the rest are "planned".
SUPPORTED = ("fortiweb", "fortigate", "fortiadc", "fortiauthenticator", "fortianalyzer")
LOCK_KEY = 7312051105  # pg advisory lock: one collector across workers
TICK_S = 60


def _satom():
    from flask import current_app
    return current_app.config["SATOM_APP"]


def _pg() -> bool:
    return db.engine.dialect.name == "postgresql"


# ── schema ───────────────────────────────────────────────────────────────────

def ensure_schema() -> None:
    """Own schema in SATOM's database, tables created if missing. On a
    read-only standby (streaming replica) the schema arrives by replication;
    a refused CREATE there is expected and not an error."""
    from . import SCHEMA
    try:
        if _pg():
            with db.engine.begin() as conn:
                if conn.execute(text("show transaction_read_only")).scalar() == "on":
                    return
                conn.execute(text("CREATE SCHEMA IF NOT EXISTS %s" % SCHEMA))
        db.create_all()
    except Exception as exc:  # noqa: BLE001 — never block SATOM's boot
        log.warning("observability-lab: schema not ensured: %s", exc)


def read_only() -> bool:
    if not _pg():
        return False
    try:
        return db.session.execute(text("show transaction_read_only")).scalar() == "on"
    except Exception:  # noqa: BLE001
        return True


# ── inventory ────────────────────────────────────────────────────────────────

def _appliances():
    from ..models import Appliance
    return (Appliance.query.filter(Appliance.is_cluster.is_(False),
                                   Appliance.maintenance.is_(False))
            .order_by(Appliance.name).all())


def sync_sources() -> dict:
    """Make ``sources`` mirror SATOM's appliances. Returns counts."""
    from .models import Source, audit
    with _satom().app_context():
        rows = [{"id": a.id, "name": a.name, "kind": a.kind, "host": a.host,
                 "port": a.port or 443, "username": a.username or "",
                 "verify": bool(a.verify_ssl), "vdom": a.vdom or "",
                 "build": (a.firmware or "")[:160]}
                for a in _appliances() if a.kind in SUPPORTED]
    by_aid = {}
    for s in Source.query.all():
        aid = (s.config or {}).get("appliance_id")
        if aid is not None:
            by_aid[int(aid)] = s
    seen, added, changed = set(), 0, 0
    for r in rows:
        seen.add(r["id"])
        s = by_aid.get(r["id"])
        cfg = {"fortinet_source": "satom", "appliance_id": r["id"]}
        if r["vdom"]:
            cfg["vdom"] = r["vdom"]
        if s is None:
            clash = Source.query.filter_by(name=r["name"]).first()
            if clash is not None:  # a pre-existing direct source of the same name
                continue
            s = Source(name=r["name"], kind=r["kind"], interval_s=300, enabled=True)
            db.session.add(s)
            added += 1
            audit("satom", "source.sync_add", r["name"], "SATOM appliance %d" % r["id"])
        before = (s.name, s.kind, s.host, s.port, s.username, s.tls_verify, s.config)
        s.name, s.kind, s.host, s.port = r["name"][:80], r["kind"], r["host"], r["port"]
        s.username, s.tls_verify, s.config, s.secret_enc = r["username"], r["verify"], cfg, ""
        if r["build"] and not s.build:
            s.build = r["build"]  # SATOM's last-known firmware until a test reads it live
        if before != (s.name, s.kind, s.host, s.port, s.username, s.tls_verify, s.config) and s.id:
            changed += 1
    removed = 0
    for aid, s in by_aid.items():
        if aid not in seen:
            audit("satom", "source.sync_remove", s.name, "no longer a visible SATOM appliance")
            db.session.delete(s)
            removed += 1
    db.session.commit()
    return {"added": added, "changed": changed, "removed": removed, "total": len(rows)}


def planned_devices() -> list:
    """SATOM devices of products without a connector here (shown, never faked)."""
    with _satom().app_context():
        return [{"name": a.name, "kind": a.kind} for a in _appliances() if a.kind not in SUPPORTED]


def credentials(appliance_id: int) -> tuple[str, str]:
    """(username, secret) of a SATOM appliance, decrypted by SATOM, in memory
    only — Observability reads the device AS SATOM (operator 2026-11-05:
    "the data must be direct, it is SATOM in the end")."""
    from ..models import Appliance
    with _satom().app_context():
        a = db_satom_get(Appliance, appliance_id)
        if a is None:
            raise RuntimeError("SATOM appliance %s no longer exists" % appliance_id)
        return a.username or "", a.password or ""


def collector_status(appliance_id: int) -> dict:
    """``{collector: {"status", "detail", "at"}}``: SATOM's own record of its
    last scrape of this appliance (Monitoring › Collection). The metric only
    says up/down; the reason (``last_detail``) lives here."""
    from ..models_metrics import ScrapeTarget
    if not appliance_id:
        return {}
    with _satom().app_context():
        return {t.collector: {"status": t.last_status or "", "detail": t.last_detail or "", "at": t.last_run_at}
                for t in ScrapeTarget.query.filter_by(appliance_id=int(appliance_id))}


def db_satom_get(model, ident):
    from ..extensions import db as satom_db
    return satom_db.session.get(model, int(ident))


# ── SATOM's device cache ─────────────────────────────────────────────────────

def cache_rows(appliance_id: int, logical: str, layer: str = "config") -> tuple[list, object]:
    """``(rows, snapshot_at)``: the cached objects of one table, each with its
    sub-tables folded back in as lists (``srcintf: [{"name": ...}]``), i.e.
    the shape of the device's REST answer. ``snapshot_at`` is None when SATOM
    never captured that layer of this device."""
    from ..models_cache import DeviceObject, DeviceSnapshot
    from ..extensions import db as satom_db
    with _satom().app_context():
        at = (satom_db.session.query(satom_db.func.max(DeviceSnapshot.generated_at))
              .filter(DeviceSnapshot.appliance_id == appliance_id, DeviceSnapshot.layer == layer)
              .scalar())
        tops = (DeviceObject.query.filter_by(appliance_id=appliance_id, logical_name=logical, layer=layer)
                .order_by(DeviceObject.idx, DeviceObject.id).all())
        if not tops:
            return [], at
        kids: dict = {}
        prefix = logical + "/"
        for o in (DeviceObject.query
                  .filter(DeviceObject.parent_id.in_([t.id for t in tops]),
                          DeviceObject.logical_name.like(prefix + "%"))
                  .order_by(DeviceObject.idx, DeviceObject.id)):
            sub = o.logical_name[len(prefix):]
            if "/" in sub:
                continue
            kids.setdefault(o.parent_id, {}).setdefault(sub, []).append(
                dict(o.payload) if isinstance(o.payload, dict) else {})
        rows = []
        for t in tops:
            row = dict(t.payload) if isinstance(t.payload, dict) else {}
            for sub, items in kids.get(t.id, {}).items():
                if not isinstance(row.get(sub), list) or not row.get(sub):
                    row[sub] = items
            rows.append(row)
        return rows, at


# ── scheduled collection ─────────────────────────────────────────────────────

_started = False
_start_lock = threading.Lock()


def on_request(app) -> None:
    """Start this worker's collector thread on its first request (web workers
    only — SATOM's scheduler process never serves /observability)."""
    global _started
    if _started or not app.config.get("OBS_COLLECTOR"):
        return
    with _start_lock:
        if _started:
            return
        _started = True
        threading.Thread(target=_loop, args=(app,), daemon=True, name="obs-lab-collector").start()


def _loop(app) -> None:
    time.sleep(5)
    while True:
        try:
            with app.app_context():
                tick()
        except Exception:  # noqa: BLE001 — the loop must survive anything
            log.exception("observability-lab collector tick failed")
        time.sleep(TICK_S)


def tick() -> int:
    """One scheduler pass: sync the inventory, collect every due source.
    Returns the number of sources collected (0 when another worker holds the
    lock or the database is a read-only standby)."""
    from . import collect
    if read_only():
        return 0
    conn = None
    if _pg():
        conn = db.engine.connect()
        if not conn.execute(text("select pg_try_advisory_lock(:k)"), {"k": LOCK_KEY}).scalar():
            conn.close()
            return 0
    try:
        sync_sources()
        n = 0
        for s in list(collect.due_sources()):
            collect.run_source(s, "scheduler")
            n += 1
        from . import alerts
        alerts.evaluate()
        return n
    finally:
        if conn is not None:
            try:
                conn.execute(text("select pg_advisory_unlock(:k)"), {"k": LOCK_KEY})
            finally:
                conn.close()


def inventory_coverage() -> list:
    """Every SATOM appliance and what Observability does with it (phase 0 of
    the path analysis): read live + cache, cache only, or why it is left out."""
    from ..models import Appliance
    from .connectors.satom import BY_PRODUCT
    out = []
    with _satom().app_context():
        for a in Appliance.query.order_by(Appliance.name).all():
            if a.is_cluster:
                why, mode = "cluster container (its members are the devices)", ""
            elif a.maintenance:
                why, mode = "in maintenance in SATOM", ""
            elif a.kind not in SUPPORTED:
                why, mode = "no connector for %s" % a.kind, ""
            else:
                why = ""
                mode = ("SATOM cache only" if a.kind in ("fortiadc", "fortiauthenticator", "fortianalyzer")
                        else "SATOM cache (configuration) + device (live state)")
            if mode:
                mode = ("direct, as SATOM (SATOM's credential, GET only); SATOM's cache when the device fails"
                        if a.kind in ("fortiweb", "fortigate") else
                        "from SATOM (configuration cache + SATOM's own live collectors) — no direct reader yet")
            out.append({"appliance_id": a.id, "name": a.name, "kind": a.kind, "host": a.host,
                        "vdom": a.vdom or "", "included": not why and a.kind in BY_PRODUCT,
                        "mode": mode, "why": why, "satom_status": a.last_status or ""})
    return out


def cache_tree(appliance_id: int, logical: str, layer: str = "deep") -> tuple[list, object]:
    """Like :func:`cache_rows` but every level of children nested
    (``server_policy`` → ``server_pool`` → ``pserver-list``), for SATOM's
    ``deep`` snapshot."""
    from ..models_cache import DeviceObject, DeviceSnapshot
    from ..extensions import db as satom_db
    with _satom().app_context():
        at = (satom_db.session.query(satom_db.func.max(DeviceSnapshot.generated_at))
              .filter(DeviceSnapshot.appliance_id == appliance_id, DeviceSnapshot.layer == layer).scalar())
        objs = (DeviceObject.query.filter(DeviceObject.appliance_id == appliance_id, DeviceObject.layer == layer,
                                          (DeviceObject.logical_name == logical) |
                                          DeviceObject.logical_name.like(logical + "/%"))
                .order_by(DeviceObject.idx, DeviceObject.id).all())
        nodes = {o.id: (o, dict(o.payload) if isinstance(o.payload, dict) else {}) for o in objs}
        tops = []
        for o, row in nodes.values():
            if o.logical_name == logical and (o.parent_id is None or o.parent_id not in nodes):
                tops.append(row)
                continue
            parent = nodes.get(o.parent_id)
            if parent is None:
                continue
            sub = o.logical_name.rsplit("/", 1)[-1]
            lst = parent[1].get(sub)
            if not isinstance(lst, list):
                lst = parent[1][sub] = []
            lst.append(row)
        return tops, at


def appliance_identity(appliance_id: int) -> dict:
    """What SATOM knows about the appliance itself (no device call)."""
    from ..models import Appliance
    with _satom().app_context():
        a = db_satom_get(Appliance, appliance_id)
        if a is None:
            return {}
        return {"hostname": a.device_hostname or a.name, "firmware": a.firmware or "", "serial": a.serial or "",
                "model": a.model or "", "ha": a.ha_mode or ""}


class SatomLiveError(Exception):
    pass


#: Window for "current": SATOM scrapes every few minutes.
LIVE_WINDOW = "15m"


def satom_live(device: str) -> dict:
    """The last value of every ``satom_*`` series SATOM's collectors wrote for
    this device, plus the state of each collector (``satom_scrape_up``)."""
    import httpx
    from flask import current_app
    url = current_app.config.get("METRICS_URL", "")
    if not url:
        raise SatomLiveError("not configured")
    sel = 'device="%s"' % device.replace("\\", "\\\\").replace('"', '\\"')
    try:
        r = httpx.get(url.rstrip("/") + "/api/v1/query", timeout=10, params={
            "query": 'last_over_time({__name__=~"satom_(box|iface|policy|scrape)_.+", %s}[%s])' % (sel, LIVE_WINDOW)})
        body = r.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise SatomLiveError("unreachable: %s" % type(exc).__name__) from exc
    if r.status_code >= 400 or body.get("status") != "success":
        raise SatomLiveError("query failed: %s" % (body.get("error") or r.status_code))
    series, collectors = [], {}
    for row in (body.get("data") or {}).get("result") or []:
        m = dict(row.get("metric") or {})
        name = m.pop("__name__", "")
        try:
            value = float(row["value"][1])
        except (KeyError, IndexError, TypeError, ValueError):
            continue
        value = int(value) if value.is_integer() else value
        if name == "satom_scrape_up":
            collectors[m.get("collector", "?")] = value
        else:
            series.append((name, m, value))
    return {"series": series, "collectors": collectors, "window": LIVE_WINDOW}
