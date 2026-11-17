"""What the diagram shows on top of the drawing: stored facts only (cache
first — nothing here talks to a device), grouped by layer, with per-layer
state: ``ok``, ``error`` (a read feeding that layer failed), ``stale`` (older
than 3 collection intervals) or ``none`` (no data)."""
from __future__ import annotations

from datetime import timedelta

from .connectors import LAYERS
from .extensions import db
from .models import EndpointStatus, Fact, Source, utcnow


def _state(src: Source, statuses, layer: str, has_facts: bool) -> tuple[str, str]:
    feeding = [s for s in statuses if layer in (s.layers or "").split(",")]
    bad = [s for s in feeding if not s.ok]
    if bad:
        return "error", "; ".join("%s: %s" % (s.endpoint, s.error) for s in bad)[:600]
    if not has_facts:
        return "none", ("; ".join(sorted({s.error or "absent on this build" for s in feeding}))
                        if feeding and all(s.absent for s in feeding) else "")
    if src.last_run_at and src.last_run_at < utcnow() - timedelta(seconds=3 * max(60, src.interval_s)):
        return "stale", "last read %s UTC" % src.last_run_at.strftime("%Y-%m-%d %H:%M")
    return "ok", ""


def for_source(src: Source, object_ref: str | None = None) -> dict:
    q = Fact.query.filter_by(source_id=src.id)
    if object_ref:
        q = q.filter((Fact.object_ref == object_ref) | (Fact.object_ref.like(object_ref + ":%")))
    facts = q.order_by(Fact.layer, Fact.object_ref, Fact.key).all()
    statuses = EndpointStatus.query.filter_by(source_id=src.id).all()
    layers = {}
    for layer in LAYERS:
        rows = [f for f in facts if f.layer == layer]
        state, why = _state(src, statuses, layer, bool(rows))
        objs: dict = {}
        for f in rows:
            objs.setdefault(f.object_ref, {})[f.key] = f.value
        layers[layer] = {"state": state, "why": why, "objects": objs,
                         "read_at": max((f.read_at for f in rows), default=None)}
        if layers[layer]["read_at"]:
            layers[layer]["read_at"] = layers[layer]["read_at"].strftime("%Y-%m-%d %H:%M:%S")
    return {"source": {"id": src.id, "name": src.name, "kind": src.kind,
                       "status": src.last_status, "build": src.build,
                       "tls_verify": src.tls_verify},
            "layers": layers}


def for_layout(layout: dict) -> dict:
    out = {"nodes": {}, "edges": {}}
    cache: dict = {}

    def get(sid, ref):
        key = (sid, ref or "")
        if key not in cache:
            src = db.session.get(Source, sid) if sid else None
            cache[key] = for_source(src, ref) if src else None
        return cache[key]

    for n in layout.get("nodes", []):
        if n.get("source_id"):
            out["nodes"][n["id"]] = get(n["source_id"], n.get("object_ref"))
    for e in layout.get("edges", []):
        if e.get("source_id"):
            out["edges"]["%s|%s" % (e["from"], e["to"])] = get(e["source_id"], e.get("object_ref"))
    return out
