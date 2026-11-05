from flask import Blueprint, abort, jsonify, request
from flask_login import login_required
from sqlalchemy import text

from .. import VERSION, insights, metrics
from ..extensions import db
from ..models import EndpointStatus, Fact, Job, Source

bp = Blueprint("api", __name__)


@bp.route("/healthz")
def health():
    try:
        db.session.execute(text("select 1"))
        return jsonify(ok=True, version=VERSION)
    except Exception:  # noqa: BLE001
        return jsonify(ok=False, version=VERSION, error="database"), 503


@bp.route("/api/v1/facts")
@login_required
def facts():
    q = Fact.query
    if request.args.get("source_id"):
        q = q.filter_by(source_id=int(request.args["source_id"]))
    if request.args.get("layer"):
        q = q.filter_by(layer=request.args["layer"])
    if request.args.get("object_ref"):
        q = q.filter_by(object_ref=request.args["object_ref"])
    rows = q.order_by(Fact.id).limit(5000).all()
    return jsonify([{"source_id": f.source_id, "object_ref": f.object_ref, "layer": f.layer,
                     "key": f.key, "value": f.value, "read_at": f.read_at.isoformat() + "Z"}
                    for f in rows])


def _scope():
    """(sources in scope, source name for the metrics selector or None).
    ``?source=`` must name a known source; anything else means all."""
    allq = Source.query.order_by(Source.name).all()
    name = request.args.get("source") or ""
    picked = [s for s in allq if s.name == name]
    return (picked, name) if picked else (allq, None)


def _range():
    r = request.args.get("range") or metrics.DEFAULT_RANGE
    return r if r in metrics.RANGES else metrics.DEFAULT_RANGE


def _iso(dt):
    return dt.isoformat() + "Z" if dt else None


def _availability(buckets: dict):
    """% of enabled policies with at least one back-end up, over the policies
    whose health is KNOWN (no health check or not read = unknown, excluded)."""
    known = buckets.get("ok", 0) + buckets.get("degraded", 0) + buckets.get("all_down", 0)
    if not known:
        return None
    return round(100.0 * (buckets.get("ok", 0) + buckets.get("degraded", 0)) / known, 1)


@bp.route("/api/v1/shell")
@login_required
def shell():
    """Top bar: global health, last collection, problems for the bell."""
    sources, _ = _scope()
    probs = insights.problems(sources)
    states = [insights.source_state(s) for s in sources]
    last = max((s.last_run_at for s in sources if s.last_run_at), default=None)
    if not sources:
        health = "none"
    elif any(p["severity"] == "critical" for p in probs):
        health = "critical"
    elif probs:
        health = "warning"
    else:
        health = "ok"
    live = ("none" if last is None else "error" if "error" in states else
            "stale" if "stale" in states else "ok")
    return jsonify(health=health, live=live, last_read=_iso(last),
                   problems=probs[:50], problem_count=len(probs),
                   sources=[{"id": s.id, "name": s.name} for s in Source.query.order_by(Source.name)])


@bp.route("/api/v1/search")
@login_required
def search():
    return jsonify(results=insights.search(request.args.get("q", "")))


@bp.route("/api/v1/overview")
@login_required
def overview():
    """Everything the overview needs that is NOT a time series: counts and
    distributions from the facts, plus "now" values from the metrics store.
    A metrics failure is returned per value as ``error``, never as zero."""
    sources, sname = _scope()
    rng = _range()
    pols = insights.policies(sources)
    ifs = insights.interfaces(sources)
    reads = EndpointStatus.query.filter(EndpointStatus.source_id.in_([s.id for s in sources])).all()
    buckets = {}
    for p in pols:
        buckets[p["health"]] = buckets.get(p["health"], 0) + 1
    backends = {"up": 0, "down": 0, "unchecked": 0}
    for p in pols:
        if p.get("backends_total"):
            backends["up"] += p["backends_up"]
            backends["down"] += p["backends_down"]
            backends["unchecked"] += p["backends_unchecked"]
    now = {}
    for k in metrics.INSTANT:
        try:
            now[k] = metrics.instant(k, rng, sname)
        except metrics.MetricsError as exc:
            now[k] = {"value": None, "unit": metrics.INSTANT[k][1], "error": str(exc)}
    try:
        top = {"sessions": metrics.top_policies("sessions", sname),
               "app_response": metrics.top_policies("app_response", sname),
               "fw_sessions": metrics.top_policies("fw_sessions", sname)}
        top_error = ""
    except metrics.MetricsError as exc:
        top, top_error = {"sessions": [], "app_response": [], "fw_sessions": []}, str(exc)
    # Firewall policies are labelled by id in the store; show their names.
    fwnames = {(f.source_id, f.object_ref.split(":", 1)[1]): f.value for f in Fact.query.filter(
        Fact.source_id.in_([s.id for s in sources]), Fact.key == "name", Fact.object_ref.like("fwpolicy:%"))}
    sid_by_name = {s.name: s.id for s in sources}
    for r in top["fw_sessions"]:
        nm = fwnames.get((sid_by_name.get(r["source"]), r["policy"]))
        r["policy"] = "#%s %s" % (r["policy"], nm) if nm else "#%s (implicit)" % r["policy"] if r["policy"] == "0" else "#" + r["policy"]
    enabled = [p for p in pols if p.get("status") == "enable"]
    probs = insights.problems(sources)
    jobs = (Job.query.filter(Job.source_id.in_([s.id for s in sources]))
            .order_by(Job.id.desc()).limit(12).all())
    return jsonify(
        range=rng, scope=sname or "all",
        sources={"total": len(sources),
                 "states": {st: [insights.source_state(s) for s in sources].count(st)
                            for st in ("ok", "stale", "error", "none")},
                 "rows": [{"id": s.id, "name": s.name, "kind": s.kind, "build": s.build,
                           "state": insights.source_state(s), "last_read": _iso(s.last_run_at)}
                          for s in sources]},
        reads={"ok": sum(1 for r in reads if r.ok), "failed": sum(1 for r in reads if not r.ok),
               "total": len(reads)},
        interfaces={"total": len(ifs), "up": sum(1 for i in ifs if i["state"] == "ok"),
                    "down": sum(1 for i in ifs if i["state"] == "down")},
        services={"total": len(pols), "enabled": len(enabled), "health": buckets,
                  "availability": _availability(buckets)},
        backends=backends, now=now, top=top, top_error=top_error,
        devices=insights.devices(sources),
        problems=probs[:20], problem_count=len(probs),
        critical=sum(1 for p in probs if p["severity"] == "critical"),
        activity=[{"id": j.id, "kind": j.kind, "status": j.status, "summary": j.summary,
                   "source_id": j.source_id, "at": _iso(j.started_at),
                   "failed_steps": sum(1 for s in j.steps if not s.ok)} for j in jobs])


@bp.route("/api/v1/series/<name>")
@login_required
def series(name):
    if name not in metrics.SERIES:
        abort(404)
    _sources, sname = _scope()
    try:
        return jsonify(metrics.series(name, _range(), sname))
    except metrics.MetricsError as exc:
        title, unit, _ = metrics.SERIES[name]
        return jsonify(name=name, title=title, unit=unit, error=str(exc)), 502
