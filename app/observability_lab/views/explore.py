"""Monitor / Visualize / Analyze pages over the stored facts and the metrics
store: Infrastructure, Network, Applications, Data Flows, Dependencies and
Analytics. Read-only: nothing here writes or talks to a device. Every list
filter is applied on the server (the URL is the state)."""
from __future__ import annotations

from flask import Blueprint, abort, jsonify, render_template, request
from flask_login import login_required

from .. import insights, metrics, topology
from ..extensions import db
from ..models import EndpointStatus, Source

bp = Blueprint("explore", __name__)

HEALTH = ("all_down", "degraded", "no_data", "unchecked", "ok", "disabled")
HEALTH_LABEL = {"all_down": "All back-ends down", "degraded": "Back-ends down", "no_data": "Not read",
                "unchecked": "No health check", "ok": "Healthy", "disabled": "Disabled"}
PATH_LABEL = {"reached": "Reached", "leaves": "Leaves monitored network", "no_route": "No route",
              "denied": "Blocked by firewall", "loop": "Routing loop", "invalid": "Invalid address"}


def _scope():
    """(sources in scope, picked source name or ''). ``?source=`` must name a
    known source; anything else means all sources."""
    allq = Source.query.order_by(Source.name).all()
    name = request.args.get("source") or ""
    picked = [s for s in allq if s.name == name]
    return (picked, name) if picked else (allq, "")


def _range():
    r = request.args.get("range") or metrics.DEFAULT_RANGE
    return r if r in metrics.RANGES else metrics.DEFAULT_RANGE


def _pick(name, allowed):
    v = request.args.get(name) or ""
    return v if v in allowed else ""


def _render(tpl, **kw):
    sources, scope = kw.pop("_scope", None) or _scope()
    return render_template(tpl, scope=scope, scope_sources=sources, range_key=_range(),
                           health_label=HEALTH_LABEL, path_label=PATH_LABEL, **kw)


# ── Monitor ──────────────────────────────────────────────────────────────────

@bp.route("/infrastructure")
@login_required
def infrastructure():
    from .. import satom_bridge
    sources, scope = _scope()
    m = topology.build(sources)
    devs = {d["source_id"]: d for d in insights.devices(sources)}
    ifs = insights.interfaces(sources)
    pols = insights.policies(sources)
    statuses = EndpointStatus.query.filter(EndpointStatus.source_id.in_([s.id for s in sources])).all()
    cards = []
    for s in sources:
        objs = m.objs.get(s.id, {})
        counts = {}
        for ref in objs:
            k = ref.split(":", 1)[0]
            if k != "device":
                counts[k] = counts.get(k, 0) + 1
        mine_if = [i for i in ifs if i["source_id"] == s.id]
        mine_st = [st for st in statuses if st.source_id == s.id]
        cards.append({"s": s, "d": dict(objs.get("device", {}), **devs.get(s.id, {})), "counts": counts,
                      "if_up": sum(1 for i in mine_if if i["state"] == "ok"), "if_total": len(mine_if),
                      "if_down": sum(1 for i in mine_if if i["state"] == "down"),
                      "reads_ok": sum(1 for st in mine_st if st.ok), "reads": len(mine_st),
                      "failed": [st for st in mine_st if not st.ok],
                      "policies": sum(1 for p in pols if p["source_id"] == s.id),
                      "problems": [p for p in insights.problems([s])]})
    return _render("explore/infrastructure.html", _scope=(sources, scope), cards=cards,
                   planned=satom_bridge.planned_devices())


@bp.route("/network")
@login_required
def network():
    sources, scope = _scope()
    m = topology.build(sources)
    state = _pick("state", ("ok", "down", "admin_down", "none"))
    ifs = insights.interfaces(sources)
    rows = []
    for i in ifs:
        kv = m.objs.get(i["source_id"], {}).get("if:" + i["name"], {})
        rows.append(dict(i, **{k: kv.get(k) for k in ("alias", "role", "mac", "mtu", "speed", "speed_duplex",
                                                    "rx_bytes", "tx_bytes", "rx_errors", "tx_errors",
                                                    "management_access", "configured_address")}))
    counts = {k: sum(1 for r in rows if r["state"] == k) for k in ("ok", "down", "admin_down", "none")}
    if state:
        rows = [r for r in rows if r["state"] == state]
    endpoints = [{"source_id": sid, "source": m.name(sid), "ip": str(ip), "mac": mac, "interface": ifn,
                  "online": (m.objs.get(sid, {}).get("endpoint:" + mac, {}) or {}).get("online")}
                 for ip, sid, mac, ifn in m.endpoints]
    return _render("explore/network.html", _scope=(sources, scope), rows=rows, counts=counts, state=state,
                   segments=topology.segments(m), routes=topology.route_rows(m), endpoints=endpoints,
                   addresses=topology.dependencies(m, flows=[])["addresses"])


@bp.route("/applications")
@login_required
def applications():
    sources, scope = _scope()
    health = _pick("health", HEALTH)
    m = topology.build(sources)
    pols = insights.policies(sources)
    counts = {h: sum(1 for p in pols if p["health"] == h) for h in HEALTH}
    if health:
        pols = [p for p in pols if p["health"] == health]
    for p in pols:
        kv = m.objs.get(p["source_id"], {})
        p["detail"] = kv.get("policy:" + p["name"], {})
        p["pool_kv"] = kv.get("pool:%s" % p.get("server_pool"), {}) if p.get("server_pool") else {}
    return _render("explore/applications.html", _scope=(sources, scope), pols=pols, counts=counts,
                   health=health, total=sum(counts.values()))


# ── Visualize ────────────────────────────────────────────────────────────────

@bp.route("/flows")
@login_required
def flows():
    sources, scope = _scope()
    view = _pick("view", ("apps", "firewall")) or "apps"
    path = _pick("path", tuple(PATH_LABEL))
    health = _pick("health", HEALTH)
    m = topology.build(sources)
    flows_ = topology.app_flows(m)
    path_counts: dict = {}
    for f in flows_:
        for b in f["backend_rows"]:
            path_counts[b["path"]["status"]] = path_counts.get(b["path"]["status"], 0) + 1
    if health:
        flows_ = [f for f in flows_ if f["health"] == health]
    if path:
        flows_ = [f for f in flows_ if any(b["path"]["status"] == path for b in f["backend_rows"])]
    return _render("explore/flows.html", _scope=(sources, scope), view=view, flows=flows_,
                   fw=topology.fw_flows(m), path=path, health=health, path_counts=path_counts)


@bp.route("/dependencies")
@login_required
def dependencies():
    sources, scope = _scope()
    m = topology.build(sources)
    return _render("explore/dependencies.html", _scope=(sources, scope), dep=topology.dependencies(m),
                   segments=[s for s in topology.segments(m) if s["shared"]])


@bp.route("/api/v1/trace")
@login_required
def trace():
    """Path from a monitored device to an IP (``?from=<source id>&ip=``)."""
    try:
        sid = int(request.args.get("from") or 0)
    except ValueError:
        abort(400)
    src = db.session.get(Source, sid)
    if src is None:
        abort(404)
    t = topology.trace(topology.build(), sid, request.args.get("ip", ""))
    return jsonify(t)


# ── Analyze ──────────────────────────────────────────────────────────────────

#: Panels of the Analytics page: named series only (the expression is built in
#: metrics.py; the browser never sends one).
PANELS = [("throughput", "arrow-left-right"), ("packets", "boxes"), ("sessions", "people"),
          ("connections", "lightning"), ("latency", "stopwatch"), ("resources", "cpu"),
          ("fw_traffic", "bricks"), ("fw_sessions", "bricks"), ("reads", "cloud-check")]


def _dist(rows, key, label=None):
    out: dict = {}
    for r in rows:
        v = r.get(key)
        v = ", ".join(v) if isinstance(v, list) else ("—" if v in (None, "") else str(v))
        out[v] = out.get(v, 0) + 1
    return {"label": label or key, "rows": sorted(out.items(), key=lambda x: -x[1])}


@bp.route("/analytics")
@login_required
def analytics():
    sources, scope = _scope()
    m = topology.build(sources)
    pols = insights.policies(sources)
    for p in pols:
        kv = m.objs.get(p["source_id"], {})
        p.update({k: v for k, v in kv.get("policy:" + p["name"], {}).items() if k in ("ssl", "deployment_mode", "service")})
        pkv = kv.get("pool:%s" % p.get("server_pool"), {}) if p.get("server_pool") else {}
        p["lb_algo"], p["health_check"] = pkv.get("lb_algo"), pkv.get("health_check")
    fw = topology.fw_flows(m)
    ifs = insights.interfaces(sources)
    backends = [b for f in topology.app_flows(m, pols) for b in f["backend_rows"]]
    dists = [
        ("Server policies", [_dist(pols, "health", "Health"), _dist(pols, "protocol", "Protocol"),
                             _dist(pols, "ssl", "SSL"), _dist(pols, "lb_algo", "Load-balancing"),
                             _dist(pols, "health_check", "Health check"),
                             _dist(pols, "deployment_mode", "Deployment mode")]),
        ("Back-ends", [_dist(backends, "health", "Health"),
                       _dist([{"s": b["path"]["status"]} for b in backends], "s", "Network path")]),
        ("Firewall policies", [_dist(fw, "action", "Action"), _dist(fw, "nat", "NAT"),
                               _dist(fw, "status", "Status")]),
        ("Interfaces", [_dist(ifs, "state", "State"), _dist(ifs, "type", "Type")]),
    ]
    return _render("explore/analytics.html", _scope=(sources, scope), panels=PANELS,
                   series=metrics.SERIES, dists=dists)


@bp.route("/api/v1/analytics/<name>")
@login_required
def analytics_series(name):
    if name not in metrics.SERIES:
        abort(404)
    _sources, scope = _scope()
    try:
        d = metrics.series(name, _range(), scope or None)
    except metrics.MetricsError as exc:
        title, unit, _ = metrics.SERIES[name]
        return jsonify(name=name, title=title, unit=unit, error=str(exc)), 502
    for s in d["series"]:
        s["stats"] = metrics.stats(s["points"])
    return jsonify(d)


@bp.route("/api/v1/top/<what>")
@login_required
def top(what):
    _sources, scope = _scope()
    fn = {"interfaces": metrics.top_interfaces, "fw_bytes": metrics.top_fw_bytes}.get(what)
    if fn is None:
        abort(404)
    try:
        return jsonify(rows=fn(scope or None, _range()))
    except metrics.MetricsError as exc:
        return jsonify(rows=[], error=str(exc)), 502


# ── path analysis by phases ──────────────────────────────────────────────────

def _device_data(m, sid):
    """Phase 1: what the model holds for one device, per VDOM."""
    objs = m.objs.get(sid, {})
    src = m.sources[sid]
    per_vdom = []
    for v in m.vdoms(sid):
        ifs = [n for (s, n), vd in m.ifvdom.items() if s == sid and vd == v]
        per_vdom.append({"vdom": v, "interfaces": len(ifs),
                         "addressed": sum(1 for ifo, s, n in m.addrs if s == sid and m.ifvdom.get((s, n)) == v),
                         "down": sorted("%s (%s)" % (n, m.ifdown[(sid, n)]) for n in ifs if (sid, n) in m.ifdown),
                         "connected": sum(1 for r in m.routes.get(sid, []) if r.vdom == v and r.gateway is None),
                         "static": sum(1 for r in m.routes.get(sid, []) if r.vdom == v and r.gateway),
                         "policies": len(topology._policies(m, sid, v)) if m.kind(sid) == "fortigate" else None})
    dev = objs.get("device", {})
    return {"sid": sid, "name": src.name, "kind": src.kind, "state": insights.source_state(src),
            "last_run": src.last_run_at, "mode": dev.get("read_mode") or "SATOM cache + device",
            "snapshot": dev.get("config_snapshot_at"), "vdoms": per_vdom, "notes": m.notes.get(sid, []),
            "failed": [st for st in EndpointStatus.query.filter_by(source_id=sid, ok=False)]}


@bp.route("/flows/analyze")
@login_required
def analyze():
    from .. import satom_bridge
    m = topology.build()
    sources = sorted(m.sources.values(), key=lambda s: s.name)
    try:
        sid = int(request.args.get("from") or 0)
    except ValueError:
        sid = 0
    ip = (request.args.get("ip") or "").strip()
    src_ip = (request.args.get("src") or "").strip()
    port = (request.args.get("port") or "").strip()
    vdom = (request.args.get("vdom") or "").strip() or None
    result, error = None, ""
    if sid and ip:
        if sid not in m.sources:
            error = "that source does not exist"
        elif vdom and vdom not in m.vdoms(sid):
            error = "%s has no VDOM %s (known: %s)" % (m.name(sid), vdom, ", ".join(m.vdoms(sid)))
        else:
            result = topology.trace(m, sid, ip, src_ip or None, vdom)
            if result["status"] == "invalid":
                error, result = "%r is not an IP address" % ip, None
    involved = []
    if result:
        for h in result["hops"]:
            if h["source_id"] not in involved:
                involved.append(h["source_id"])
    examples = []
    for f in topology.app_flows(m)[:200]:
        for b in f["backend_rows"]:
            if len(examples) < 8 and b["path"]["status"] not in [e["status"] for e in examples]:
                examples.append({"from": f["source_id"], "source": f["source"], "ip": b["address"],
                                 "port": b["port"], "status": b["path"]["status"], "policy": f["name"]})
    return render_template("explore/analyze.html", sources=sources, sid=sid, ip=ip, src_ip=src_ip, port=port,
                           vdom=vdom or "", result=result, error=error, examples=examples,
                           coverage=satom_bridge.inventory_coverage(),
                           data=[_device_data(m, s) for s in (involved or [x.id for x in sources])],
                           vdoms={s.id: m.vdoms(s.id) for s in sources}, path_label=PATH_LABEL,
                           health_label=HEALTH_LABEL, scope="", range_key=_range())
