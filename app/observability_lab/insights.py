"""Derived views over the stored facts (cache first — nothing here talks to a
device). Shared by the overview, the top bar (health, notifications, search)
and, later, data flows and dependencies.

Every number here comes from a fact or an endpoint status; anything the
connectors do not collect is reported as not collected, never estimated."""
from __future__ import annotations

from datetime import timedelta

from .extensions import db
from .models import Diagram, EndpointStatus, Fact, Source, utcnow

#: Backend health as stored by the connectors -> one of up / down / unchecked.
_HEALTH = {"up": "up", "down": "down"}


def backend_health(value) -> str:
    return _HEALTH.get(str(value or "").strip().lower(), "unchecked")


def source_state(src: Source) -> str:
    """ok / error / stale / none for one source (same rule as the overlay)."""
    if src.last_run_at is None:
        return "none"
    if src.last_status == "error":
        return "error"
    if src.last_run_at < utcnow() - timedelta(seconds=3 * max(60, src.interval_s)):
        return "stale"
    return "error" if src.last_status == "partial" else "ok"


def _facts(sources, layer=None, keys=None):
    q = Fact.query.filter(Fact.source_id.in_([s.id for s in sources]))
    if layer:
        q = q.filter(Fact.layer == layer)
    if keys:
        q = q.filter(Fact.key.in_(keys))
    return q.all()


def policies(sources) -> list[dict]:
    """One row per server policy: status, listen, sessions, latency fields and
    backend counts. ``health`` buckets: disabled, no_data (enabled, backends
    not read — e.g. over the detail cap), all_down, degraded, unchecked, ok."""
    names = {s.id: s.name for s in sources}
    rows: dict = {}
    for f in _facts(sources, keys=("status", "listen", "protocol", "sessions", "conn_per_s",
                                   "client_rtt", "server_rtt", "app_response_time",
                                   "server_pool", "vserver", "wpp", "backends")):
        if not f.object_ref.startswith("policy:"):
            continue
        r = rows.setdefault((f.source_id, f.object_ref), {
            "source_id": f.source_id, "source": names.get(f.source_id, ""),
            "ref": f.object_ref, "name": f.object_ref.split(":", 1)[1]})
        r[f.key] = f.value
    out = []
    for r in rows.values():
        bks = r.pop("backends", None)
        if isinstance(bks, list):
            states = [backend_health(b.get("health")) for b in bks if isinstance(b, dict)]
            r["backends_up"], r["backends_down"] = states.count("up"), states.count("down")
            r["backends_unchecked"], r["backends_total"] = states.count("unchecked"), len(states)
        else:
            r["backends_total"] = None
        if r.get("status") != "enable":
            h = "disabled"
        elif r["backends_total"] is None:
            h = "no_data"
        elif r["backends_total"] and r["backends_down"] == r["backends_total"]:
            h = "all_down"
        elif r.get("backends_down"):
            h = "degraded"
        elif r["backends_total"] and r["backends_unchecked"] == r["backends_total"]:
            h = "unchecked"
        else:
            h = "ok"
        r["health"] = h
        out.append(r)
    order = {"all_down": 0, "degraded": 1, "no_data": 2, "unchecked": 3, "ok": 4, "disabled": 5}
    out.sort(key=lambda r: (order[r["health"]], r["source"], r["name"]))
    return out


def interfaces(sources) -> list[dict]:
    names = {s.id: s.name for s in sources}
    rows: dict = {}
    for f in _facts(sources, keys=("link", "admin_status", "speed_duplex", "address", "type")):
        if not f.object_ref.startswith("if:"):
            continue
        r = rows.setdefault((f.source_id, f.object_ref), {
            "source_id": f.source_id, "source": names.get(f.source_id, ""),
            "name": f.object_ref.split(":", 1)[1]})
        r[f.key] = f.value
    for r in rows.values():
        link = str(r.get("link", "")).lower()
        admin = str(r.get("admin_status", "")).lower()
        r["state"] = ("ok" if link == "up" else
                      "admin_down" if admin == "down" else
                      "down" if link else "none")
    return sorted(rows.values(), key=lambda r: (r["source"], r["name"]))


def devices(sources) -> list[dict]:
    """One row per source: identity, licence and resource facts (only what
    the connector of that kind collects; the rest stays absent)."""
    keys = ("hostname", "firmware", "model", "licence_valid", "licence_status", "vm_licence",
            "cpu_pct", "mem_pct", "disk_pct", "sessions")
    rows = {s.id: {"source_id": s.id, "source": s.name, "kind": s.kind, "state": source_state(s)} for s in sources}
    for f in _facts(sources, layer="device", keys=keys):
        if f.object_ref == "device":
            rows[f.source_id][f.key] = f.value
    return sorted(rows.values(), key=lambda r: r["source"])


#: Device resource thresholds (percent): (warning, critical). Built-in rules,
#: listed on Events & Alerts; a device that does not report a value is not
#: judged (FortiWeb's connector does not read CPU/memory yet).
RESOURCE_RULES = {"cpu_pct": ("CPU", 80, 95), "mem_pct": ("memory", 85, 95), "disk_pct": ("disk", 85, 95)}


def problems(sources) -> list[dict]:
    """What needs attention, worst first. Feeds the bell, the health pill and
    the alerts (``key`` is stable while the condition holds, so a change of
    severity of the same condition is one alert, not two)."""
    out = []
    names = {s.id: s.name for s in sources}

    def add(key, sid, severity, kind, title, detail, url):
        out.append({"key": key, "source_id": sid, "severity": severity, "kind": kind,
                    "title": title, "detail": detail, "url": url})

    for s in sources:
        st = source_state(s)
        if st in ("error", "stale"):
            add("source:%d" % s.id, s.id, "critical" if st == "error" else "warning", "source",
                "%s: %s" % (s.name, "collection failing" if st == "error" else "data is stale"),
                s.last_error or ("last read %s UTC" % s.last_run_at.strftime("%Y-%m-%d %H:%M")
                                 if s.last_run_at else ""),
                "/sources/%d" % s.id)
    for st in EndpointStatus.query.filter(EndpointStatus.source_id.in_(names.keys()),
                                          EndpointStatus.ok.is_(False)):
        add("read:%d:%s" % (st.source_id, st.endpoint), st.source_id, "critical", "read",
            "%s: read failed — %s" % (names[st.source_id], st.endpoint), st.error[:200],
            "/sources/%d" % st.source_id)
    # Licence: an invalid licence silently disables features (FortiWeb
    # signatures, FortiGate updates), so it is critical, not informational.
    for f in Fact.query.filter(Fact.source_id.in_(names.keys()), Fact.object_ref == "device",
                               Fact.key.in_(("licence_valid", "vm_licence"))):
        bad = (f.key == "licence_valid" and f.value is False) or \
              (f.key == "vm_licence" and str(f.value).lower() == "invalid")
        if bad:
            add("licence:%d" % f.source_id, f.source_id, "critical", "licence",
                "%s: licence not valid" % names[f.source_id],
                "features that need a licence are inactive (%s = %s)" % (f.key, f.value),
                "/sources/%d#device" % f.source_id)
    for d in devices(sources):
        for key, (label, warn, crit) in RESOURCE_RULES.items():
            v = d.get(key)
            if isinstance(v, (int, float)) and not isinstance(v, bool) and v >= warn:
                add("resource:%d:%s" % (d["source_id"], key), d["source_id"],
                    "critical" if v >= crit else "warning", "resource",
                    "%s: %s at %s %%" % (d["source"], label, v),
                    "threshold %d %% warning, %d %% critical" % (warn, crit),
                    "/infrastructure#src-%d" % d["source_id"])
    for p in policies(sources):
        if p["health"] in ("all_down", "degraded"):
            add("policy:%d:%s" % (p["source_id"], p["name"]), p["source_id"],
                "critical" if p["health"] == "all_down" else "warning", "policy",
                "%s: %s" % (p["name"], "every back-end down" if p["health"] == "all_down" else "back-ends down"),
                "%d of %d back-ends down" % (p["backends_down"], p["backends_total"]),
                "/sources/%d#L7" % p["source_id"])
    for i in interfaces(sources):
        if i["state"] == "down":
            add("if:%d:%s" % (i["source_id"], i["name"]), i["source_id"], "critical", "interface",
                "%s: %s link down" % (i["source"], i["name"]), "administratively up, no link",
                "/sources/%d#L1" % i["source_id"])
    rank = {"critical": 0, "warning": 1}
    out.sort(key=lambda p: rank[p["severity"]])
    return out


def search(q: str, limit: int = 20) -> list[dict]:
    """Global search over what the platform knows: sources, diagrams and the
    objects in the facts (interfaces, policies, pools, VIPs, back-end
    addresses). Case-insensitive substring."""
    q = (q or "").strip().lower()
    if len(q) < 2:
        return []
    out = []
    for s in Source.query.order_by(Source.name):
        if q in s.name.lower() or q in (s.host or "").lower():
            out.append({"type": "source", "label": s.name, "sub": "%s · %s" % (s.kind, s.host),
                        "url": "/sources/%d" % s.id})
    for d in Diagram.query.order_by(Diagram.name):
        if q in d.name.lower():
            out.append({"type": "diagram", "label": d.name, "sub": "%d elements" % len(d.layout.get("nodes", [])),
                        "url": "/diagrams/%d" % d.id})
    names = {s.id: s.name for s in Source.query}
    like = "%%%s%%" % q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    refs = (db.session.query(Fact.source_id, Fact.object_ref, Fact.layer).filter(
        db.func.lower(Fact.object_ref).like(like, escape="\\")).distinct().limit(200).all())
    seen = set()
    for sid, ref, layer in refs:
        if (sid, ref) in seen or ref == "device":
            continue
        seen.add((sid, ref))
        kind, _, name = ref.partition(":")
        out.append({"type": kind, "label": name or ref, "sub": "%s · %s" % (names.get(sid, "?"), layer),
                    "url": "/sources/%d#%s" % (sid, layer)})
    # Objects whose ref is an id (FortiGate firewall policies) are found by name.
    for f in Fact.query.filter(Fact.key == "name", Fact.object_ref.like("fwpolicy:%")):
        if q in str(f.value or "").lower() and (f.source_id, f.object_ref) not in seen:
            seen.add((f.source_id, f.object_ref))
            out.append({"type": "fwpolicy", "label": "#%s %s" % (f.object_ref.split(":", 1)[1], f.value),
                        "sub": "%s · L4" % names.get(f.source_id, "?"), "url": "/sources/%d#L4" % f.source_id})
    # Detected devices (FortiGate) are keyed by MAC; their IP is a fact.
    for f in Fact.query.filter(Fact.key == "address", Fact.object_ref.like("endpoint:%")):
        if q in str(f.value or "").lower() and (f.source_id, f.object_ref) not in seen:
            seen.add((f.source_id, f.object_ref))
            out.append({"type": "endpoint", "label": "%s (%s)" % (f.value, f.object_ref.split(":", 1)[1]),
                        "sub": "%s · detected device" % names.get(f.source_id, "?"), "url": "/sources/%d#L3" % f.source_id})
    # Back-end addresses live inside the backends list of a policy.
    if any(c.isdigit() for c in q):
        for f in Fact.query.filter_by(key="backends"):
            for b in f.value or []:
                if isinstance(b, dict) and q in str(b.get("address", "")).lower():
                    out.append({"type": "backend", "label": "%s:%s" % (b.get("address"), b.get("port")),
                                "sub": "%s · %s · %s" % (names.get(f.source_id, "?"), f.object_ref.split(":", 1)[1],
                                                         backend_health(b.get("health"))),
                                "url": "/sources/%d#L7" % f.source_id})
    return out[:limit]
