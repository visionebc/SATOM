"""Analyze: Events & Alerts, Incidents and Reports.

Alerts and events are derived by :mod:`..alerts` from the problems the
platform computes; incidents are the operators' record (writes need the SATOM
``config_write`` permission, handed over as ``is_admin``). Reports are built
on demand from the same data, printable and exportable as CSV."""
from __future__ import annotations

import csv
import io
from datetime import timedelta

from flask import Blueprint, Response, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from .. import alerts as alerts_mod
from .. import diagnose, insights, metrics, satom_bridge, topology
from ..extensions import db
from ..models import Alert, Event, Incident, IncidentNote, Job, Source, audit, utcnow
from . import admin_required

bp = Blueprint("ops", __name__)

PERIODS = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}
EVENT_KINDS = ("opened", "resolved", "escalated", "deescalated")


def _evaluate():
    """Keep alerts current when the page is opened on the primary."""
    if not satom_bridge.read_only():
        alerts_mod.evaluate()


def _arg(name, allowed, default=""):
    v = request.args.get(name) or ""
    return v if v in allowed else default


def _names():
    return {s.id: s.name for s in Source.query.all()}


# ── Events & Alerts ──────────────────────────────────────────────────────────

@bp.route("/events")
@login_required
def events():
    _evaluate()
    sev = _arg("severity", alerts_mod.SEVERITIES)
    kind = _arg("kind", EVENT_KINDS)
    period = _arg("period", PERIODS, "7d")
    since = utcnow() - timedelta(seconds=PERIODS[period])
    aq = Alert.query.filter_by(status="active")
    if sev:
        aq = aq.filter_by(severity=sev)
    active = aq.order_by(Alert.severity.asc(), Alert.first_seen.asc()).all()
    eq = Event.query.filter(Event.at >= since)
    if sev:
        eq = eq.filter_by(severity=sev)
    if kind:
        eq = eq.filter_by(kind=kind)
    evs = eq.order_by(Event.id.desc()).limit(500).all()
    all_active = Alert.query.filter_by(status="active").all()
    return render_template("ops/events.html", active=active, events=evs, sev=sev, kind=kind, period=period,
                           periods=PERIODS, kinds=EVENT_KINDS, names=_names(), rules=alerts_mod.RULES,
                           counts={"critical": sum(1 for a in all_active if a.severity == "critical"),
                                   "warning": sum(1 for a in all_active if a.severity == "warning"),
                                   "linked": sum(1 for a in all_active if a.incident_id)},
                           now=utcnow(), duration=alerts_mod.duration_s,
                           resolved_n=Alert.query.filter(Alert.status == "resolved", Alert.resolved_at >= since).count())


@bp.route("/events/alerts/<int:aid>")
@login_required
def alert(aid):
    """One alert: what raised it (the stored evidence), why, and what fixes it."""
    a = db.session.get(Alert, aid)
    if a is None:
        abort(404)
    evs = Event.query.filter_by(alert_id=a.id).order_by(Event.id.desc()).limit(100).all()
    return render_template("ops/alert.html", a=a, x=diagnose.explain(a), events=evs, names=_names(),
                           now=utcnow(), duration=alerts_mod.duration_s)


# ── Incidents ────────────────────────────────────────────────────────────────

@bp.route("/incidents")
@login_required
def incidents():
    _evaluate()
    status = _arg("status", alerts_mod.INCIDENT_STATUSES + ("all",), "active")
    q = Incident.query
    if status == "active":
        q = q.filter(Incident.status != "resolved")
    elif status != "all":
        q = q.filter_by(status=status)
    rows = q.order_by(Incident.id.desc()).limit(300).all()
    allinc = Incident.query.all()
    return render_template("ops/incidents.html", rows=rows, status=status,
                           counts={s: sum(1 for i in allinc if i.status == s) for s in alerts_mod.INCIDENT_STATUSES},
                           stats=alerts_mod.incident_stats(allinc),
                           age=lambda i: int(((i.resolved_at or utcnow()) - i.created_at).total_seconds()),
                           unlinked=Alert.query.filter_by(status="active", incident_id=None)
                           .order_by(Alert.severity.asc(), Alert.first_seen.asc()).all())


@bp.route("/incidents/new", methods=["POST"])
@login_required
@admin_required
def incident_new():
    ids = [int(x) for x in request.form.getlist("alert_id") if x.isdigit()]
    title = (request.form.get("title") or "").strip()
    if not ids and not title:
        flash("Give the incident a title or pick at least one alert.", "warning")
        return redirect(url_for("ops.incidents"))
    inc = alerts_mod.open_incident(current_user.username, title, ids,
                                   (request.form.get("assignee") or "").strip())
    audit(current_user.username, "incident.open", "#%d %s" % (inc.id, inc.title), "%d alerts" % len(ids))
    db.session.commit()
    flash("Incident #%d opened." % inc.id, "success")
    return redirect(url_for("ops.incident", iid=inc.id))


def _incident(iid) -> Incident:
    inc = db.session.get(Incident, iid)
    if inc is None:
        abort(404)
    return inc


@bp.route("/incidents/<int:iid>")
@login_required
def incident(iid):
    inc = _incident(iid)
    return render_template("ops/incident.html", inc=inc, names=_names(), now=utcnow(),
                           duration=alerts_mod.duration_s,
                           candidates=Alert.query.filter_by(status="active", incident_id=None).all())


@bp.route("/incidents/<int:iid>/update", methods=["POST"])
@login_required
@admin_required
def incident_update(iid):
    inc = _incident(iid)
    user, done = current_user.username, []
    status = request.form.get("status") or ""
    if status and alerts_mod.set_status(inc, status, user):
        done.append(status)
    if "assignee" in request.form:
        who = (request.form.get("assignee") or "").strip()[:64]
        if who != inc.assignee:
            inc.assignee = who
            inc.notes.append(IncidentNote(user=user, kind="assign",
                                          text=("Assigned to %s" % who) if who else "Unassigned"))
            done.append("assignee")
    sev = request.form.get("severity") or ""
    if sev in alerts_mod.SEVERITIES and sev != inc.severity:
        inc.notes.append(IncidentNote(user=user, kind="status", text="Severity %s → %s" % (inc.severity, sev)))
        inc.severity = sev
        done.append("severity")
    for aid in [int(x) for x in request.form.getlist("alert_id") if x.isdigit()]:
        a = db.session.get(Alert, aid)
        if a is not None and a.incident_id is None:
            a.incident_id = inc.id
            inc.notes.append(IncidentNote(user=user, kind="link", text="Linked alert: %s" % a.title))
            done.append("link")
    note = (request.form.get("note") or "").strip()
    if note:
        inc.notes.append(IncidentNote(user=user, kind="note", text=note[:4000]))
        done.append("note")
    if done:
        audit(user, "incident.update", "#%d" % inc.id, ", ".join(done))
        db.session.commit()
        flash("Incident updated.", "success")
    else:
        flash("Nothing changed.", "info")
    return redirect(url_for("ops.incident", iid=inc.id))


# ── Reports ──────────────────────────────────────────────────────────────────

REPORTS = {
    "health": ("Health & availability", "heart-pulse",
               "Per source: state, collection success, read availability, alerts and incidents in the period."),
    "inventory": ("Inventory", "hdd-rack",
                  "Every device, interface, server policy, back-end and firewall policy the platform knows."),
    "alerts": ("Alerts & incidents", "bell",
               "Every alert opened in the period with its duration, and the incidents with MTTA / MTTR."),
}


def _health_report(period):
    since = utcnow() - timedelta(seconds=PERIODS[period])
    sources = Source.query.order_by(Source.name).all()
    rng = {"24h": "24h", "7d": "7d", "30d": "30d"}[period]
    rows, err = [], ""
    for s in sources:
        jobs = Job.query.filter(Job.source_id == s.id, Job.kind == "collect", Job.started_at >= since).all()
        ok = sum(1 for j in jobs if j.status == "done")
        al = Alert.query.filter(Alert.source_id == s.id, Alert.first_seen >= since).all()
        avail = None
        if not err:
            try:
                avail = metrics.instant("read_availability", rng, s.name)["value"]
            except metrics.MetricsError as exc:
                err = str(exc)
        rows.append({"source": s.name, "kind": s.kind, "state": insights.source_state(s), "build": s.build,
                     "collections": len(jobs), "collections_ok": ok,
                     "success": round(100.0 * ok / len(jobs), 1) if jobs else None,
                     "read_availability": None if avail is None else round(100.0 * avail, 2),
                     "alerts": len(al), "critical": sum(1 for a in al if a.severity == "critical"),
                     "active": sum(1 for a in al if a.status == "active")})
    pols = insights.policies(sources)
    buckets = {h: sum(1 for p in pols if p["health"] == h) for h in ("ok", "degraded", "all_down", "empty", "unchecked", "no_data", "disabled")}
    known = buckets["ok"] + buckets["degraded"] + buckets["all_down"]
    incs = Incident.query.filter(Incident.created_at >= since).all()
    return {"rows": rows, "metrics_error": err, "services": buckets,
            "availability": round(100.0 * (buckets["ok"] + buckets["degraded"]) / known, 1) if known else None,
            "incidents": alerts_mod.incident_stats(incs), "since": since}


def _inventory_report():
    sources = Source.query.order_by(Source.name).all()
    m = topology.build(sources)
    flows = topology.app_flows(m)
    return {"devices": insights.devices(sources), "interfaces": insights.interfaces(sources),
            "policies": flows, "fw": topology.fw_flows(m), "segments": topology.segments(m),
            "planned": satom_bridge.planned_devices()}


def _alerts_report(period):
    since = utcnow() - timedelta(seconds=PERIODS[period])
    al = Alert.query.filter((Alert.first_seen >= since) | (Alert.status == "active")).order_by(Alert.first_seen).all()
    incs = Incident.query.filter((Incident.created_at >= since) | (Incident.status != "resolved")).order_by(Incident.id).all()
    return {"alerts": al, "incidents": incs, "stats": alerts_mod.incident_stats(incs), "since": since}


@bp.route("/reports")
@login_required
def reports():
    return render_template("ops/reports.html", reports=REPORTS, periods=PERIODS)


@bp.route("/reports/<kind>")
@login_required
def report(kind):
    if kind not in REPORTS:
        abort(404)
    period = _arg("period", PERIODS, "7d")
    data = (_health_report(period) if kind == "health" else
            _inventory_report() if kind == "inventory" else _alerts_report(period))
    return render_template("ops/report.html", kind=kind, meta=REPORTS[kind], period=period, periods=PERIODS,
                           d=data, names=_names(), now=utcnow(), duration=alerts_mod.duration_s,
                           health_label={"ok": "Healthy", "degraded": "Back-ends down", "all_down": "All back-ends down",
                                         "unchecked": "No health check", "no_data": "Not read", "empty": "No back-ends", "disabled": "Disabled"})


def _csv(name, header, rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    for r in rows:
        w.writerow(["" if v is None else (", ".join(map(str, v)) if isinstance(v, list) else v) for v in r])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=observability-%s-%s.csv"
                             % (name, utcnow().strftime("%Y%m%d-%H%M"))})


@bp.route("/reports/<kind>/<table>.csv")
@login_required
def report_csv(kind, table):
    period = _arg("period", PERIODS, "7d")
    if kind == "health" and table == "sources":
        d = _health_report(period)
        return _csv("health-sources", ["source", "kind", "state", "build", "collections", "collections_ok",
                                       "success_pct", "read_availability_pct", "alerts", "critical", "still_active"],
                    [[r["source"], r["kind"], r["state"], r["build"], r["collections"], r["collections_ok"],
                      r["success"], r["read_availability"], r["alerts"], r["critical"], r["active"]] for r in d["rows"]])
    if kind == "inventory":
        d = _inventory_report()
        if table == "devices":
            return _csv("devices", ["source", "kind", "state", "hostname", "model", "firmware", "licence",
                                    "cpu_pct", "mem_pct", "disk_pct", "sessions"],
                        [[x["source"], x["kind"], x["state"], x.get("hostname"), x.get("model"), x.get("firmware"),
                          x.get("licence_status") or x.get("vm_licence") or x.get("licence_valid"), x.get("cpu_pct"),
                          x.get("mem_pct"), x.get("disk_pct"), x.get("sessions")] for x in d["devices"]])
        if table == "interfaces":
            return _csv("interfaces", ["source", "interface", "state", "link", "admin", "speed", "address", "type"],
                        [[x["source"], x["name"], x["state"], x.get("link"), x.get("admin_status"),
                          x.get("speed_duplex"), x.get("address"), x.get("type")] for x in d["interfaces"]])
        if table == "policies":
            return _csv("server-policies", ["source", "policy", "status", "health", "listen", "pool", "backend",
                                            "port", "backend_health", "path"],
                        [[f["source"], f["name"], f.get("status"), f["health"], f.get("listen"), f.get("server_pool"),
                          b["address"], b["port"], b["health"], b["path"]["status"]]
                         for f in d["policies"] for b in (f["backend_rows"] or [{"address": "", "port": "", "health": "",
                                                                                "path": {"status": ""}}])])
        if table == "firewall":
            return _csv("firewall-policies", ["source", "id", "name", "srcintf", "srcaddr", "dstintf", "dstaddr",
                                              "service", "action", "nat", "status", "hits", "bytes", "last_used"],
                        [[r["source"], r["id"], r["name"], r["srcintf"], r["srcaddr"], r["dstintf"], r["dstaddr"],
                          r["service"], r["action"], r["nat"], r["status"], r["hits"], r["bytes"], r["last_used"]]
                         for r in d["fw"]])
    if kind == "alerts" and table in ("alerts", "incidents"):
        d = _alerts_report(period)
        names = _names()
        if table == "alerts":
            return _csv("alerts", ["id", "source", "severity", "kind", "title", "status", "first_seen_utc",
                                   "resolved_utc", "duration_s", "incident"],
                        [[a.id, names.get(a.source_id, ""), a.severity, a.kind, a.title, a.status,
                          a.first_seen.strftime("%Y-%m-%d %H:%M:%S"),
                          a.resolved_at.strftime("%Y-%m-%d %H:%M:%S") if a.resolved_at else "",
                          alerts_mod.duration_s(a), a.incident_id or ""] for a in d["alerts"]])
        return _csv("incidents", ["id", "title", "severity", "status", "assignee", "created_utc", "acked_utc",
                                  "resolved_utc", "alerts"],
                    [[i.id, i.title, i.severity, i.status, i.assignee, i.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                      i.acked_at.strftime("%Y-%m-%d %H:%M:%S") if i.acked_at else "",
                      i.resolved_at.strftime("%Y-%m-%d %H:%M:%S") if i.resolved_at else "", len(i.alerts)]
                     for i in d["incidents"]])
    abort(404)
