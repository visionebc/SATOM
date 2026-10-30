"""Scout's read-only sources beyond Path Diagnostics and metrics.

Scout is the operations assistant: a diagnosis starts from the saved Path
Diagnostics report and the metrics around it (``advisor.tool_path_report`` /
``tool_metrics_context``). This module gives it the rest of what an operator
looks at when a service breaks -- what Sentinel saw, what SATOM itself ran
against the box (jobs, and each REST/SSH call they made), who changed what
(the audit log) and the logs of the same window, from every source SATOM can
reach.

Rules that are load-bearing
---------------------------
* **The operator's own view, never a wider one.** Every function runs in the
  operator's request (the chat stream keeps it) and applies the SAME gate as
  the page that shows the data: ``monitoring.view`` + appliance visibility for
  Sentinel, owner-or-admin + ADOM for jobs, ``audit.view`` + ADOM for the
  audit log. Scout must never be the way round a page's permission.
* **Presentation reads what collectors left.** Nothing here talks to an
  appliance. The only network reads are to LOG COLLECTORS an admin configured
  (a FortiAnalyzer behind an edge-map row, an external SIEM), each time-boxed.
* **A source that could not look is not a source that found nothing.**
  :func:`search_logs` reports every source with a status -- ``ok``,
  ``no_match``, ``error``, ``not_configured``, ``disabled``, ``forbidden`` --
  so "Splunk timed out" can never read as "Splunk has no lines".
* **Everything is capped and redacted.** Device and log text goes through
  :func:`secret_scan.redact` and is clipped per field; the advisor then wraps
  the result as untrusted and (for an external provider) redacts identifiers.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

from .secret_scan import redact

MAX_ROWS = 50
MAX_TEXT = 300
MAX_WINDOW_MINUTES = 1440


def _clip(v, n: int = MAX_TEXT) -> str:
    s = redact(str(v if v is not None else ""))
    return s if len(s) <= n else s[:n] + "…"


def _int(v, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(int(v), hi))
    except (TypeError, ValueError):
        return default


def _need(perm: str) -> None:
    from flask_login import current_user
    from ..rbac import has_permission
    if not has_permission(current_user, perm):
        raise PermissionError(f"your account lacks the '{perm}' permission, "
                              "so Scout cannot read this for you")


def _visible_ids() -> list[int]:
    from ..models import Appliance, visible_appliances
    return [a.id for a in visible_appliances().with_entities(Appliance.id).all()]


def _me() -> str:
    from flask_login import current_user
    return getattr(current_user, "username", "") or ""


def _is_admin() -> bool:
    from flask_login import current_user
    can = getattr(current_user, "can", None)
    return bool(can and can("user_manage"))


# ---------------------------------------------------------------------------
# Sentinel
# ---------------------------------------------------------------------------

_INCIDENT_KEYS = ("id", "ref", "opened_at", "last_event_at", "status", "device",
                  "policy", "src_ip", "src_country", "attack_family", "severity",
                  "event_count", "blocked_count", "passed_count", "score", "band",
                  "impact", "exploit_available", "target_vulnerable", "waf_blocked",
                  "fp_reason")


def list_incidents(appliance_id: int = 0, status: str = "open", limit: int = 10) -> list[dict]:
    """Sentinel incidents on appliances this ADOM sees, newest first."""
    _need("monitoring.view")
    from ..models_sentinel import SentinelIncident
    ids = _visible_ids()
    if appliance_id:
        ids = [i for i in ids if i == int(appliance_id)]
    if not ids:
        return []
    q = SentinelIncident.query.filter(SentinelIncident.appliance_id.in_(ids))
    st = (status or "").strip().lower()
    if st and st != "all":
        q = q.filter(SentinelIncident.status == st)
    rows = (q.order_by(SentinelIncident.last_event_at.desc().nullslast(),
                       SentinelIncident.id.desc())
            .limit(_int(limit, 10, 1, MAX_ROWS)).all())
    out = []
    for r in rows:
        d = r.to_dict()
        out.append({k: d.get(k) for k in _INCIDENT_KEYS})
    return out


def incident(incident: str) -> dict:
    """One incident (by id or ``INC-…`` reference) with its newest events.
    Not visible = not found, never "forbidden": do not confirm it exists."""
    _need("monitoring.view")
    from ..models_sentinel import SentinelEvent, SentinelIncident
    key = str(incident or "").strip()
    q = SentinelIncident.query
    row = (q.filter(SentinelIncident.id == int(key)).first() if key.isdigit()
           else q.filter(SentinelIncident.ref == key).first())
    if row is None or row.appliance_id not in set(_visible_ids()):
        raise LookupError(f"incident {key!r} not found")
    d = row.to_dict()
    out = {k: d.get(k) for k in _INCIDENT_KEYS}
    out["score_factors"] = d.get("score_factors")
    out["model_opinion"] = d.get("ai") or {}
    evs = (SentinelEvent.query.filter(SentinelEvent.incident_id == row.id)
           .order_by(SentinelEvent.ts.desc()).limit(20).all())
    out["events"] = [_event_row(e) for e in evs]
    return out


def _event_row(e) -> dict:
    return {"ts": e.ts.isoformat(timespec="seconds") if e.ts else "",
            "device": e.device or "", "source": e.source or "",
            "policy": e.policy or "", "src_ip": e.src_ip or "",
            "dst": f"{e.dst_ip or ''}:{e.dst_port or ''}".strip(":"),
            "method": e.http_method or "", "uri": _clip(e.uri, 200),
            "status": e.http_status, "signature": _clip(e.signature, 160),
            "family": e.attack_family or "", "severity": e.severity or "",
            "action": e.action or "", "count": e.count or 1}


# ---------------------------------------------------------------------------
# jobs -- what SATOM itself did against the box
# ---------------------------------------------------------------------------

def _job_visible(st: dict) -> bool:
    from .product_scope import visible_product
    if not visible_product((st.get("meta") or {}).get("product")):
        return False
    return _is_admin() or (st.get("by") or "") == _me()


def _job_summary(st: dict) -> dict:
    meta = st.get("meta") or {}
    steps = meta.get("steps") or []
    return {"id": st.get("id"), "type": st.get("type"), "title": _clip(st.get("title"), 160),
            "status": st.get("status"), "by": st.get("by"),
            "created": st.get("created"), "finished": st.get("finished"),
            "appliance_id": meta.get("appliance_id"),
            "message": _clip(st.get("message"), 200),
            "error": _clip(st.get("error"), 300) if st.get("error") else "",
            "steps": len(steps),
            "failed_steps": sum(1 for s in steps if not s.get("ok", True))}


def recent_jobs(appliance_id: int = 0, status: str = "", limit: int = 10) -> list[dict]:
    """The Jobs page's rule: your own jobs (all of them for an admin), in this
    ADOM, newest first."""
    from . import jobs as jobsvc
    by = None if _is_admin() else _me()
    rows = jobsvc.list_jobs(limit=200, by=by, status=(status or None),
                            appliance_id=int(appliance_id) if appliance_id else None)
    n = _int(limit, 10, 1, MAX_ROWS)
    out = [_job_summary(st) for st in rows if _job_visible(st)]
    return out[:n]


def job_detail(job_id: str) -> dict:
    """One job with its last 40 steps (each REST call / SSH command, outcome,
    duration). Not visible = not found."""
    from . import jobs as jobsvc
    jid = str(job_id or "").strip()
    st = jobsvc.get_job(jid) if jid and "/" not in jid and ".." not in jid else None
    if st is None or not _job_visible(st):
        raise LookupError(f"job {jid!r} not found")
    out = _job_summary(st)
    steps = (st.get("meta") or {}).get("steps") or []
    out["last_steps"] = [{"at": s.get("at"), "call": _clip(s.get("label"), 160),
                          "outcome": s.get("outcome", ""), "ok": s.get("ok", True),
                          "ms": s.get("ms")} for s in steps[-40:]]
    return out


# ---------------------------------------------------------------------------
# audit log -- who changed what
# ---------------------------------------------------------------------------

def audit_events(action: str = "", target: str = "", minutes: int = 1440,
                 limit: int = 25) -> list[dict]:
    """Audit rows of this ADOM, newest first -- the Audit Log page's gate."""
    _need("audit.view")
    from ..models import AuditLog
    from .product_scope import scope_query
    since = datetime.utcnow() - timedelta(minutes=_int(minutes, 1440, 1, 43200))
    q = scope_query(AuditLog.query, AuditLog.product).filter(AuditLog.timestamp >= since)
    if (action or "").strip():
        q = q.filter(AuditLog.action.ilike(f"%{action.strip()}%"))
    if (target or "").strip():
        q = q.filter(AuditLog.target.ilike(f"%{target.strip()}%"))
    rows = q.order_by(AuditLog.timestamp.desc()).limit(_int(limit, 25, 1, MAX_ROWS)).all()
    return [{"at": r.timestamp.isoformat(timespec="seconds"), "user": r.username,
             "action": r.action, "target": _clip(r.target, 160),
             "extra": _clip(r.extra, 300)} for r in rows]


# ---------------------------------------------------------------------------
# alerts -- what reached the operator's bell
# ---------------------------------------------------------------------------

def recent_alerts(minutes: int = 1440, unread_only: bool = False,
                  limit: int = 25) -> list[dict]:
    """The operator's OWN notifications (the bell) in this ADOM: failed jobs,
    monitor and capacity alerts, certificate and licence warnings. Never
    another user's -- the bell is per user and so is this."""
    from flask_login import current_user
    from ..models_notifications import Notification
    from .product_scope import scope_query
    uid = getattr(current_user, "id", None)
    if uid is None:
        return []
    since = datetime.utcnow() - timedelta(minutes=_int(minutes, 1440, 1, 43200))
    q = scope_query(Notification.query, Notification.product).filter(
        Notification.user_id == uid, Notification.created_at >= since)
    if unread_only in (True, "true", "1", 1):
        q = q.filter(Notification.read.is_(False))
    rows = q.order_by(Notification.created_at.desc()).limit(_int(limit, 25, 1, MAX_ROWS)).all()
    return [{"at": r.created_at.isoformat(timespec="seconds"), "kind": r.kind,
             "title": _clip(r.title, 200), "body": _clip(r.body, 300),
             "read": bool(r.read)} for r in rows]


# ---------------------------------------------------------------------------
# logs -- every source, one window, each with its own status
# ---------------------------------------------------------------------------

def _matches(row, q: str) -> bool:
    if not q:
        return True
    return q.lower() in json.dumps(row, default=str, ensure_ascii=False).lower()


def _src(name: str, status: str, detail: str = "", rows=None, **extra) -> dict:
    d = {"source": name, "status": status, "detail": detail, "rows": rows or []}
    d.update(extra)
    return d


def _from_sentinel(ap, q, start, end, limit) -> dict:
    from ..models_sentinel import SentinelEvent
    try:
        _need("monitoring.view")
    except PermissionError as exc:
        return _src("sentinel", "forbidden", str(exc))
    qry = SentinelEvent.query.filter(SentinelEvent.ts >= start, SentinelEvent.ts <= end)
    if ap is not None:
        qry = qry.filter(SentinelEvent.appliance_id == ap.id)
    else:
        qry = qry.filter(SentinelEvent.appliance_id.in_(_visible_ids()))
    rows = [_event_row(e) for e in qry.order_by(SentinelEvent.ts.desc()).limit(500).all()]
    rows = [r for r in rows if _matches(r, q)][:limit]
    return _src("sentinel", "ok" if rows else "no_match",
                "" if rows else "Sentinel holds no matching event in this window "
                "(it only ingests attack logs, syslog and FAZ events it was fed)",
                rows)


def _from_syslog(ap, q, start, end, limit) -> dict:
    from . import syslog_receiver
    st = syslog_receiver.read_state() or {}
    if not st.get("enabled"):
        return _src("syslog", "disabled", "the syslog receiver is switched off "
                    "(Monitoring -> Collection)")
    if not st.get("running") or st.get("error"):
        return _src("syslog", "error", st.get("error") or st.get("reason")
                    or "the receiver is not running on this node")
    want = (ap.name if ap is not None else "")
    rows = []
    for m in reversed(st.get("recent") or []):
        try:
            at = datetime.fromisoformat(str(m.get("at"))).replace(tzinfo=None)
        except ValueError:
            continue
        if not (start <= at <= end):
            continue
        if want and m.get("device") != want:
            continue
        row = {"at": m.get("at"), "device": m.get("device"), "severity": m.get("severity"),
               "app": m.get("app"), "text": _clip(m.get("text"))}
        if _matches(row, q):
            rows.append(row)
        if len(rows) >= limit:
            break
    detail = ""
    if not rows:
        detail = ("the receiver keeps only the last 500 messages; none matched. "
                  f"It has received {st.get('received', 0)} and dropped "
                  f"{sum((st.get('dropped') or {}).values())} since it started")
    return _src("syslog", "ok" if rows else "no_match", detail, rows,
                note="ring buffer of the last 500 messages, not a log store")


def _from_faz(ap, q, start, end, limit, timeout) -> dict:
    if ap is None:
        return _src("fortianalyzer", "not_configured",
                    "pass appliance_id: the FortiAnalyzer is chosen per appliance "
                    "by its edge-map row (Sentinel -> Edge map)")
    from ..extensions import db
    from ..models import Appliance
    from ..models_sentinel import SentinelEdgeMap
    from . import faz_logs
    em = SentinelEdgeMap.query.filter_by(appliance_id=ap.id).first()
    if em is None or not em.analyzer_id:
        return _src("fortianalyzer", "not_configured",
                    "no edge-map row for this appliance, so no FortiAnalyzer was "
                    "asked -- this is not 'no logs'")
    faz = db.session.get(Appliance, em.analyzer_id)
    if faz is None:
        return _src("fortianalyzer", "error", "the edge map points at a deleted analyzer")
    ok, why = faz_logs.reachable(faz)
    if not ok:
        return _src("fortianalyzer", "error", f"{faz.name}: {why}")
    rows, err = faz_logs.search(
        faz, adom=em.adom or "root",
        devices=faz_logs.device_selector(em.fortigate, em.vdom),
        logtype=em.logtype or "traffic", start=start, end=end,
        limit=200, timeout=timeout)
    if err:
        return _src("fortianalyzer", "error", f"{faz.name}: {err}")
    rows = [{k: _clip(v, 160) for k, v in r.items()} for r in rows
            if isinstance(r, dict) and _matches(r, q)][:limit]
    return _src("fortianalyzer", "ok" if rows else "no_match",
                "" if rows else f"{faz.name} answered and matched nothing",
                rows, analyzer=faz.name,
                note="unverified against a live FortiAnalyzer in this lab")


def _from_external(src, ap, q, start, end, limit, timeout) -> dict:
    from . import log_sources
    name = f"external:{src['key']}"
    if src.get("enabled") is False:
        return _src(name, "disabled", "switched off in Settings -> AI -> Log sources")
    terms = [ap.name, ap.host] if ap is not None else []
    rows, err, query = log_sources.search(src, device_terms=terms, query=q,
                                          start=start, end=end, limit=limit,
                                          timeout=timeout)
    extra = {"label": src.get("label"), "kind": src.get("kind"), "query": query}
    if not log_sources.KINDS.get(src.get("kind"), {}).get("verified"):
        extra["note"] = "connector unverified against a live instance of this SIEM"
    if err:
        return _src(name, "error", err, **extra)
    rows = [{k: _clip(v) for k, v in r.items()} for r in rows]
    return _src(name, "ok" if rows else "no_match",
                "" if rows else "the SIEM answered and matched nothing", rows, **extra)


def search_logs(appliance_id: int = 0, query: str = "", minutes: int = 60,
                report_id: int = 0, source: str = "", limit: int = 20,
                timeout: float = 20.0) -> dict:
    """The logs of ONE window from every source SATOM can read, side by side.

    ``report_id`` anchors the window on a saved Path Diagnostics walk (its
    appliance, and ``minutes`` before it to five minutes after) -- the
    correlation an operator wants. ``query`` is a free-text term (a client or
    backend IP, a URL, an error word); for a non-Fortinet device in the path
    (a Cisco in front of the FortiWeb) pass its address here without an
    appliance, and only the external sources can answer."""
    from ..extensions import db
    from ..models import visible_appliance_or_404
    w = _int(minutes, 60, 1, MAX_WINDOW_MINUTES)
    end = datetime.utcnow()
    ap = None
    if report_id:
        from ..models_pathdiag import PathDiagReport
        rep = db.session.get(PathDiagReport, int(report_id))
        if rep is None or rep.appliance_id is None:
            raise LookupError(f"report {report_id} not found")
        ap = visible_appliance_or_404(rep.appliance_id)
        end = rep.created_at + timedelta(minutes=5)
    elif appliance_id:
        ap = visible_appliance_or_404(int(appliance_id))
    q = (query or "").strip()[:200]
    if ap is None and not q:
        raise ValueError("pass appliance_id, report_id or a query term")
    start = end - timedelta(minutes=w)
    n = _int(limit, 20, 1, MAX_ROWS)
    t = max(2.0, min(float(timeout or 20.0), 30.0))
    want = (source or "").strip().lower()

    from . import log_sources
    plan = [("sentinel", lambda: _from_sentinel(ap, q, start, end, n)),
            ("syslog", lambda: _from_syslog(ap, q, start, end, n)),
            ("fortianalyzer", lambda: _from_faz(ap, q, start, end, n, t))]
    externals = log_sources.list_sources()
    for s in externals:
        plan.append((f"external:{s['key']}",
                     lambda s=s: _from_external(s, ap, q, start, end, n, t)))
    out = []
    for name, fn in plan:
        if want and want not in (name, name.split(":", 1)[-1]):
            continue
        try:
            out.append(fn())
        except Exception as exc:  # noqa: BLE001 -- one source failing never hides the others
            out.append(_src(name, "error", f"{type(exc).__name__}: {str(exc)[:200]}"))
    if not externals and (not want or want.startswith("external")):
        out.append(_src("external", "not_configured",
                        "no external log source (Splunk…) is configured; logs of "
                        "non-Fortinet devices in the path cannot be read"))
    return {"window": {"start": start.isoformat(timespec="seconds") + "Z",
                       "end": end.isoformat(timespec="seconds") + "Z", "minutes": w},
            "appliance": ap.name if ap is not None else "", "query": q,
            "sources": fit_budget(out)}


#: Under the advisor's per-result cap (8000 bytes) with room for the envelope.
RESULT_BUDGET = 6500


def fit_budget(sources: list[dict], budget: int = RESULT_BUDGET) -> list[dict]:
    """Trim rows from the LONGEST source first until the whole fits. The
    advisor would otherwise truncate the JSON at the end -- which is where the
    external sources sit, so the hop most likely at fault would vanish first.
    Every source keeps its status line, and a trim is announced in band."""
    def size():
        return len(json.dumps(sources, default=str, ensure_ascii=False).encode())
    while size() > budget:
        longest = max(sources, key=lambda s: len(s.get("rows") or []), default=None)
        if not longest or not longest.get("rows"):
            break
        longest["rows"].pop()
        longest["rows_omitted"] = int(longest.get("rows_omitted") or 0) + 1
    return sources


__all__ = ["list_incidents", "incident", "recent_jobs", "job_detail",
           "audit_events", "recent_alerts", "search_logs", "fit_budget"]
