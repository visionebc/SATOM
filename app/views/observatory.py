# app/views/observatory.py
"""HTTP Observatory — Troubleshooting page: grade the sites the appliances
publish, explain each finding and fix it on the FortiWeb.

Gates, because two of these endpoints make the server act:

* ``/api/scan`` makes THIS SERVER send GET/OPTIONS requests — but only to the
  VIP of a server policy (or FortiADC virtual server) read from a device the
  user can see (:func:`visible_appliance_or_404`, ADOM confinement included).
  The operator names the site, never the address, so it needs ``view`` like
  the tracer's inventory mode and no free-target permission.
* ``/api/plan`` and ``/api/apply`` change appliance configuration:
  ``config_write``, FortiWebOps (dry-run, ChangeHistory, re-read
  verification), the template lock, edit leases, and an explicit
  acknowledgement when the change reaches other server policies.

Every scan and every fix is audited.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Appliance, visible_appliance_or_404, visible_appliances
from ..services import header_observatory as ho
from ..services import observatory, observatory_fix as ofx, observatory_scan as osc
from ..services.audit import log_action

bp = Blueprint("observatory", __name__, url_prefix="/observatory")


def _username() -> str:
    return getattr(current_user, "username", "") or ""


def _appliances():
    return (visible_appliances(Appliance.query)
            .filter(Appliance.kind.in_(osc.PRODUCTS))
            .order_by(Appliance.name).all())


def _appliance(appliance_id):
    appl = visible_appliance_or_404(int(appliance_id or 0))
    if appl.kind not in osc.PRODUCTS:
        return None
    return appl


def _host_arg(raw) -> str:
    """The site name the operator typed — a NAME (Host / SNI), never an
    address to dial; the VIP is always the policy's."""
    host = str(raw or "").strip().lower().rstrip(".")
    if not host:
        return ""
    if len(host) > 253 or any(ch in host for ch in " /\\@?#\r\n\t"):
        raise ValueError("the site name must be a bare host name (no scheme, path or port)")
    return host


def _context(appl, policy):
    """``(ctx, error)`` — the appliance configuration for attribution."""
    if appl.kind != "fortiweb":
        return None, ""
    try:
        return ofx.read_context(appl, policy), ""
    except Exception as exc:  # noqa: BLE001 — findings still render without it
        return None, "could not read the configuration of %s: %s" % (policy, exc)


def _view(row, appl, *, with_findings=True) -> dict:
    data = row.result_dict
    out = {"scan": row.summary(), "target": data.get("target") or {},
           "analysis": data.get("analysis"), "retrieval": data.get("retrieval") or {},
           "findings": [], "context_error": ""}
    prev = observatory.previous(row)
    out["previous"] = prev.summary() if prev else None
    if with_findings and data.get("analysis"):
        ctx, err = _context(appl, row.policy)
        out["context_error"] = err
        out["findings"] = ofx.findings(data["analysis"], data.get("retrieval") or {},
                                       ctx, target=data.get("target") or {})
        if ctx is not None:
            out["context"] = {"wpp": ctx.get("wpp"), "hhs": ctx.get("hhs"),
                              "cks": ctx.get("cks"), "version": ctx.get("version"),
                              "wpp_policies": ctx.get("wpp_policies"),
                              "wpp_managed": ctx.get("wpp_managed")}
        trust = ofx.project(data["analysis"], data.get("retrieval") or {},
                            {"trust_certificate": True})
        if trust and trust.get("score") != row.score:
            out["if_certificate_trusted"] = {"score": trust["score"], "grade": trust["grade"]}
    return out


@bp.route("/")
@login_required
@require_permission("view")
def index():
    """Troubleshooting › HTTP Observatory."""
    rows = [{"id": a.id, "name": a.name, "kind": a.kind} for a in _appliances()]
    want = request.args.get("appliance", type=int)
    return render_template("observatory/index.html", appliances=rows,
                           selected=want if any(r["id"] == want for r in rows) else
                           (rows[0]["id"] if rows else None),
                           may_fix=current_user.can("config_write"),
                           prefill_policy=str(request.args.get("policy") or "")[:128],
                           tests=ho.TESTS)


@bp.route("/api/targets")
@login_required
@require_permission("view")
def api_targets():
    """Published sites of one appliance (reads the device) + their last grade."""
    appl = _appliance(request.args.get("appliance_id"))
    if appl is None:
        return jsonify(ok=False, error="The HTTP Observatory grades FortiWeb and FortiADC "
                                       "published sites only."), 400
    try:
        targets = osc.targets_for(appl)
    except Exception as exc:  # noqa: BLE001 — unreadable box: say so, never "no sites"
        return jsonify(ok=False, error="Could not list the published sites of %s: %s"
                                       % (appl.name, exc)), 502
    latest = observatory.latest_by_policy(appl.id)
    rows = []
    for t in targets:
        d = t.as_dict()
        last = latest.get(t.policy)
        d["last"] = last.summary() if last else None
        rows.append(d)
    return jsonify(ok=True, appliance={"id": appl.id, "name": appl.name, "kind": appl.kind},
                   targets=rows)


@bp.route("/api/scan", methods=["POST"])
@login_required
@require_permission("view")
def api_scan():
    """Grade one published site and store the result."""
    body = request.get_json(silent=True) or {}
    appl = _appliance(body.get("appliance_id"))
    if appl is None:
        return jsonify(ok=False, error="Not a FortiWeb or FortiADC appliance."), 400
    policy = str(body.get("policy") or "").strip()
    try:
        host = _host_arg(body.get("host"))
    except ValueError as exc:
        return jsonify(ok=False, error=str(exc)), 400
    try:
        target = osc.find_target(appl, policy)
    except Exception as exc:  # noqa: BLE001
        return jsonify(ok=False, error="Could not read %s: %s" % (appl.name, exc)), 502
    if target is None:
        return jsonify(ok=False, error="%s has no published site named %s."
                                       % (appl.name, policy)), 404
    row = observatory.run(appl, target, host or None, trigger="manual",
                          username=_username())
    log_action("observatory.scan", target="%s:%s" % (appl.name, policy),
               extra={"appliance_id": appl.id, "host": row.host, "grade": row.grade, "score": row.score,
                      "error": (row.error or "")[:200]})
    return jsonify(ok=True, **_view(row, appl))


@bp.route("/api/scan/<int:scan_id>")
@login_required
@require_permission("view")
def api_scan_get(scan_id):
    from ..models_observatory import ObservatoryScan
    from ..extensions import db
    row = db.session.get(ObservatoryScan, scan_id)
    if row is None:
        return jsonify(ok=False, error="scan not found"), 404
    appl = visible_appliance_or_404(row.appliance_id)
    return jsonify(ok=True, **_view(row, appl))


@bp.route("/api/history")
@login_required
@require_permission("view")
def api_history():
    appl = _appliance(request.args.get("appliance_id"))
    if appl is None:
        return jsonify(ok=False, error="Not a FortiWeb or FortiADC appliance."), 400
    policy = str(request.args.get("policy") or "")
    return jsonify(ok=True, scans=[r.summary() for r in observatory.history(appl.id, policy)])


def _download(data, mimetype, filename):
    from flask import Response
    resp = Response(data, mimetype=mimetype)
    resp.headers["Content-Disposition"] = 'attachment; filename="%s"' % filename
    resp.headers["Cache-Control"] = "no-store"
    return resp


def _file_part(text: str) -> str:
    import re
    return re.sub(r"[^A-Za-z0-9._-]+", "-", text or "")[:60].strip("-") or "site"


@bp.route("/api/export.csv")
@login_required
@require_permission("view")
def api_export_csv():
    """Every published site of one appliance with its latest grade (CSV)."""
    from datetime import datetime
    from ..services import observatory_report
    appl = _appliance(request.args.get("appliance_id"))
    if appl is None:
        return jsonify(ok=False, error="Not a FortiWeb or FortiADC appliance."), 400
    latest = observatory.latest_by_policy(appl.id)
    try:
        targets, err = osc.targets_for(appl), ""
    except Exception as exc:  # noqa: BLE001 — stored grades still export, marked
        targets, err = [], "the appliance could not be listed (%s); stored grades only" % str(exc)[:120]
    data = observatory_report.sites_csv(appl, targets, latest, listing_error=err)
    log_action("observatory.export", target=appl.name,
               extra={"appliance_id": appl.id, "format": "csv",
                      "rows": len(targets) or len(latest)})
    return _download(data, "text/csv; charset=utf-8", "observatory-%s-%s.csv" % (
        _file_part(appl.name), datetime.utcnow().strftime("%Y%m%d-%H%M")))


@bp.route("/api/scan/<int:scan_id>/report.pdf")
@login_required
@require_permission("view")
def api_scan_pdf(scan_id):
    """One scan as a PDF report (the findings the page shows)."""
    from ..extensions import db
    from ..models_observatory import ObservatoryScan
    from ..services import observatory_report
    row = db.session.get(ObservatoryScan, scan_id)
    if row is None:
        return jsonify(ok=False, error="scan not found"), 404
    appl = visible_appliance_or_404(row.appliance_id)
    data = observatory_report.scan_pdf(_view(row, appl), appliance_name=appl.name,
                                       generated_by=_username())
    log_action("observatory.export", target="%s:%s" % (appl.name, row.policy),
               extra={"appliance_id": appl.id, "format": "pdf", "scan_id": row.id})
    return _download(data, "application/pdf", "observatory-%s-%s-%s.pdf" % (
        _file_part(appl.name), _file_part(row.policy),
        row.started_at.strftime("%Y%m%d-%H%M") if row.started_at else row.id))


def _plan_request(body):
    """``(appliance, row, items, ctx, plan, projection)`` or a ready error."""
    from ..models_observatory import ObservatoryScan
    from ..extensions import db
    row = db.session.get(ObservatoryScan, int(body.get("scan_id") or 0))
    if row is None:
        return None, (jsonify(ok=False, error="scan not found"), 404)
    appl = visible_appliance_or_404(row.appliance_id)
    if appl.kind != "fortiweb":
        return None, (jsonify(ok=False, error="SATOM applies Observatory fixes on FortiWeb only."), 400)
    raw = body.get("items") or []
    if not isinstance(raw, list) or not raw:
        return None, (jsonify(ok=False, error="Pick at least one fix."), 400)
    items = []
    for it in raw[:20]:
        if not isinstance(it, dict) or not it.get("fix"):
            return None, (jsonify(ok=False, error="each item needs a fix id"), 400)
        opts = it.get("options") if isinstance(it.get("options"), dict) else {}
        items.append((str(it["fix"]), opts))
    try:
        ctx = ofx.read_context(appl, row.policy)
    except Exception as exc:  # noqa: BLE001
        return None, (jsonify(ok=False, error="Could not read %s: %s" % (row.policy, exc)), 502)
    try:
        the_plan = ofx.plan_many(appl, row.policy, items, ctx)
    except ofx.FixRefused as exc:
        return None, (jsonify(ok=False, error=str(exc)), 409)
    data = row.result_dict
    projection = ofx.project(data.get("analysis") or {}, data.get("retrieval") or {},
                             ofx.merge_effects([ofx.effects_of(f, o, ctx) for f, o in items]))
    return (appl, row, items, ctx, the_plan, projection), None


@bp.route("/api/plan", methods=["POST"])
@login_required
@require_permission("config_write")
def api_plan():
    """What a set of fixes would write, who else it reaches, and the grade it
    would give. Sends nothing to the device."""
    res, err = _plan_request(request.get_json(silent=True) or {})
    if err:
        return err
    appl, row, items, ctx, the_plan, projection = res
    return jsonify(ok=True, plan=the_plan, projection=projection,
                   current={"grade": row.grade, "score": row.score})


@bp.route("/api/apply", methods=["POST"])
@login_required
@require_permission("config_write")
def api_apply():
    """Apply the fixes, then grade the site again."""
    body = request.get_json(silent=True) or {}
    res, err = _plan_request(body)
    if err:
        return err
    appl, row, items, ctx, the_plan, projection = res
    try:
        out = ofx.apply(appl, the_plan, ack_shared=bool(body.get("ack_shared")),
                        user_id=getattr(current_user, "id", None))
    except ofx.FixRefused as exc:
        log_action("observatory.fix.refused", target="%s:%s" % (appl.name, row.policy),
                   extra={"appliance_id": appl.id, "fixes": [f for f, _o in items],
                                                "reason": str(exc)[:300]})
        return jsonify(ok=False, error=str(exc), plan=the_plan), 409
    log_action("observatory.fix", target="%s:%s" % (appl.name, row.policy),
               extra={"appliance_id": appl.id, "fixes": [f for f, _o in items], "ok": out["ok"],
                      "writes": [r["describe"] for r in out["results"]],
                      "error": out.get("error", "")[:300],
                      "affected_policies": the_plan.get("affected_policies")})
    fix = observatory.record_fix(appl, row.policy, the_plan, out, scan_id=row.id,
                                 username=_username())
    after = _regrade(appl, row.policy, row.host)
    if fix is not None and after is not None:
        fix.after_scan_id = after["scan"]["id"]
        from ..extensions import db
        db.session.commit()
    return jsonify(ok=out["ok"], error=out.get("error", ""), results=out["results"],
                   plan=the_plan, projection=projection, after=after,
                   fix=fix.summary() if fix is not None else None)


def _regrade(appl, policy, host):
    """Grade the site again after a write (the change stands either way; the
    re-grade is how the operator sees what it did)."""
    try:
        target = osc.find_target(appl, policy)
    except Exception:  # noqa: BLE001
        target = None
    if target is None:
        return None
    new = observatory.run(appl, target, host or None, trigger="fix", username=_username())
    return _view(new, appl)


def _fix_or_404(fix_id):
    from flask import abort
    from ..extensions import db
    from ..models_observatory import ObservatoryFix
    fix = db.session.get(ObservatoryFix, int(fix_id))
    if fix is None:
        abort(404)
    appl = visible_appliance_or_404(fix.appliance_id)
    return fix, appl


@bp.route("/api/fixes")
@login_required
@require_permission("view")
def api_fixes():
    """The fixes applied to one site, newest first, with their revert state."""
    appl = _appliance(request.args.get("appliance_id"))
    if appl is None:
        return jsonify(ok=False, error="Not a FortiWeb or FortiADC appliance."), 400
    policy = str(request.args.get("policy") or "")
    return jsonify(ok=True, fixes=[f.summary() for f in observatory.fixes(appl.id, policy)])


@bp.route("/api/fix/<int:fix_id>/revert-plan", methods=["POST"])
@login_required
@require_permission("config_write")
def api_revert_plan(fix_id):
    """What reverting a fix would write, read against the device now."""
    fix, appl = _fix_or_404(fix_id)
    try:
        rp = ofx.revert_plan(appl, fix)
    except ofx.FixRefused as exc:
        return jsonify(ok=False, error=str(exc)), 409
    except Exception as exc:  # noqa: BLE001 — unreadable box: say so
        return jsonify(ok=False, error="Could not read %s: %s" % (appl.name, exc)), 502
    return jsonify(ok=True, plan=rp, fix=fix.summary())


@bp.route("/api/fix/<int:fix_id>/revert", methods=["POST"])
@login_required
@require_permission("config_write")
def api_revert(fix_id):
    """Revert a fix, then grade the site again."""
    from datetime import datetime
    import json as _json
    from ..extensions import db
    fix, appl = _fix_or_404(fix_id)
    body = request.get_json(silent=True) or {}
    try:
        out = ofx.revert(appl, fix, ack_shared=bool(body.get("ack_shared")),
                         user_id=getattr(current_user, "id", None))
    except ofx.FixRefused as exc:
        log_action("observatory.fix.revert.refused", target="%s:%s" % (appl.name, fix.policy),
                   extra={"appliance_id": appl.id, "fix_id": fix.id, "reason": str(exc)[:300]})
        return jsonify(ok=False, error=str(exc)), 409
    except Exception as exc:  # noqa: BLE001
        return jsonify(ok=False, error="Could not read %s: %s" % (appl.name, exc)), 502
    fix.revert_result = _json.dumps(out["results"])
    if out["reverted"]:
        fix.reverted_at = datetime.utcnow()
        fix.reverted_by = _username()[:64]
    db.session.commit()
    log_action("observatory.fix.revert", target="%s:%s" % (appl.name, fix.policy),
               extra={"appliance_id": appl.id, "fix_id": fix.id, "ok": out["ok"],
                      "reverted": out["reverted"],
                      "writes": [r["describe"] for r in out["results"]],
                      "error": (out.get("error") or "")[:300]})
    from ..models_observatory import ObservatoryScan
    planned_from = db.session.get(ObservatoryScan, fix.scan_id) if fix.scan_id else None
    after = (_regrade(appl, fix.policy, planned_from.host if planned_from else "")
             if out["results"] else None)
    return jsonify(ok=out["ok"], error=out.get("error", ""), results=out["results"],
                   reverted=out["reverted"], plan=out["plan"], after=after, fix=fix.summary())


#: Refreshing or importing the preload list replaces node data every grade
#: reads: the permission that runs scheduled actions (the weekly refresh is
#: one), not a viewer's.
PRELOAD_PERMISSION = "operations.apply"


@bp.route("/api/hsts-preload")
@login_required
@require_permission("view")
def api_preload_status():
    from ..services import hsts_preload
    return jsonify(ok=True, status=hsts_preload.status(),
                   may_refresh=current_user.can(PRELOAD_PERMISSION))


@bp.route("/api/hsts-preload/refresh", methods=["POST"])
@login_required
@require_permission("view")
def api_preload_refresh():
    """Download the list now (what the weekly action does)."""
    from ..services import hsts_preload
    if not current_user.can(PRELOAD_PERMISSION):
        return jsonify(ok=False, error="Refreshing the HSTS preload list needs Run operations."), 403
    try:
        meta = hsts_preload.refresh()
    except hsts_preload.PreloadError as exc:
        log_action("observatory.hsts_preload.refresh", target="hsts-preload",
                   extra={"ok": False, "error": str(exc)[:200]})
        return jsonify(ok=False, error=str(exc), status=hsts_preload.status()), 502
    log_action("observatory.hsts_preload.refresh", target="hsts-preload",
               extra={"ok": True, "count": meta.get("count")})
    return jsonify(ok=True, status=hsts_preload.status())


@bp.route("/api/hsts-preload/import", methods=["POST"])
@login_required
@require_permission("view")
def api_preload_import():
    """Store an uploaded copy of Chromium's transport_security_state_static.json
    (a node without internet access)."""
    from ..services import hsts_preload
    if not current_user.can(PRELOAD_PERMISSION):
        return jsonify(ok=False, error="Importing the HSTS preload list needs Run operations."), 403
    f = request.files.get("file")
    if f is None:
        return jsonify(ok=False, error="Choose the Chromium transport_security_state_static.json file."), 400
    raw = f.stream.read(hsts_preload.MAX_BYTES + 1)
    try:
        meta = hsts_preload.import_bytes(raw, origin="upload by %s" % _username())
    except hsts_preload.PreloadError as exc:
        return jsonify(ok=False, error=str(exc), status=hsts_preload.status()), 400
    log_action("observatory.hsts_preload.import", target="hsts-preload",
               extra={"count": meta.get("count"), "bytes": len(raw)})
    return jsonify(ok=True, status=hsts_preload.status())


@bp.route("/api/grade-headers", methods=["POST"])
@login_required
@require_permission("view")
def api_grade_headers():
    """The header-only part of the grade for ONE response the caller already
    has (the Transaction Tracer's leg A). No request is made: it scores what
    it is given. Partial by construction — no redirect chain, no page body,
    no CORS preflight, certificate trust unknown — and labelled so."""
    body = request.get_json(silent=True) or {}
    headers = body.get("headers") or []
    if not isinstance(headers, list):
        return jsonify(ok=False, error="headers must be a list"), 400
    clean = [[str(h[0])[:128], str(h[1])[:4096]] for h in headers[:200]
             if isinstance(h, (list, tuple)) and len(h) == 2]
    cookies = [c for c in (body.get("set_cookie") or [])[:100] if isinstance(c, dict)]
    url = str(body.get("url") or "")[:2048]
    resp = {"status": 200, "headers": clean, "set_cookie": cookies,
            "verified": True, "body": ""}
    host = ho._host_of(url)
    req = {"host": host, "auto": resp, "auto_url": url,
           "https": resp if url.lower().startswith("https:") else None,
           "cookies": cookies}
    try:
        from ..services import hsts_preload
        req["hsts_preload"] = hsts_preload.lookup_many([host])
    except Exception:  # noqa: BLE001 — no list: nothing is preloaded
        req["hsts_preload"] = {}
    tests = []
    with_extra = uncurved = 100
    for name in ("content-security-policy", "x-frame-options", "x-content-type-options",
                 "referrer-policy", "cross-origin-resource-policy",
                 "cross-origin-opener-policy", "cross-origin-embedder-policy",
                 "strict-transport-security", "cookies"):
        r = ho.ALL_TESTS[name](req)
        mod = ho.SCORE_TABLE.get(r["result"], (0, "", ""))[0]
        with_extra += mod
        if mod < 0:
            uncurved += mod
        tests.append({"name": name, "title": ho.TEST_TITLES[name],
                      "result": r["result"], "modifier": mod, "pass": r["pass"]})
    score = max(with_extra if uncurved >= ho.MINIMUM_SCORE_FOR_EXTRA_CREDIT else uncurved, 0)
    return jsonify(ok=True, partial=True, score=score, grade=ho.grade_for(score),
                   tests=tests,
                   note=("Headers of this one response only: redirects, Subresource "
                         "Integrity, CORS and certificate trust are not part of it. "
                         "The HTTP Observatory grades the whole site."))
