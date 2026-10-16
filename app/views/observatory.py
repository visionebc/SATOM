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
    after = None
    if out["results"] and any(r["ok"] for r in out["results"]):
        target = None
        try:
            target = osc.find_target(appl, row.policy)
        except Exception:  # noqa: BLE001 — the fix stands; the re-scan is a bonus
            target = None
        if target is not None:
            new = observatory.run(appl, target, row.host or None, trigger="fix",
                                  username=_username())
            after = _view(new, appl)
    return jsonify(ok=out["ok"], error=out.get("error", ""), results=out["results"],
                   plan=the_plan, projection=projection, after=after)


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
    req = {"host": "", "auto": resp, "auto_url": url,
           "https": resp if url.lower().startswith("https:") else None,
           "cookies": cookies}
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
