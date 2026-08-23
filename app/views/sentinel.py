"""SATOM Sentinel — the console.

Four pages, and the split between them is the product's argument made visible:

* ``/sentinel/`` — the live picture: open incidents, pipeline health, baseline
  coverage, mirror freshness, and the honest state of the response engine.
* ``/sentinel/incident/<id>`` — ONE incident: timeline, evidence table, the
  time-aligned charts, the AI narrative clearly labelled as a model's opinion,
  and every gate that refused an action with its reason.
* ``/sentinel/context`` — trusted sources, maintenance windows, topology and
  the CVE mirror. The operator's levers over false positives.
* ``/sentinel/docs`` — the architecture, rendered FROM the live weight table,
  the live action catalog and the live settings spec. Not a copy of them.

Every one of them is drawn from a partial that the Admin Console also renders
as a pane (Settings → Sentinel), so the two surfaces cannot disagree.

Two rules the routes keep
-------------------------
**A render never touches an appliance.** Every read is DB or loopback metrics
store. During an incident the device is by hypothesis already under load, and
a console that adds round-trips then becomes part of the outage. The one
exception (``/run`` and ``/vuln/sync``) is an explicit operator action, is a
POST, and says so. ``/run`` does not even do it in the request any more: it
starts a JOB over the devices the operator picked, because a synchronous
fleet sweep holds a gunicorn worker for as long as the slowest appliance
takes and reports no progress at all while it does.

**Nothing here executes a response against a device — still true, and now a
division of labour rather than an absence.** Approving an action moves its row
to ``queued``; ``satom-responder.timer`` picks it up in a separate process,
re-runs every gate against the state at that moment, asks the appliance whether
it can even enforce, and only then writes. A bug in this blueprint — a double
submit, a crawler, a stray retry — can at worst enqueue a request that the
runner will refuse on its own merits.

The one route here that does reach a device is ``/arm``, and it is not a
response to anything: it binds Sentinel's IP list to a policy's protection
profile because a person decided that policy may be enforced on. That decision
belongs in the audit log as theirs, never as a side effect of an attack.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from flask import (Blueprint, abort, flash, jsonify, redirect,
                   render_template, request, url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import db, visible_appliances
from ..models_sentinel import (SentinelAction, SentinelEvent, SentinelIncident,
                               SentinelMaintenanceWindow, SentinelPolicy,
                               SentinelTopology, SentinelTrustedSource,
                               SentinelVuln)

bp = Blueprint("sentinel", __name__, url_prefix="/sentinel")


def _svc():
    from ..services.sentinel import (actions, ai, baseline, config, correlate,
                                     incident, pipeline, responder, scoring,
                                     transports, vuln)
    return dict(actions=actions, ai=ai, baseline=baseline, config=config,
                correlate=correlate, incident=incident, pipeline=pipeline,
                responder=responder, scoring=scoring, transports=transports,
                vuln=vuln)


def _visible_names() -> set:
    return {a.name for a in visible_appliances().all()}


def _who() -> str:
    return getattr(current_user, "username", "") or "unknown"


# --------------------------------------------------------------------------- #
#  Console                                                                      #
# --------------------------------------------------------------------------- #
def _health() -> dict:
    """Everything the console needs to say whether Sentinel is actually working.

    Each field answers a question an operator would otherwise have to guess:
    is the pipeline running, can it judge behaviour yet, is the intelligence
    current, and can the response engine actually do anything. A page that
    shows incidents without these four can look perfectly healthy while
    detecting nothing.
    """
    s = _svc()
    from ..services import vm_store
    verified, total = s["actions"].verified_count()
    cov = s["baseline"].coverage()
    store = vm_store.health()
    last_sweep = None
    if store.get("up"):
        res = vm_store.query("satom_sentinel_up")
        points = ((res.get("data") or {}).get("result") or []) \
            if res.get("status") == "success" else []
        if points:
            try:
                last_sweep = float(points[0]["value"][0])
            except (KeyError, IndexError, TypeError, ValueError):
                last_sweep = None
    return {
        "enabled": bool(s["config"].get("enabled")),
        "response_armed": bool(s["config"].get("response_enabled")),
        "ai_enabled": bool(s["config"].get("ai_enabled")),
        "store": store,
        "baseline": cov,
        "vuln": s["vuln"].mirror_health(),
        "catalog_verified": verified, "catalog_total": total,
        "last_sweep_epoch": last_sweep,
        "last_sweep_age_s": (int(datetime.utcnow().timestamp() - last_sweep)
                             if last_sweep else None),
        "protect_errors": s["config"].protect_errors(),
    }


def console_context(status: str = "live", health: dict = None) -> dict:
    """Everything ``sentinel/_console_section.html`` needs — for BOTH surfaces.

    The section is rendered twice from that one file: on this blueprint's own
    page and inside the Admin Console pane Settings -> Sentinel -> Incidents
    console. It is therefore built ONCE, here. A second builder in the settings
    view would let the pane and the page disagree about the very incident list
    and health tiles the section exists to show — and neither would fail; they
    would simply answer differently depending on which URL the operator
    arrived by.

    ``health`` is taken as an argument rather than always recomputed because
    the caller may already hold it: :func:`_health` reaches the metrics store,
    and the Admin Console renders three Sentinel sections in one response.
    """
    s = _svc()
    names = _visible_names()
    q = SentinelIncident.query
    if status == "live":
        q = q.filter(SentinelIncident.status.in_([SentinelIncident.STATUS_OPEN,
                                                  SentinelIncident.STATUS_VERIFYING]))
    elif status != "all":
        q = q.filter(SentinelIncident.status == status)
    rows = [i for i in q.order_by(SentinelIncident.score.desc(),
                                  SentinelIncident.opened_at.desc())
            .limit(300).all() if not names or i.device in names or not i.device]
    return {
        "incidents": [i.to_dict() for i in rows],
        "stats": s["incident"].stats(days=7),
        "health": _health() if health is None else health,
        "status": status,
        "sweep_targets": sweep_targets(),
        "bands": {"observe": SentinelIncident.BAND_OBSERVE,
                  "recommend": SentinelIncident.BAND_RECOMMEND,
                  "semi_auto": SentinelIncident.BAND_SEMI_AUTO}}


@bp.route("/")
@login_required
def index():
    return render_template(
        "sentinel/index.html",
        **console_context(request.args.get("status", "live")))


@bp.route("/data")
@login_required
def data():
    """Poll target for the console. Same numbers, no page reload."""
    s = _svc()
    rows = (SentinelIncident.query
            .filter(SentinelIncident.status.in_([SentinelIncident.STATUS_OPEN,
                                                 SentinelIncident.STATUS_VERIFYING]))
            .order_by(SentinelIncident.score.desc()).limit(300).all())
    return jsonify({"incidents": [i.to_dict() for i in rows],
                    "stats": s["incident"].stats(days=7),
                    "health": _health()})


def _back_to(pane: str, endpoint: str):
    """Where a Sentinel POST returns to: the surface it was fired from.

    The pane posts ``return_to=pane``; anything else (the standalone page, a
    bookmark, a script) keeps the historical redirect. Same contract as the
    Sentinel settings form — an operator who never left the Admin Console must
    not be moved out of it by pressing a button inside it.

    One helper for all four sections rather than four near-copies: the pane
    anchor and the fallback endpoint are the only things that differ, and a
    copy per section is how one of them would keep the old redirect after the
    contract changed — silently, since every copy still works.
    """
    if request.form.get("return_to") == "pane":
        return redirect(url_for("settings.index") + "#" + pane)
    return redirect(url_for(endpoint))


def _back_to_console():
    return _back_to("tab-sentinel-console", "sentinel.index")


def _back_to_context():
    return _back_to("tab-sentinel-context", "sentinel.context")


def _back_to_policies():
    return _back_to("tab-sentinel-policy", "sentinel.policies")


def sweep_targets() -> list:
    """The devices a sweep may read, as rows the picker renders.

    ``eligible`` is why the modal can show a device it will not run: a host in
    maintenance or pointed at ``.invalid`` is deliberately skipped by the
    pipeline, and hiding it would make the omission look like the device does
    not exist. FortiADC is absent for a reason that is not an oversight —
    what a sweep ingests is the FortiWeb attack log, and there is no such log
    on an ADC. Listing them would offer a selection that could only ever
    return nothing.
    """
    from ..models import Appliance
    names = _visible_names()
    rows = (Appliance.query.filter(Appliance.kind == "fortiweb")
            .order_by(Appliance.name).all())
    out = []
    for a in rows:
        if names and a.name not in names:
            continue
        reason = ""
        if getattr(a, "maintenance", False):
            reason = "in maintenance — the sweep skips it"
        elif str(getattr(a, "host", "") or "").endswith(".invalid"):
            reason = "host is .invalid — retired, never contacted"
        out.append({"id": a.id, "name": a.name,
                    "host": getattr(a, "host", "") or "",
                    "eligible": not reason, "reason": reason})
    return out


@bp.route("/run", methods=["POST"])
@login_required
@require_permission("config_write")
def run_now():
    """Start a sweep as a JOB, over the devices the operator picked.

    It used to run the whole fleet synchronously inside this request. That is
    the defect, not the missing picker: one gunicorn worker was held for as
    long as the slowest appliance took, with no progress anywhere, and at the
    fleet this product is sized for (ninety appliances) the request is gone
    long before the sweep is. The work now goes to the shared job ledger, so
    it survives the page, reports progress per device and can be stopped at a
    safe checkpoint.

    An empty selection means EVERY eligible device — the historical behaviour,
    kept because that is what the button did before and a button that quietly
    changed meaning is worse than one that asks.
    """
    from flask import current_app
    from ..services.sentinel import sweep_job
    if not _svc()["config"].get("enabled"):
        flash("Sentinel is disabled in Settings — nothing was collected.",
              "warning")
        return _back_to_console()
    wanted = [n for n in request.form.getlist("device") if n]
    known = {r["name"]: r for r in sweep_targets()}
    unknown = [n for n in wanted if n not in known]
    if unknown:
        # Not silently dropped: a name the operator picked and this node does
        # not know is a stale page or a hand-built POST, and running "the rest
        # of them" would report a sweep of a selection nobody made.
        abort(400)
    skipped = [n for n in wanted if not known[n]["eligible"]]
    names = [n for n in wanted if known[n]["eligible"]]
    if wanted and not names:
        flash("Every device you picked is in maintenance or retired — a sweep "
              "would skip all of them, so none was started.", "warning")
        return _back_to_console()
    job = sweep_job.start(current_app._get_current_object(), names, by=_who())
    flash(f"Sweep started as job {job['id']} over "
          f"{len(names) or len([r for r in known.values() if r['eligible']])} "
          f"device(s). Progress is in the Jobs dock; this page does not wait "
          f"for it."
          + (f" Skipped as ineligible: {', '.join(skipped)}." if skipped else ""),
          "success")
    return _back_to_console()


@bp.route("/baselines/recompute", methods=["POST"])
@login_required
@require_permission("config_write")
def recompute():
    """Rebuild behavioural baselines from the metrics store. Touches no device."""
    s = _svc()
    result = s["pipeline"].recompute_baselines()
    flash(f"Baselines recomputed: {result['detail']}", "success")
    if result.get("errors"):
        flash(f"{len(result['errors'])} series could not be read: "
              + "; ".join(result["errors"][:3]), "warning")
    return _back_to_console()


# --------------------------------------------------------------------------- #
#  One incident                                                                 #
# --------------------------------------------------------------------------- #
@bp.route("/incident/<int:iid>")
@login_required
def incident_view(iid):
    s = _svc()
    inc = SentinelIncident.query.get_or_404(iid)
    proposal = s["actions"].recommend(inc)
    gates = {key: s["actions"].evaluate(inc, key)
             for key in s["actions"].CATALOG}
    return render_template(
        "sentinel/incident.html",
        inc=inc, incident=inc.to_dict(),
        events=[e.to_dict() for e in
                SentinelEvent.query.filter_by(incident_id=inc.id)
                .order_by(SentinelEvent.ts).limit(500).all()],
        evidence=[e.to_dict() for e in inc.evidence],
        timeline=[t.to_dict() for t in inc.timeline],
        actions_taken=[a.to_dict() for a in inc.actions],
        recommendation=proposal,
        gates=gates,
        disagreement=s["ai"].disagreement(inc, proposal),
        fp_reasons=s["incident"].FP_REASONS,
        catalog=s["actions"].catalog_rows())


@bp.route("/incident/<int:iid>/charts")
@login_required
def incident_charts(iid):
    """Time-aligned series for the incident's window, one payload.

    Fetched AFTER the page rather than during the render: a store hiccup must
    degrade one card, not turn the whole incident view into a 500 at the
    moment someone needs to read it.
    """
    s = _svc()
    inc = SentinelIncident.query.get_or_404(iid)
    ctx = s["correlate"].build(inc.device, inc.src_ip, inc.attack_family,
                               inc.last_event_at or inc.opened_at,
                               appliance_id=inc.appliance_id)
    return jsonify({"t0": ctx.t0.isoformat(timespec="seconds"),
                    "start": ctx.start.isoformat(timespec="seconds"),
                    "end": ctx.end.isoformat(timespec="seconds"),
                    "store_ok": ctx.store_ok, "store_detail": ctx.store_detail,
                    "layers_unknown": ctx.layers_unknown,
                    "series": [r.to_dict() for r in ctx.readings],
                    "chain": ctx.to_dict()["chain"],
                    "http": ctx.http})


@bp.route("/incident/<int:iid>/rescore", methods=["POST"])
@login_required
@require_permission("config_write")
def incident_rescore(iid):
    s = _svc()
    inc = SentinelIncident.query.get_or_404(iid)
    s["incident"].rescore(inc)
    inc.similar = s["incident"].similar(inc)
    db.session.commit()
    flash(f"{inc.ref} re-correlated: score {inc.score}/100 ({inc.band}).",
          "success")
    return redirect(url_for("sentinel.incident_view", iid=iid))


@bp.route("/incident/<int:iid>/reason", methods=["POST"])
@login_required
@require_permission("config_write")
def incident_reason(iid):
    """Ask the model. Failure is reported, never raised at the operator."""
    s = _svc()
    inc = SentinelIncident.query.get_or_404(iid)
    if not s["ai"].enabled():
        flash("AI reasoning is disabled in Settings — the incident keeps its "
              "deterministic score and evidence.", "warning")
        return redirect(url_for("sentinel.incident_view", iid=iid))
    opinion = s["ai"].reason(inc, [e.to_dict() for e in inc.evidence])
    opinion["scored_at"] = inc.score
    inc.ai = opinion
    s["incident"].timeline_add(
        inc, "decision",
        f"AI assessment ({opinion.get('model', '?')}): "
        f"{opinion.get('assessment') or opinion.get('error', 'no answer')}")
    db.session.commit()
    flash("Model answered." if opinion.get("ok")
          else f"Model did not answer: {opinion.get('error')}",
          "success" if opinion.get("ok") else "warning")
    return redirect(url_for("sentinel.incident_view", iid=iid))


@bp.route("/incident/<int:iid>/close", methods=["POST"])
@login_required
@require_permission("config_write")
def incident_close(iid):
    s = _svc()
    inc = SentinelIncident.query.get_or_404(iid)
    status = request.form.get("status", "")
    try:
        s["incident"].close(inc, status, by=_who(),
                            note=request.form.get("note", ""),
                            fp_reason=request.form.get("fp_reason", ""))
    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("sentinel.incident_view", iid=iid))
    db.session.commit()
    flash(f"{inc.ref} closed as {status}.", "success")
    return redirect(url_for("sentinel.index"))


@bp.route("/incident/<int:iid>/action", methods=["POST"])
@login_required
@require_permission("config_write")
def incident_action(iid):
    """Record an operator's approval of a proposed action.

    Approval ENQUEUES. It is not a promise that execution follows: the runner
    re-evaluates every gate at the moment it acts, so consent given at 12:00
    does not survive a kill switch thrown at 12:01. An approval is consent to a
    decision made under the state the approver could actually see.
    """
    s = _svc()
    inc = SentinelIncident.query.get_or_404(iid)
    action_type = request.form.get("action_type", "")
    if action_type not in s["actions"].CATALOG:
        abort(400)
    verdict = s["actions"].evaluate(inc, action_type)
    action = s["actions"].propose(inc, action_type, by=f"user:{_who()}",
                                  rationale=request.form.get("note", ""))
    if verdict["allowed"]:
        action.approved_by = _who()
        if s["transports"].get(action_type) is None:
            action.status = SentinelAction.STATUS_APPROVED
            msg = (f"{action_type} approved and recorded, but NOT queued: its "
                   f"mechanism has never been run against a live appliance of "
                   f"this product, so there is nothing to execute.")
            level = "warning"
        else:
            action.status = SentinelAction.STATUS_QUEUED
            msg = (f"{action_type} approved and queued. The runner re-checks "
                   f"every gate and asks the appliance whether it can enforce "
                   f"before writing anything.")
            level = "success"
    else:
        action.status = SentinelAction.STATUS_REJECTED
        msg = f"{action_type} refused by the policy engine: {verdict['reason']}."
        level = "danger"
    s["incident"].timeline_add(inc, "action",
                               f"{msg} (requested by {_who()})")
    db.session.commit()
    flash(msg, level)
    return redirect(url_for("sentinel.incident_view", iid=iid))


@bp.route("/arm", methods=["POST"])
@login_required
@require_permission("config_write")
def arm():
    """Bind Sentinel's IP list to a policy's web protection profile.

    Kept away from every response path deliberately. Until this has run, a
    block on that policy would add a member to a list nothing references:
    accepted by the appliance, green in our own records, and protecting
    nothing. The runner refuses to act rather than produce that, and it will
    not repair it either — an agent that binds its own enforcement point is an
    agent that can widen its own authority.
    """
    from ..clients import client_for
    from ..models import Appliance
    from ..services import audit
    s = _svc()
    device = (request.form.get("device") or "").strip()
    policy = (request.form.get("policy") or "").strip()
    if device not in _visible_names():
        abort(403)
    ap = Appliance.query.filter_by(name=device).first_or_404()
    # Which bridge to bind. Never both from one submit: arming address blocking
    # is a decision about one attacker, arming country blocking is a decision
    # about a market, and a single button that did both would make the larger
    # one a side effect of asking for the smaller.
    mechanism = (request.form.get("mechanism") or "ip").strip()
    if mechanism not in ("ip", "geo"):
        abort(400)
    arm_fn = (s["transports"].arm_geo_policy if mechanism == "geo"
              else s["transports"].arm_policy)
    try:
        out = arm_fn(client_for(ap), policy)
    except Exception as exc:
        flash(f"Could not arm {policy} on {device}: {exc}", "danger")
        return _back_to_context()
    detail = "; ".join(f"{st['name']}: {st['detail']}" for st in out["steps"])
    audit.log_action("sentinel.arm",
                     f"{device}/{policy} mechanism={mechanism} "
                     f"armed={out['ok']} :: {detail}")
    flash(f"{'Armed' if out['ok'] else 'Could not arm'} {policy} on {device} "
          f"({'country blocking' if mechanism == 'geo' else 'address blocking'}). "
          f"{detail}", "success" if out["ok"] else "danger")
    return _back_to_context()


# --------------------------------------------------------------------------- #
#  Context — trust, windows, topology, mirror                                   #
# --------------------------------------------------------------------------- #
def context_context() -> dict:
    """Everything ``sentinel/_context_section.html`` needs — for BOTH surfaces.

    Same argument as :func:`console_context` and :func:`docs_context`: the
    section is drawn on its own page and inside the Admin Console pane
    Settings → Sentinel → Context, from one file, so its context is built in
    one place. Two builders would let the pane and the page disagree about the
    trust list — the single largest weight in the scoring table — and neither
    would fail.
    """
    s = _svc()
    from ..services import hypervisors
    return dict(
        trusted=[t.to_dict() for t in
                 SentinelTrustedSource.query.order_by(
                     SentinelTrustedSource.cidr).all()],
        kinds=SentinelTrustedSource.KINDS,
        windows=[w.to_dict() for w in
                 SentinelMaintenanceWindow.query.order_by(
                     SentinelMaintenanceWindow.starts_at.desc()).all()],
        appliances=visible_appliances().all(),
        topology={t.appliance_id: t.to_dict()
                  for t in SentinelTopology.query.all()},
        sentinel_list=s["transports"].SENTINEL_LIST,
        hypervisors=hypervisors.configured_targets(),
        mirror=s["vuln"].mirror_health(),
        recent_cves=[v.to_dict() for v in
                     SentinelVuln.query.order_by(
                         SentinelVuln.fetched_at.desc()).limit(25).all()])


@bp.route("/context")
@login_required
def context():
    return render_template("sentinel/context.html", **context_context())


@bp.route("/context/trusted", methods=["POST"])
@login_required
@require_permission("config_write")
def trusted_add():
    import ipaddress
    cidr = (request.form.get("cidr") or "").strip()
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        flash(f"{cidr!r} is not a valid CIDR.", "danger")
        return _back_to_context()
    expires = (request.form.get("expires_at") or "").strip()
    when = None
    if expires:
        try:
            when = datetime.fromisoformat(expires)
        except ValueError:
            flash("Expiry must be an ISO date/time.", "danger")
            return _back_to_context()
    if when is None:
        # Not a silent default: an authorisation with no end date is a blind
        # spot nobody remembers creating, so the form supplies one and says so.
        when = datetime.utcnow() + timedelta(days=30)
        flash("No expiry given — defaulted to 30 days. A trust entry without "
              "an end date is a permanent blind spot.", "warning")
    db.session.add(SentinelTrustedSource(
        cidr=cidr, kind=request.form.get("kind", "scanner"),
        label=request.form.get("label", "")[:120],
        note=request.form.get("note", "")[:300],
        suppress_actions=True, expires_at=when, created_by=_who()))
    db.session.commit()
    flash(f"{cidr} trusted until {when:%Y-%m-%d %H:%M} UTC.", "success")
    return _back_to_context()


@bp.route("/context/trusted/<int:tid>/delete", methods=["POST"])
@login_required
@require_permission("config_write")
def trusted_delete(tid):
    row = SentinelTrustedSource.query.get_or_404(tid)
    db.session.delete(row)
    db.session.commit()
    flash("Trusted source removed.", "success")
    return _back_to_context()


@bp.route("/context/window", methods=["POST"])
@login_required
@require_permission("config_write")
def window_add():
    try:
        starts = datetime.fromisoformat(request.form["starts_at"])
        ends = datetime.fromisoformat(request.form["ends_at"])
    except (KeyError, ValueError):
        flash("Both start and end must be ISO date/times.", "danger")
        return _back_to_context()
    if ends <= starts:
        flash("A maintenance window must end after it starts.", "danger")
        return _back_to_context()
    db.session.add(SentinelMaintenanceWindow(
        label=request.form.get("label", "")[:120],
        scope_device=request.form.get("scope_device", "")[:120],
        starts_at=starts, ends_at=ends,
        suppress_actions=bool(request.form.get("suppress_actions")),
        freeze_baseline=bool(request.form.get("freeze_baseline")),
        note=request.form.get("note", "")[:300], created_by=_who()))
    db.session.commit()
    flash("Maintenance window saved. Detection continues inside it — only "
          "actions and baseline learning are affected.", "success")
    return _back_to_context()


@bp.route("/context/window/<int:wid>/delete", methods=["POST"])
@login_required
@require_permission("config_write")
def window_delete(wid):
    row = SentinelMaintenanceWindow.query.get_or_404(wid)
    db.session.delete(row)
    db.session.commit()
    flash("Maintenance window removed.", "success")
    return _back_to_context()


@bp.route("/context/topology", methods=["POST"])
@login_required
@require_permission("config_write")
def topology_save():
    """Map an appliance to its VM and hypervisor node.

    Without this row the VM and host layers are structurally unavailable and
    every incident on that device reports them as *unknown*. That is the
    honest state, and it is also why this form exists.
    """
    appliance_id = int(request.form.get("appliance_id") or 0)
    row = SentinelTopology.query.filter_by(appliance_id=appliance_id).first()
    if row is None:
        row = SentinelTopology(appliance_id=appliance_id)
        db.session.add(row)
    target = request.form.get("hypervisor_target_id") or ""
    row.hypervisor_target_id = int(target) if target.isdigit() else None
    row.vm_id = (request.form.get("vm_id") or "").strip()[:40]
    row.node = (request.form.get("node") or "").strip()[:120]
    backends = []
    for line in (request.form.get("backends") or "").splitlines():
        line = line.strip()
        if not line:
            continue
        # "name|cpe" — the CPE is what lets the CVE cross-check answer
        # "does this exploit affect what this target actually runs".
        name, _, cpe = line.partition("|")
        backends.append({"name": name.strip(), "cpe": cpe.strip()})
    row.backends = backends
    db.session.commit()
    flash("Topology saved." if row.complete else
          "Topology saved but INCOMPLETE — the VM and host layers stay "
          "unknown until hypervisor, VM id and node are all set.",
          "success" if row.complete else "warning")
    return _back_to_context()


@bp.route("/vuln/sync", methods=["POST"])
@login_required
@require_permission("config_write")
def vuln_sync():
    """The only outbound call in the whole module, and it is gated twice."""
    s = _svc()
    result = s["vuln"].sync()
    flash(result.get("detail") or result.get("reason", ""),
          "success" if result.get("ok") else "warning")
    return _back_to_context()


@bp.route("/vuln/manual", methods=["POST"])
@login_required
@require_permission("config_write")
def vuln_manual():
    """Enter a CVE by hand — the path that works with no internet at all."""
    s = _svc()
    try:
        row = s["vuln"].upsert(
            request.form.get("cve", ""),
            cvss=float(request.form["cvss"]) if request.form.get("cvss") else None,
            epss=float(request.form["epss"]) if request.form.get("epss") else None,
            in_kev=bool(request.form.get("in_kev")),
            summary=request.form.get("summary", "")[:4000],
            affected_cpe=[c.strip() for c in
                          (request.form.get("affected_cpe") or "").splitlines()
                          if c.strip()],
            source="manual")
    except ValueError as exc:
        flash(str(exc), "danger")
        return _back_to_context()
    db.session.commit()
    flash(f"{row.cve} stored in the local mirror.", "success")
    return _back_to_context()


# --------------------------------------------------------------------------- #
#  Response policy                                                              #
# --------------------------------------------------------------------------- #
def policies_context() -> dict:
    """Everything ``sentinel/_policy_section.html`` needs — for BOTH surfaces.

    ``modes`` and ``mode_current`` are computed here, and both come from
    :mod:`app.services.sentinel.modes`, which derives them from the live
    values on every call. A cached or stored mode would be a claim that
    outlives the configuration it describes.
    """
    s = _svc()
    from ..services.sentinel import modes as sn_modes
    return dict(policies=s["actions"].policy_rows(),
                catalog=s["actions"].catalog_rows(),
                levels=[(0, "0 — Observe"), (1, "1 — Recommend"),
                        (2, "2 — Semi-automatic"),
                        (3, "3 — Autonomous")],
                armed=bool(s["config"].get("response_enabled")),
                verified=s["actions"].verified_count(),
                handoffs=s["actions"].handoff_keys(),
                modes=sn_modes.rows(),
                mode_current=sn_modes.current(),
                recent=[a.to_dict() for a in
                        SentinelAction.query.order_by(
                            SentinelAction.created_at.desc()).limit(50).all()])


@bp.route("/policies")
@login_required
@require_permission("config_write")
def policies():
    return render_template("sentinel/policies.html", **policies_context())


@bp.route("/policies/mode", methods=["POST"])
@login_required
@require_permission("config_write")
def mode_apply():
    """Apply one named operating mode.

    The mode is not stored anywhere: this route writes the preset's VALUES,
    and the posture is re-derived from those values on the next render. That
    is what keeps the label honest — a knob edited by hand afterwards moves
    the page to Custom without anything having to notice.

    Audited with the full before → after list rather than the mode name.
    "Someone selected Ultra high" is not an answer to "why did this appliance
    start blocking on its own"; the eleven values that changed are.
    """
    from ..services import audit
    from ..services.sentinel import modes as sn_modes
    try:
        result = sn_modes.apply(request.form.get("mode", ""))
    except KeyError:
        abort(400)
    detail = "; ".join(f"{c['key']}: {c['before']} -> {c['after']}"
                       for c in result["changed"]) or "no change"
    audit.log_action("sentinel.mode", target="sentinel",
                     detail=f"{result['mode']} :: {detail}")
    if result["changed"]:
        flash(f"Operating mode {result['label']}: {len(result['changed'])} "
              f"value(s) changed. They are ordinary settings from now on — "
              f"edit any of them and the mode reads Custom.", "success")
    else:
        flash(f"Already configured exactly as {result['label']}; nothing "
              f"changed.", "info")
    return _back_to_policies()


@bp.route("/policies/<action_type>", methods=["POST"])
@login_required
@require_permission("config_write")
def policy_save(action_type):
    s = _svc()
    spec = s["actions"].CATALOG.get(action_type)
    if spec is None:
        abort(404)
    row = SentinelPolicy.query.filter_by(action_type=action_type).first_or_404()
    want = int(request.form.get("level") or 0)
    # The catalog's ceiling is enforced HERE as well as in evaluate(): a form
    # that silently accepts level 3 for block_country and is only stopped at
    # execution time teaches the operator a permission they do not have.
    row.level = min(want, spec.max_level)
    row.enabled = bool(request.form.get("enabled"))
    row.min_confidence = max(0, min(100, int(request.form.get("min_confidence") or 85)))
    row.ttl_minutes = max(0, int(request.form.get("ttl_minutes") or 0))
    row.max_ttl_minutes = max(row.ttl_minutes,
                              int(request.form.get("max_ttl_minutes") or 240))
    db.session.commit()
    if want > spec.max_level:
        flash(f"{action_type} is capped at level {spec.max_level}: "
              f"{spec.blast}", "warning")
    else:
        flash(f"{action_type} policy saved.", "success")
    return _back_to_policies()


# --------------------------------------------------------------------------- #
#  Documentation                                                                #
# --------------------------------------------------------------------------- #
@bp.route("/docs")
@login_required
def docs():
    """The architecture, rendered from the LIVE tables it describes.

    Weights, action catalog and settings spec are read from the running code,
    not transcribed. A hand-written copy is how ``Version: 1.0`` survived four
    releases in this repo: nothing fails when a document goes stale, the
    sentence simply stops being true.
    """
    return render_template("sentinel/docs.html", **docs_context())


def docs_context(health: dict = None) -> dict:
    """Everything ``sentinel/_docs_section.html`` needs — for BOTH surfaces.

    Same argument as :func:`console_context`: the document is drawn on its own
    page and inside the Admin Console pane, from one file, so its context is
    built in one place. Everything below is read from the LIVE tables the
    document describes, never transcribed.
    """
    s = _svc()
    return dict(
        weights=s["scoring"].explain(),
        catalog=s["actions"].catalog_rows(),
        settings=s["config"].form_groups(),
        layers=s["correlate"].LAYER_SERIES,
        families=[f for f, _ in
                  __import__("app.services.sentinel.normalize",
                             fromlist=["x"])._FAMILY_PATTERNS],
        fp_reasons=s["incident"].FP_REASONS,
        assessments=s["ai"].ALLOWED_ASSESSMENTS,
        recommendations=s["ai"].ALLOWED_RECOMMENDATIONS,
        bands={"observe": SentinelIncident.BAND_OBSERVE,
               "recommend": SentinelIncident.BAND_RECOMMEND,
               "semi_auto": SentinelIncident.BAND_SEMI_AUTO},
        verified=s["actions"].verified_count(),
        # The decision diagram iterates this rather than restating it. A
        # picture drawn NEXT TO a decision chain is the easiest thing here to
        # leave behind: nothing fails when the two disagree.
        gate_order=s["actions"].GATE_ORDER,
        handoffs=s["actions"].handoff_keys(),
        health=_health() if health is None else health)
