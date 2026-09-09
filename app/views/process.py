"""Process — Administrator → Process, in EVERY ADOM.

An operator draws a procedure once (recovery plan, post-upgrade validation,
onboarding check) and SATOM walks it: every step asks the module that owns the
question, the arrows say where to go depending on the answer, and the run says
which layer stopped it.

NOTHING IS DECIDED HERE. This file reads the form, resolves the permission and
the ADOM, calls the service and renders. What a step means lives in
``services.process_kinds``; where the walk goes next and what the whole thing
adds up to lives in ``services.process_engine``; which processes this console
may see lives in ``process_engine.visible_processes``. That last one matters:
filtering the list in the template would make the sidebar and the gate two
authors of visibility, which is how ``calendar_plan`` shipped drawn in the
FortiADC menu and bouncing to ``/adc/`` when clicked.

ARMING
------
A run is a **rehearsal** unless the operator arms it. Unarmed, every
write-capable step executes with ``dry_run=True`` and the row says so. That is
the same preview→confirm split ``dns_decommission`` and ``cert_manager`` use,
and it is what makes a recovery plan safe to point at production before the
night you need it.
"""
from __future__ import annotations

import json

from flask import (Blueprint, Response, abort, flash, jsonify,
                   redirect, render_template, request, url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import (Appliance, db, visible_appliance_or_404,
                      visible_appliances)
from ..models_adom import Adom
from ..models_process import (PASS, Process, ProcessEdge, ProcessNode,
                              ProcessRun, WAITING)
from ..services import process_engine as engine
from ..services import process_kinds as pk
from ..services import process_xml as pxml
from ..services.audit import log_action
from ..services.product_scope import GLOBAL, session_product

bp = Blueprint("process", __name__, url_prefix="/process")

#: A posted diagram larger than this is not a diagram.
MAX_GRAPH = 512 * 1024



def _adoms():
    """Every ADOM a process may be registered for, in menu order."""
    return (Adom.query.filter_by(active=True)
            .order_by(Adom.sort_order.asc(), Adom.name.asc()).all())


def _appliances():
    return visible_appliances().order_by(Appliance.name).all()


def _proc_or_404(pid: int) -> Process:
    proc = db.session.get(Process, pid)
    if proc is None:
        abort(404)
    if not engine.may_run_here(proc):
        # Not a 403: in this ADOM the process does not exist. Telling an
        # operator "forbidden" about a record they cannot see anywhere in their
        # console describes a permission problem that is not the one they have.
        abort(404)
    return proc


def _action_catalog():
    """Catalogue actions a process step may invoke, already cut to what it may.

    Actions bound to a change request are EXCLUDED from the picker rather than
    offered and refused: an option that always fails is a support ticket.
    """
    from ..services.scheduled_actions import ALL_ACTIONS
    out = []
    for spec in ALL_ACTIONS.values():
        if spec.requires_change_request:
            continue
        out.append({"key": spec.key, "label": spec.label,
                    "danger": bool(spec.danger),
                    "needs_targets": bool(spec.needs_targets),
                    "products": list(spec.products),
                    "summary": spec.summary or ""})
    out.sort(key=lambda r: r["label"].lower())
    return out


def _hook_catalog():
    """Integration hooks offerable to a ``hook`` step.

    DISABLED hooks are listed and marked, not hidden. A hook that is merely
    switched off is exactly the one an operator writes into a recovery plan and
    turns on for the drill; hiding it would look like the hook was deleted. The
    engine does not consult ``enabled`` either — ``dispatch_one`` is the
    named-hook door and it deliberately queues disabled hooks.
    """
    from ..services import integration_hooks as ih
    try:
        rows = ih.list_hooks()
    except Exception:  # noqa: BLE001 — an unreadable hooks dir is an empty list,
        return []      # not a 500 on the diagram page.
    out = [{"slug": h.get("slug", ""), "event": h.get("event", ""),
            "enabled": bool(h.get("enabled")),
            "timeout": ih.clamp_timeout(h.get("timeout")),
            "secrets": list(h.get("secrets") or [])}
           for h in rows]
    out.sort(key=lambda r: r["slug"])
    return out


def _kinds_json():
    """The kind catalogue as plain data for the editor.

    Built from the dataclasses rather than re-declared in JavaScript: two copies
    of "what parameters does an HTTP check take" is how a form and its validator
    start disagreeing — the server refusing a save for a field the editor never
    drew.
    """
    from dataclasses import asdict
    return [asdict(k) for k in pk.kinds()]


# ---------------------------------------------------------------------------
# list / metadata
# ---------------------------------------------------------------------------

@bp.route("/")
@login_required
@require_permission("view")
def index():
    rows = engine.visible_processes()
    last = {}
    for proc in rows:
        last[proc.id] = (ProcessRun.query.filter_by(process_id=proc.id)
                         .order_by(ProcessRun.started_at.desc()).first())
    runs = (ProcessRun.query.order_by(ProcessRun.started_at.desc())
            .limit(15).all())
    return render_template("process/index.html", processes=rows, last=last,
                           runs=runs, product_key=session_product(),
                           is_global=session_product() == GLOBAL)


@bp.route("/new", methods=["GET", "POST"])
@login_required
@require_permission("config_write")
def create():
    if request.method == "POST":
        key = (request.form.get("key") or "").strip().lower()
        name = (request.form.get("name") or "").strip()
        if not pk.KEY_RE.match(key):
            flash("The key must be lowercase letters, digits, - or _.", "danger")
        elif Process.query.filter_by(key=key).first():
            flash("A process with the key %r already exists." % key, "danger")
        elif not name:
            flash("The process needs a name.", "danger")
        else:
            proc = Process(key=key, name=name,
                           description=(request.form.get("description") or "").strip(),
                           products=request.form.getlist("products"),
                           enabled=bool(request.form.get("enabled")),
                           created_by=getattr(current_user, "username", "") or "")
            db.session.add(proc)
            db.session.flush()
            # Every process starts with a Start step. An empty canvas cannot be
            # saved (validate_graph refuses it), so shipping one would make the
            # first save of every new process an error message.
            db.session.add(ProcessNode(process_id=proc.id, node_key="start",
                                       kind="start", label="Start",
                                       pos_x=60, pos_y=60))
            db.session.commit()
            log_action("process.create", target=proc.key, extra={"name": name, "products": proc.products})
            return redirect(url_for("process.detail", pid=proc.id))
    return render_template("process/form.html", proc=None, adoms=_adoms())


@bp.route("/<int:pid>/edit", methods=["GET", "POST"])
@login_required
@require_permission("config_write")
def edit(pid):
    proc = _proc_or_404(pid)
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        if not name:
            flash("The process needs a name.", "danger")
        else:
            proc.name = name
            proc.description = (request.form.get("description") or "").strip()
            proc.products = request.form.getlist("products")
            proc.enabled = bool(request.form.get("enabled"))
            db.session.commit()
            log_action("process.edit", target=proc.key, extra={"name": name, "products": proc.products})
            return redirect(url_for("process.detail", pid=proc.id))
    return render_template("process/form.html", proc=proc, adoms=_adoms())


@bp.route("/<int:pid>/delete", methods=["POST"])
@login_required
@require_permission("config_write")
def delete(pid):
    proc = _proc_or_404(pid)
    key, name = proc.key, proc.name
    # Runs survive on purpose: each carries its own copy of the name, key and
    # graph, and history that vanishes with its definition is not history.
    #
    # The link is cut HERE and not left to the column's ``ondelete="SET NULL"``.
    # That clause only fires when the database enforces the constraint —
    # Postgres does, the SQLite the tests run against does not unless
    # ``PRAGMA foreign_keys`` is on — so relying on it would leave production
    # and the test bed disagreeing about whether a run points at a process that
    # no longer exists. One authority, same answer on both engines.
    ProcessRun.query.filter_by(process_id=proc.id).update(
        {"process_id": None}, synchronize_session=False)
    db.session.delete(proc)
    db.session.commit()
    log_action("process.delete", target=key, extra={"name": name})
    flash("Process %s deleted. Its run history was kept." % name, "success")
    return redirect(url_for("process.index"))


# ---------------------------------------------------------------------------
# the diagram
# ---------------------------------------------------------------------------

@bp.route("/<int:pid>")
@login_required
@require_permission("view")
def detail(pid):
    proc = _proc_or_404(pid)
    graph = proc.graph()
    runs = (ProcessRun.query.filter_by(process_id=proc.id)
            .order_by(ProcessRun.started_at.desc()).limit(20).all())
    return render_template(
        "process/detail.html", proc=proc, graph=graph, runs=runs,
        kinds=pk.kinds(), kinds_json=_kinds_json(), actions=_action_catalog(),
        hooks=_hook_catalog(), appliances=_appliances(),
        needs_appliance=pk.needs_appliance(graph),
        writes=pk.writes(graph), kinds_used=pk.kinds_used(graph),
        problems=pk.validate_graph(graph),
        can_edit=current_user.can("config_write"),
    )


@bp.route("/<int:pid>/graph", methods=["POST"])
@login_required
@require_permission("config_write")
def save_graph(pid):
    proc = _proc_or_404(pid)
    raw = request.get_data(as_text=True) or ""
    if len(raw) > MAX_GRAPH:
        return jsonify(ok=False, errors=["The diagram is too large to save."]), 400
    try:
        graph = json.loads(raw)
    except ValueError:
        return jsonify(ok=False, errors=["The diagram could not be read."]), 400

    errors = pk.validate_graph(graph)
    if errors:
        # Refused whole. Saving the valid half of a diagram would leave a
        # procedure that looks saved and walks somewhere else.
        return jsonify(ok=False, errors=errors), 400

    ProcessNode.query.filter_by(process_id=proc.id).delete()
    ProcessEdge.query.filter_by(process_id=proc.id).delete()
    for n in graph.get("nodes", []):
        db.session.add(ProcessNode(
            process_id=proc.id, node_key=str(n.get("key")),
            kind=str(n.get("kind")), label=str(n.get("label") or "")[:160],
            params=n.get("params") or {},
            pos_x=int(n.get("x") or 0), pos_y=int(n.get("y") or 0)))
    for e in graph.get("edges", []):
        db.session.add(ProcessEdge(
            process_id=proc.id, src_key=str(e.get("src")),
            dst_key=str(e.get("dst")),
            branch=str(e.get("branch") or "always")))
    db.session.commit()
    log_action("process.graph", target=proc.key,
               extra={"nodes": len(graph.get("nodes", [])),
                      "edges": len(graph.get("edges", []))})
    return jsonify(ok=True, nodes=len(graph.get("nodes", [])),
                   edges=len(graph.get("edges", [])))


# ---------------------------------------------------------------------------
# running
# ---------------------------------------------------------------------------

@bp.route("/<int:pid>/run", methods=["POST"])
@login_required
@require_permission("config_write")
def run(pid):
    proc = _proc_or_404(pid)
    if not proc.enabled:
        flash("This process is disabled.", "warning")
        return redirect(url_for("process.detail", pid=proc.id))

    graph = proc.graph()
    problems = pk.validate_graph(graph)
    if problems:
        flash("This diagram cannot run yet: %s" % problems[0], "danger")
        return redirect(url_for("process.detail", pid=proc.id))

    appliance = None
    aid = (request.form.get("appliance_id") or "").strip()
    if aid:
        appliance = visible_appliance_or_404(int(aid))
    if pk.needs_appliance(graph) and appliance is None:
        flash("This process has steps that act on a device — choose one.", "danger")
        return redirect(url_for("process.detail", pid=proc.id))

    armed = bool(request.form.get("armed"))
    if armed and not pk.writes(graph):
        # Arming a read-only plan is harmless but it is also meaningless, and a
        # run stamped "armed" that could never have written anything teaches an
        # operator the wrong thing about the badge.
        armed = False

    run_row = engine.start_run(
        proc, appliance=appliance, armed=armed, trigger="manual",
        user=getattr(current_user, "username", "") or "",
        product=session_product())
    log_action("process.run", target=proc.key,
               extra={"run": run_row.id, "armed": armed,
                      "appliance": run_row.appliance_name,
                      "status": run_row.status, "verdict": run_row.verdict})
    return redirect(url_for("process.run_detail", rid=run_row.id))


@bp.route("/runs/<int:rid>")
@login_required
@require_permission("view")
def run_detail(rid):
    row = db.session.get(ProcessRun, rid)
    if row is None:
        abort(404)
    gate = ""
    if row.status == WAITING:
        for n in (row.graph or {}).get("nodes", []):
            if str(n.get("key")) == row.waiting_node:
                gate = str((n.get("params") or {}).get("prompt") or "")
    return render_template("process/run.html", run=row, gate_prompt=gate,
                           can_edit=current_user.can("config_write"))


@bp.route("/runs/<int:rid>/resume", methods=["POST"])
@login_required
@require_permission("config_write")
def run_resume(rid):
    row = db.session.get(ProcessRun, rid)
    if row is None:
        abort(404)
    if row.status != WAITING:
        flash("That run is not waiting for an answer.", "warning")
        return redirect(url_for("process.run_detail", rid=rid))
    answer = (request.form.get("answer") or "").strip()
    engine.resume(row, answer if answer == PASS else "fail",
                  note=(request.form.get("note") or "").strip()[:400])
    log_action("process.resume", target=row.process_key,
               extra={"run": row.id, "answer": answer})
    return redirect(url_for("process.run_detail", rid=rid))


# ---------------------------------------------------------------------------
# XML — a procedure as a file
# ---------------------------------------------------------------------------
#
# WHY THE IMPORT GOES THROUGH ``validate_graph``
# ---------------------------------------------
# It is the SAME call ``save_graph`` makes, on the same dict, before a single
# row is written. A console step carrying ``factoryreset`` is refused here
# exactly as it is refused in the editor. An importer with its own idea of what
# is allowed would be the easiest way past every gate in the product, and it
# would be attractive precisely because a file reads like data.

@bp.route("/<int:pid>/export.xml")
@login_required
@require_permission("view")
def export_xml(pid):
    """Download this process as the file :func:`import_xml` reads back."""
    proc = _proc_or_404(pid)
    body = pxml.to_xml(key=proc.key, name=proc.name,
                       description=proc.description or "",
                       products=proc.products or [], enabled=bool(proc.enabled),
                       graph=proc.graph())
    log_action("process.export", target=proc.key,
               extra={"nodes": len(proc.nodes), "edges": len(proc.edges)})
    # A whole procedure — console scripts included — leaving as a file is worth
    # an audit row even though the page it came from is only a read.
    return Response(body, mimetype="application/xml", headers={
        "Content-Disposition": 'attachment; filename="process-%s.xml"' % proc.key})


@bp.route("/import", methods=["GET", "POST"])
@login_required
@require_permission("config_write")
def import_xml():
    """Create — or knowingly replace — a process from an XML file.

    Nothing is written unless EVERY check passes: the file parses, its ADOMs
    exist in this installation, and the graph satisfies the editor's validator.
    A half-imported procedure would look saved and walk somewhere else, which is
    the same reason ``save_graph`` refuses a diagram whole.
    """
    errors: list = []
    if request.method == "POST":
        upload = request.files.get("xml_file")
        raw = upload.read(pxml.MAX_XML + 1) if upload is not None else b""
        if not raw:
            errors.append("Choose an XML file to import.")
        else:
            doc, errors = pxml.read_xml(raw)
            if doc is not None:
                errors = list(errors)
                known = {a.key for a in _adoms()}
                for prod in doc.products:
                    if prod not in known:
                        # Refused, never dropped. Dropping would import the plan
                        # as a draft that looks published — and a process moved
                        # between installations is the case this whole feature
                        # exists for, so a missing ADOM is the LIKELY error and
                        # has to be said out loud.
                        errors.append(
                            "This installation has no ADOM %r. It has: %s."
                            % (prod, ", ".join(sorted(known)) or "none"))
                existing = (Process.query.filter_by(key=doc.key).first()
                            if doc.key else None)
                if existing is not None and not engine.may_run_here(existing):
                    # Everywhere else in this module such a process does not
                    # exist. Overwriting it from here would edit a record this
                    # console cannot even list.
                    errors.append(
                        "A process with the key %r already exists but is not "
                        "offered in this ADOM. Open the Global console to "
                        "replace it." % doc.key)
                elif existing is not None and (
                        request.form.get("replace_key") or "").strip() != doc.key:
                    errors.append(
                        "A process with the key %r already exists. To replace "
                        "it — its steps, its arrows and its settings — type its "
                        "key in the confirmation box. Its run history is kept "
                        "either way." % doc.key)
                errors.extend(pk.validate_graph(doc.graph))
                if not errors:
                    proc = _apply_import(doc, existing)
                    flash("Imported %s: %d steps, %d arrows."
                          % (proc.name, len(doc.graph.get("nodes") or []),
                             len(doc.graph.get("edges") or [])), "success")
                    return redirect(url_for("process.detail", pid=proc.id))
    return render_template("process/import.html", adoms=_adoms(), errors=errors,
                           example=_EXAMPLE_XML)


def _apply_import(doc, existing):
    """Write the imported process. Called only when nothing is left to refuse."""
    replaced = existing is not None
    proc = existing or Process(key=doc.key,
                               created_by=getattr(current_user, "username", "") or "")
    proc.name = doc.name
    proc.description = doc.description
    proc.products = list(doc.products)
    proc.enabled = doc.enabled
    if not replaced:
        db.session.add(proc)
    db.session.flush()

    # Runs are NOT touched: each carries its own copy of the graph it walked, so
    # replacing a definition cannot rewrite what a past run says it did — and a
    # run parked on a manual gate resumes through its own snapshot, not through
    # the steps that just arrived.
    ProcessNode.query.filter_by(process_id=proc.id).delete()
    ProcessEdge.query.filter_by(process_id=proc.id).delete()
    for n in doc.graph.get("nodes") or []:
        db.session.add(ProcessNode(
            process_id=proc.id, node_key=str(n.get("key")),
            kind=str(n.get("kind")), label=str(n.get("label") or "")[:160],
            params=n.get("params") or {},
            pos_x=int(n.get("x") or 0), pos_y=int(n.get("y") or 0)))
    for e in doc.graph.get("edges") or []:
        db.session.add(ProcessEdge(
            process_id=proc.id, src_key=str(e.get("src")),
            dst_key=str(e.get("dst")), branch=str(e.get("branch") or "always")))
    db.session.commit()
    log_action("process.import", target=proc.key,
               extra={"replaced": replaced, "name": proc.name,
                      "products": proc.products,
                      "nodes": len(doc.graph.get("nodes") or []),
                      "edges": len(doc.graph.get("edges") or [])})
    return proc


#: Shown on the import page. Deliberately a WORKING plan rather than a field
#: reference: the format is learned faster from three steps that check a
#: service and stop than from a table of element names.
_EXAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<satom-process key="dr-failover-check" name="DR failover check" enabled="yes">
  <description>Prove the standby answers before anyone is told it does.</description>
  <adoms>
    <adom>fortiweb</adom>
  </adoms>
  <steps>
    <step key="start" kind="start" label="Start" x="60" y="40"/>
    <step key="vip" kind="tcp_check" label="VIP answers" x="60" y="140">
      <param name="host">192.0.2.249</param>
      <param name="port">443</param>
    </step>
    <step key="health" kind="http_check" label="Service is healthy" x="60" y="240">
      <param name="url">https://192.0.2.249/healthz</param>
      <param name="expect_status">200</param>
      <param name="max_ms">2000</param>
    </step>
    <step key="escalate" kind="end" label="Escalate" x="300" y="240">
      <param name="note">The standby did not answer. Do not switch traffic.</param>
    </step>
    <step key="ok" kind="end" label="Standby is serving" x="60" y="340"/>
  </steps>
  <arrows>
    <arrow from="start" to="vip" branch="always"/>
    <arrow from="vip" to="health" branch="pass"/>
    <arrow from="vip" to="escalate" branch="fail"/>
    <arrow from="health" to="ok" branch="pass"/>
    <arrow from="health" to="escalate" branch="fail"/>
  </arrows>
</satom-process>
"""
