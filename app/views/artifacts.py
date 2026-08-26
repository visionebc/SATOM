"""WAF artifact library — the bytes FortiWeb will not give back.

Seven API-Protection object types (XML Schema, XML DTD, WSDL, OpenAPI, gRPC
IDL, JSON Schema, Lua scripting) keep only a NAME in the configuration. Four can
be read off a device through a private endpoint; **three cannot be read from any
FortiWeb at all**, and are absent from the device's own full-config backup. For
those, a clone can only ever be as complete as what SATOM itself holds — which
is what this page fills.

Three verbs, and the separation is deliberate:

``upload``   an operator hands SATOM the file. The ONLY way the three unreadable
             kinds ever enter the store.
``capture``  SATOM reads it off a device and keeps it. Available for the four
             readable kinds; a write to SATOM, never to the appliance.
``push``     SATOM writes a stored copy onto an appliance. The only verb here
             that touches a device, and it is a create — so it is behind
             ``config_write`` and audited, unlike the two above.

Four pages, split by the question each answers:

``/artifacts/``           the catalogue: which object types exist and which of
                          them a device will hand back. Reference, not work.
``/artifacts/manage``     get bytes INTO the store and keep them: upload, author
                          in the browser, capture off a device, push to a
                          device, edit, delete a version.
``/artifacts/inventory``  what is held, where it lives, WHO USES IT, and — the
                          migration answer — which policies could move today and
                          which are blocked on content nobody has a copy of.

``/artifacts/audit``      the whole picture PER DEVICE, in one place and
                          exportable: every policy walked (and every walk that
                          FAILED), every artifact it needs, the profile it
                          arrives through, whether SATOM holds the bytes, what
                          is stored for that box, what is orphaned, and where
                          two boxes hold DIFFERENT content under one name.

The last two are only possible because :mod:`services.artifact_refs` persists
the *policy → artifact* edge the clone planner used to compute and discard, and
:mod:`services.artifact_wpp` attributes each edge to the Web Protection Profile
it travels through.
"""
from __future__ import annotations

import csv
import io as _io
from datetime import datetime

from flask import (Blueprint, Response, abort, flash, jsonify, redirect,
                   render_template, request, url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Appliance
from ..services import artifact_files as af
from ..services import artifact_refs as ar
from ..services import artifact_stats as ast_
from ..services import waf_artifacts as wa
from ..services.audit import log_action

bp = Blueprint("artifacts", __name__, url_prefix="/artifacts")

#: A schema/IDL is text. The cap is generous next to the real files (the lab's
#: largest is a few KB) and exists only so a mis-picked ISO cannot fill the
#: partition the SoT store shares.
MAX_BYTES = 4 * 1024 * 1024


def _appliances():
    return Appliance.query.filter_by(kind="fortiweb").order_by(Appliance.name).all()


def _appliance_names() -> dict:
    return {a.id: a.name for a in Appliance.query.order_by(Appliance.name).all()}


@bp.route("/")
@login_required
def index():
    """Statistics, cut by (device, ADOM) — plus the reference the numbers need.

    No ``history()`` read any more. The page stopped rendering the stored-object
    table when the verbs moved to ``/manage``, and a full scan of every artifact
    version to build a list nothing displays is a cost with no reader.

    ``?scope=<appliance_id>`` narrows every figure on the page to ONE ADOM. The
    filter is applied to the appliance list *before* the statistics are
    computed, so a narrowed page never sums another ADOM's rows into its
    totals — and the ``borrowed`` verdict still consults the whole store,
    because "some other box holds this name" is by definition a fact about
    somewhere else.
    """
    appliances = _appliances()
    raw_scope = (request.args.get("scope") or "").strip()
    scope_id = None
    if raw_scope.isdigit():
        scope_id = int(raw_scope)
    selected = [a for a in appliances if a.id == scope_id] if scope_id else appliances
    # A scope id that matches nothing is a COMPLAINT, never a silent fall back
    # to the whole fleet: that would answer a question about one ADOM with the
    # numbers of twelve.
    if scope_id and not selected:
        flash("No FortiWeb scope with id %s — showing the whole fleet."
              % scope_id, "warning")
        selected, scope_id = appliances, None
    return render_template("artifacts/index.html",
                           kinds=wa.KINDS, unreadable=wa.UNREADABLE,
                           appliances=appliances, stats=wa.stats(),
                           ref_stats=ar.stats(),
                           fleet=ast_.fleet_stats(selected),
                           scope_id=scope_id,
                           active_kind=(request.args.get("kind") or "").strip())


@bp.route("/upload", methods=["POST"])
@login_required
@require_permission("config_write")
def upload():
    """Store a file an operator supplies. Touches no appliance."""
    kind = (request.form.get("kind") or "").strip()
    name = (request.form.get("name") or "").strip()
    appl_id = (request.form.get("appliance_id") or "").strip()
    back = request.form.get("back") or ""
    fh = request.files.get("file")
    if kind not in wa.KINDS:
        flash("Unknown artifact type %r." % kind, "danger")
        return redirect(url_for("artifacts.index"))
    if not name:
        # An OpenAPI object's name IS its filename, so falling back to the
        # uploaded filename is right for every kind and REQUIRED for that one.
        name = (getattr(fh, "filename", "") or "").strip()
    if not name:
        flash("An object name is required — it is the mkey the device will "
              "store this under.", "danger")
        return redirect(url_for("artifacts.manage"))
    if fh is None or not fh.filename:
        flash("No file selected.", "danger")
        return redirect(url_for("artifacts.manage"))
    blob = fh.read(MAX_BYTES + 1)
    if len(blob) > MAX_BYTES:
        flash("File is larger than %d KB — these objects are schemas, not "
              "archives." % (MAX_BYTES // 1024), "danger")
        return redirect(url_for("artifacts.manage"))
    if not blob:
        # An empty upload is the exact state this whole feature exists to
        # prevent: it would satisfy every "SATOM has a copy" check and still
        # push an empty object the referencing rule rejects with -7694.
        flash("The file is empty. Storing it would let a clone report success "
              "while pushing an object with no content.", "danger")
        return redirect(url_for("artifacts.manage"))
    warn = wa.name_warning(kind, name)
    row, created = wa.put(kind, name, blob,
                          appliance_id=int(appl_id) if appl_id.isdigit() else None,
                          source="uploaded",
                          by=getattr(current_user, "username", "") or "",
                          note=(request.form.get("note") or "").strip())
    log_action("artifact.upload", "%s %s (%d bytes, %s)"
               % (wa.label(kind), name, len(blob), row.sha256[:12]))
    flash("Stored %s \"%s\" (%d bytes)%s.%s"
          % (wa.label(kind), name, len(blob),
             "" if created else " — identical to the copy already held",
             (" Warning: " + warn) if warn else ""),
          "warning" if warn else "success")
    if back == "manage":
        return redirect(url_for("artifacts.manage", kind=kind))
    return redirect(url_for("artifacts.index", kind=kind))


@bp.route("/capture", methods=["POST"])
@login_required
@require_permission("config_write")
def capture():
    """Read an artifact off an appliance and keep it. Read-only on the device."""
    kind = (request.form.get("kind") or "").strip()
    name = (request.form.get("name") or "").strip()
    back = request.form.get("back") or ""
    appl = Appliance.query.get_or_404(int(request.form.get("appliance_id") or 0))
    if kind not in wa.KINDS or not name:
        abort(400)
    dest = (url_for("artifacts.manage", kind=kind) if back == "manage"
            else url_for("artifacts.index", kind=kind))
    if not wa.is_readable(kind):
        flash("%s cannot be read back from any FortiWeb (7.6.8 answers -20005 "
              "on every request shape, and it is absent from the device's own "
              "full-config backup). Upload the file instead." % wa.label(kind),
              "danger")
        return redirect(dest)
    from ..clients.fortiweb import FortiWebClient
    blob, err = wa.fetch(FortiWebClient(appl), kind, name,
                         vdom=str(getattr(appl, "vdom", "") or ""))
    if blob is None:
        flash("Could not capture %s \"%s\" from %s: %s"
              % (wa.label(kind), name, appl.name, err), "danger")
        return redirect(dest)
    row, created = wa.put(kind, name, blob, appliance_id=appl.id, source="captured",
                          by=getattr(current_user, "username", "") or "",
                          note="captured from %s" % appl.name)
    log_action("artifact.capture", "%s %s from %s (%d bytes)"
               % (wa.label(kind), name, appl.name, len(blob)))
    flash("Captured %s \"%s\" from %s — %d bytes%s."
          % (wa.label(kind), name, appl.name, len(blob),
             "" if created else " (unchanged, no new version)"), "success")
    return redirect(dest)


@bp.route("/push", methods=["POST"])
@login_required
@require_permission("config_write")
def push():
    """Create the object on an appliance WITH its stored content."""
    row_id = int(request.form.get("id") or 0)
    back = request.form.get("back") or ""
    appl = Appliance.query.get_or_404(int(request.form.get("appliance_id") or 0))
    from ..models_artifacts import WafArtifact
    row = WafArtifact.query.get_or_404(row_id)
    dest = (url_for("artifacts.object_page", kind=row.kind, name=row.name)
            if back == "object" else
            url_for("artifacts.manage", kind=row.kind) if back == "manage"
            else url_for("artifacts.index", kind=row.kind))
    blob = wa.load(row.sha256)
    if blob is None:
        flash("The stored blob for %s is missing from data/artifacts — the "
              "index row survived its content." % row.sha256[:12], "danger")
        return redirect(dest)
    from ..clients.fortiweb import FortiWebClient
    ok, err = wa.push(FortiWebClient(appl), row.kind, row.name, blob,
                      vdom=str(getattr(appl, "vdom", "") or ""))
    log_action("artifact.push", "%s %s -> %s (%s)"
               % (wa.label(row.kind), row.name, appl.name, "ok" if ok else err))
    flash(("Pushed %s \"%s\" to %s." % (wa.label(row.kind), row.name, appl.name))
          if ok else
          ("Push failed on %s: %s" % (appl.name, err)),
          "success" if ok else "danger")
    return redirect(dest)


@bp.route("/blob/<int:row_id>")
@login_required
def blob(row_id: int):
    """The stored bytes, for an operator who needs to check what SATOM holds."""
    from ..models_artifacts import WafArtifact
    row = WafArtifact.query.get_or_404(row_id)
    data = wa.load(row.sha256)
    if data is None:
        abort(404)
    from flask import Response
    return Response(data, mimetype="text/plain; charset=utf-8",
                    headers={"Content-Disposition":
                             'attachment; filename="%s"' % row.name.replace('"', "")})


@bp.route("/api/list")
@login_required
def api_list():
    return jsonify(ok=True, rows=wa.history(), stats=wa.stats())


# --------------------------------------------------------------------------- #
#  Uploads & file management                                                    #
# --------------------------------------------------------------------------- #
@bp.route("/manage")
@login_required
def manage():
    """Get bytes into the store and keep them tidy.

    Deliberately separate from the inventory: this page is a set of VERBS
    (upload, author, capture, push, edit, delete) and the inventory is a set of
    FACTS. Mixing them is how a page grows a delete button next to a read-only
    report and someone finds it with the wrong row selected.
    """
    kind = (request.args.get("kind") or "").strip()
    objects = af.object_index()
    if kind in wa.KINDS:
        objects = [o for o in objects if o["kind"] == kind]
    names = _appliance_names()
    usage = ar.usage_index()
    for o in objects:
        o["appliance"] = names.get(o["appliance_id"], "") if o["appliance_id"] else ""
        o["used_by"] = usage.get((o["kind"], o["name"]), [])
    return render_template("artifacts/manage.html", objects=objects,
                           kinds=wa.KINDS, unreadable=wa.UNREADABLE,
                           appliances=_appliances(), stats=wa.stats(),
                           active_kind=kind, max_kb=MAX_BYTES // 1024)


@bp.route("/save", methods=["POST"])
@login_required
@require_permission("config_write")
def save():
    """Store an edited or browser-authored body as a NEW version.

    "New version" is not a special case: the store is content-addressed, so a
    save that changes nothing advances ``last_seen_at`` and mints no row. The
    operator is told which of the two happened, because "saved" over an
    unchanged file would suggest a version exists that does not.
    """
    kind = (request.form.get("kind") or "").strip()
    name = (request.form.get("name") or "").strip()
    appl_id = (request.form.get("appliance_id") or "").strip()
    text = request.form.get("content")
    if text is None:
        abort(400)
    row, created, err = af.save_text(
        kind, name, text,
        appliance_id=int(appl_id) if appl_id.isdigit() else None,
        by=getattr(current_user, "username", "") or "",
        note=(request.form.get("note") or "edited in SATOM").strip())
    if err:
        flash(err.capitalize() + ".", "danger")
        return redirect(request.form.get("back") or url_for("artifacts.manage"))
    warn = wa.name_warning(kind, name)
    log_action("artifact.save", "%s %s (%d bytes, %s, %s)"
               % (wa.label(kind), name, row.size, row.sha256[:12],
                  "new version" if created else "unchanged"))
    flash(("Saved %s \"%s\" as a new version (%s, %d bytes)."
           % (wa.label(kind), name, row.sha256[:12], row.size)) if created else
          ("%s \"%s\" is unchanged — the stored copy already has this exact "
           "content, so no version was created." % (wa.label(kind), name))
          + ((" Warning: " + warn) if warn else ""),
          "warning" if warn else "success")
    return redirect(url_for("artifacts.object_page", kind=kind, name=name,
                            appl=appl_id or ""))


@bp.route("/delete", methods=["POST"])
@login_required
@require_permission("config_write")
def delete():
    """Remove ONE stored version. The blob survives if another version shares it."""
    row_id = int(request.form.get("id") or 0)
    from ..models_artifacts import WafArtifact
    row = WafArtifact.query.get_or_404(row_id)
    kind, name = row.kind, row.name
    ok, msg, _removed = af.delete_version(row_id)
    log_action("artifact.delete", msg)
    flash(msg.capitalize() + ".", "success" if ok else "danger")
    if af.versions(kind, name, any_scope=True):
        return redirect(url_for("artifacts.object_page", kind=kind, name=name))
    return redirect(url_for("artifacts.manage", kind=kind))


# --------------------------------------------------------------------------- #
#  One object: view, edit, versions, diff, who uses it                          #
# --------------------------------------------------------------------------- #
@bp.route("/object/<kind>/<path:name>")
@login_required
def object_page(kind: str, name: str):
    """The file itself — something FortiWeb's own GUI cannot show.

    Version list, inline viewer, editor, an A→B diff between any two stored
    versions, and the policies that name this object. ``a``/``b`` pick the diff
    sides; with neither, the two newest versions are compared, because "what
    changed last" is the question that gets asked without being typed.
    """
    if kind not in wa.KINDS:
        abort(404)
    rows = af.versions(kind, name, any_scope=True)
    if not rows:
        abort(404)
    names = _appliance_names()
    vlist = []
    for r in rows:
        d = r.to_dict()
        d["appliance"] = names.get(r.appliance_id, "") if r.appliance_id else ""
        vlist.append(d)

    def _pick(arg, default_row):
        raw = (request.args.get(arg) or "").strip()
        if raw.isdigit():
            hit = next((r for r in rows if r.id == int(raw)), None)
            if hit is not None:
                return hit
        return default_row

    current = _pick("v", rows[0])
    blob = wa.load(current.sha256)
    text, clean = af.decode(blob or b"")
    editable, why_not = af.editability(blob)

    b_row = _pick("b", rows[0])
    a_row = _pick("a", rows[1] if len(rows) > 1 else rows[0])
    diff = af.diff_lines(
        wa.load(a_row.sha256), wa.load(b_row.sha256),
        old_label="%s (%s)" % (a_row.sha256[:12], a_row.created_at),
        new_label="%s (%s)" % (b_row.sha256[:12], b_row.created_at))

    used = ar.refs_for(kind, name)
    for u in used:
        u["appliance"] = names.get(u["appliance_id"], "#%s" % u["appliance_id"])
        u["stale"] = ar.is_stale(_parse_iso(u["seen_at"]))
    return render_template(
        "artifacts/object.html", kind=kind, name=name, label=wa.label(kind),
        readable=wa.is_readable(kind), versions=vlist, current=current.to_dict(),
        current_id=current.id, content=text, clean_utf8=clean,
        editable=editable, why_not=why_not, appliances=_appliances(),
        diff=diff, diff_stat=af.diff_stat(diff), a_id=a_row.id, b_id=b_row.id,
        used_by=used, name_warning=wa.name_warning(kind, name),
        appliance_name=names.get(current.appliance_id, "")
                       if current.appliance_id else "")


def _parse_iso(value: str):
    from datetime import datetime
    try:
        return datetime.fromisoformat(value) if value else None
    except ValueError:
        return None


@bp.route("/raw/<int:row_id>")
@login_required
def raw(row_id: int):
    """Inline view (not a download) — the browser renders it as plain text."""
    from ..models_artifacts import WafArtifact
    row = WafArtifact.query.get_or_404(row_id)
    data = wa.load(row.sha256)
    if data is None:
        abort(404)
    from flask import Response
    return Response(data, mimetype="text/plain; charset=utf-8",
                    headers={"Content-Disposition": "inline"})


# --------------------------------------------------------------------------- #
#  Inventory — what is held, where it lives, who needs it                       #
# --------------------------------------------------------------------------- #
#: Filter keys, resolved SERVER-SIDE. A client-side overlay over a partial page
#: shows "3 results" out of the 200 rows it happened to receive, which reads
#: identically to 3 results out of the fleet.
USAGE_FILTERS = ("", "used", "orphan", "stale")


@bp.route("/inventory")
@login_required
def inventory():
    """Everything held, with its users, plus the migration answer per policy."""
    kind = (request.args.get("kind") or "").strip()
    source = (request.args.get("source") or "").strip()
    usage_f = (request.args.get("usage") or "").strip()
    appl_f = (request.args.get("appl") or "").strip()
    query = (request.args.get("q") or "").strip().lower()

    names = _appliance_names()
    usage = ar.usage_index()
    objects = af.object_index()
    for o in objects:
        refs = usage.get((o["kind"], o["name"]), [])
        for r in refs:
            r["appliance"] = names.get(r["appliance_id"], "#%s" % r["appliance_id"])
        o["appliance"] = names.get(o["appliance_id"], "") if o["appliance_id"] else ""
        o["used_by"] = refs
        o["stale"] = bool(refs) and all(
            ar.is_stale(_parse_iso(r["seen_at"])) for r in refs)
        o["orphan"] = not refs

    # Named by some policy but held by nobody: the migration blockers. They are
    # NOT in object_index (which lists what is stored), and leaving them out
    # would make an inventory of holdings read as an inventory of needs.
    held_keys = {(o["kind"], o["name"]) for o in objects}
    missing = []
    for (k, n), refs in sorted(usage.items()):
        if (k, n) in held_keys:
            continue
        for r in refs:
            r["appliance"] = names.get(r["appliance_id"], "#%s" % r["appliance_id"])
        missing.append({"kind": k, "label": wa.label(k), "name": n,
                        "readable": wa.is_readable(k), "used_by": refs})

    rows = objects
    if kind in wa.KINDS:
        rows = [o for o in rows if o["kind"] == kind]
        missing = [m for m in missing if m["kind"] == kind]
    if source in ("uploaded", "captured"):
        rows = [o for o in rows if source in o["sources"]]
    if appl_f == "library":
        rows = [o for o in rows if not o["appliance_id"]]
    elif appl_f.isdigit():
        aid = int(appl_f)
        rows = [o for o in rows
                if o["appliance_id"] == aid
                or any(r["appliance_id"] == aid for r in o["used_by"])]
        missing = [m for m in missing
                   if any(r["appliance_id"] == aid for r in m["used_by"])]
    if usage_f == "used":
        rows = [o for o in rows if o["used_by"]]
    elif usage_f == "orphan":
        rows = [o for o in rows if o["orphan"]]
    elif usage_f == "stale":
        rows = [o for o in rows if o["stale"]]
    if query:
        rows = [o for o in rows if query in o["name"].lower()]
        missing = [m for m in missing if query in m["name"].lower()]

    by_kind: dict[str, dict] = {}
    for o in objects:
        agg = by_kind.setdefault(o["kind"], {"label": o["label"], "objects": 0,
                                             "versions": 0, "bytes": 0,
                                             "orphans": 0})
        agg["objects"] += 1
        agg["versions"] += o["versions"]
        agg["bytes"] += o["bytes"]
        agg["orphans"] += 1 if o["orphan"] else 0

    by_scope: dict[str, dict] = {}
    for o in objects:
        key = o["appliance"] or "SATOM library (no device)"
        agg = by_scope.setdefault(key, {"objects": 0, "bytes": 0})
        agg["objects"] += 1
        agg["bytes"] += o["bytes"]

    cov = ar.coverage_fleet(int(appl_f) if appl_f.isdigit() else None)
    for c in cov:
        c["appliance"] = names.get(c["appliance_id"], "#%s" % c["appliance_id"])

    return render_template(
        "artifacts/inventory.html", rows=rows, missing=missing,
        kinds=wa.KINDS, unreadable=wa.UNREADABLE, appliances=_appliances(),
        stats=wa.stats(), ref_stats=ar.stats(), by_kind=by_kind,
        by_scope=sorted(by_scope.items()), coverage=cov,
        active_kind=kind, active_source=source, active_usage=usage_f,
        active_appl=appl_f, query=request.args.get("q") or "",
        stale_days=ar.STALE_AFTER.days)


@bp.route("/refs/refresh", methods=["POST"])
@login_required
@require_permission("config_write")
def refresh_refs():
    """Re-derive the policy→artifact index for one appliance (or one policy).

    Read-only against the device — it is the clone planner's source walk with
    no destination — but it writes SATOM's own state, so it sits behind the
    same permission as ``capture``.
    """
    appl = Appliance.query.get_or_404(int(request.form.get("appliance_id") or 0))
    policy = (request.form.get("policy") or "").strip()
    budget = (request.form.get("budget") or "").strip()
    if policy:
        from ..clients.fortiweb import FortiWebClient
        from ..services import clone as _clone
        reader = _clone.ClientReader(FortiWebClient(appl))
        res = ar.derive_policy(reader, appl.id, policy)
        log_action("artifact.refs", "walked %s/%s: %s"
                   % (appl.name, policy, "ok" if res["ok"] else res["error"]))
        flash(("Walked %s on %s — %d artifact edge(s)."
               % (policy, appl.name, res["refs"])) if res["ok"] else
              ("Could not walk %s on %s: %s" % (policy, appl.name, res["error"])),
              "success" if res["ok"] else "danger")
    else:
        res = ar.sync_appliance(appl,
                                budget=int(budget) if budget.isdigit()
                                else ar.DEFAULT_BUDGET)
        log_action("artifact.refs", res["summary"])
        flash(res["summary"].capitalize() + ".",
              "success" if res.get("ok") else "danger")
    return redirect(request.form.get("back") or url_for("artifacts.inventory"))


@bp.route("/api/refs")
@login_required
def api_refs():
    kind = (request.args.get("kind") or "").strip()
    name = (request.args.get("name") or "").strip()
    if kind and name:
        return jsonify(ok=True, refs=ar.refs_for(kind, name), stats=ar.stats())
    return jsonify(ok=True,
                   refs=[r for group in ar.usage_index().values() for r in group],
                   stats=ar.stats())


@bp.route("/api/coverage/<int:appliance_id>/<path:policy>")
@login_required
def api_coverage(appliance_id: int, policy: str):
    """Machine-readable migration verdict for ONE policy."""
    return jsonify(ok=True, coverage=ar.policy_coverage(appliance_id, policy))


@bp.route("/audit")
@login_required
def audit():
    """Everything SATOM knows, per DEVICE — on screen, as JSON, or as CSV.

    Read-only and index-only: no appliance is contacted, so this page is safe to
    open mid-incident and gives the same answer twice. The price is a blind spot
    (a policy created since the last sweep is absent), and that sentence ships
    INSIDE the report — ``device_audit()["caveat"]`` — rather than as template
    prose, so it survives into the JSON and CSV an auditor keeps.

    The CSV grain is one row per **(device, policy, profile, artifact)**. A
    per-device summary would be smaller and useless: an auditor's first question
    is which policy is blocked on which file, and a total cannot be re-derived
    back into its rows.
    """
    appl_f = (request.args.get("appl") or "").strip()
    verdict_f = (request.args.get("verdict") or "").strip()
    fmt = (request.args.get("format") or "").strip().lower()

    appliances = _appliances()
    selected = [a for a in appliances if str(a.id) == appl_f] if appl_f.isdigit() \
        else appliances
    report = ar.fleet_audit(selected)
    names = _appliance_names()

    diverge = ar.content_divergence()
    for d in diverge:
        for c in d["copies"]:
            c["appliance"] = (names.get(c["appliance_id"], "#%s" % c["appliance_id"])
                              if c["appliance_id"] else "SATOM library (no device)")

    if verdict_f in ("blocked", "at-risk", "borrowed", "ok"):
        for dev in report:
            dev["artifacts"] = [a for a in dev["artifacts"]
                                if a["verdict"] == verdict_f]

    generated = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    if fmt == "json":
        return jsonify(ok=True, generated_at=generated, devices=report,
                       divergence=diverge, stale_after_days=ar.STALE_AFTER.days)

    if fmt == "csv":
        buf = _io.StringIO()
        w = csv.writer(buf)
        w.writerow(["generated_at", generated])
        w.writerow(["note", report[0]["caveat"] if report else ""])
        w.writerow([])
        w.writerow(["appliance", "policy", "walk_ok", "walk_error",
                    "web_protection_profile", "artifact_kind", "artifact_name",
                    "verdict", "edge_seen_at", "edge_stale"])
        for dev in report:
            if not dev["policies"]:
                # A device with nothing indexed still gets a line. Dropping it
                # would make an unswept box indistinguishable from a clean one
                # in the only artefact the auditor keeps.
                w.writerow([dev["appliance"], "", "", "never swept",
                            "", "", "", "", "", ""])
                continue
            for pol in dev["policies"]:
                if not pol["artifacts"]:
                    w.writerow([dev["appliance"], pol["policy"],
                                "yes" if pol["ok"] else "no", pol["error"],
                                "", "", "",
                                "no file-backed object" if pol["ok"]
                                else "not walked",
                                pol["scanned_at"], "yes" if pol["stale"] else "no"])
                    continue
                for a in pol["artifacts"]:
                    w.writerow([
                        dev["appliance"], pol["policy"],
                        "yes" if pol["ok"] else "no", pol["error"],
                        # The three states are written as WORDS, never as a
                        # blank cell: an empty column in a spreadsheet reads as
                        # "no data", and "" here means the opposite — it means
                        # the walk positively found no profile in between.
                        ("(not attributed)" if a["wpp"] is None else
                         ("(on the policy itself)" if a["wpp"] == "" else a["wpp"])),
                        a["label"], a["name"], a["verdict"],
                        a["seen_at"], "yes" if a["stale"] else "no"])
        data = buf.getvalue()
        return Response(
            data, mimetype="text/csv",
            headers={"Content-Disposition":
                     'attachment; filename="satom-artifact-audit-%s.csv"'
                     % generated.replace(":", "").replace("-", "")})

    return render_template(
        "artifacts/audit.html", report=report, divergence=diverge,
        appliances=appliances, active_appl=appl_f, active_verdict=verdict_f,
        generated=generated, stale_days=ar.STALE_AFTER.days,
        kinds=wa.KINDS, unreadable=wa.UNREADABLE)
