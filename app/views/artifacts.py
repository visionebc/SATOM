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
from ..models import Appliance, visible_appliances
from ..services import device_context
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


def _scope():
    """The (device, ADOM) this blueprint stands on — from the SESSION.

    Device-first navigation is how the whole product works: the operator picks
    ONE device on the Architecture map, it lands in ``session['appliance_id']``
    and Backups, Server Objects, Web Protection, Exceptions, Section Config,
    Analysis and FortiAnalyzer all read it back through
    :func:`services.device_context.current_appliance`. ``/artifacts/*`` was the
    only per-device area that never asked, so it rendered the fleet while the
    banner named a device — reported three times, and the two fixes before this
    one could not have helped: they narrowed by ``?appl=``, a query argument
    the operator's navigation never produces.
    """
    return device_context.current_appliance()


def _to_the_map(what: str):
    """No device chosen yet — send the operator to pick one, as Backups and
    Server Objects do. Rendering the fleet instead is the reported defect with
    an empty session."""
    flash("Pick a device first — %s is shown for one device and ADOM at a "
          "time." % what, "info")
    return redirect(url_for("architecture.index"))


def _hop_from_legacy_scope_link():
    """``?appl=``/``?scope=`` used to BE this blueprint's scope.

    Keeping it as a SECOND source is what let the URL bar and the nav badge
    disagree about where the operator is standing, so a link that carries one
    MOVES the session device and re-issues the request without it: after this
    there is exactly one answer to "which device am I on", and the old links
    still land where they promised. Returns a redirect, or ``None`` when there
    is nothing to hop.
    """
    raw = (request.args.get("appl") or request.args.get("scope") or "").strip()
    if not raw.isdigit():
        return None
    row = visible_appliances().filter(Appliance.id == int(raw)).first()
    if row is None:
        # A scope id that matches nothing the user may see is a COMPLAINT, not
        # a silent widening: answering a question about one ADOM with the fleet
        # is the defect this whole change exists to remove.
        flash("No device with id %s in this ADOM — showing the device you are "
              "on." % raw, "warning")
    else:
        device_context.set_current(row.id)
    keep = {k: v for k, v in request.args.items(multi=False)
            if k not in ("appl", "scope")}
    keep.update(request.view_args or {})
    return redirect(url_for(request.endpoint, **keep))


def _scope_choices():
    """The appliance rows a control on a scoped page may offer: the pair the
    page stands on, and nothing else.

    A dropdown listing the fleet is the same defect as a table listing it —
    and it is the half three rounds of guards could not see, because they
    stripped ``<select>`` before asserting on the reasoning that a picker
    enumerates the fleet by design. It does not, here: switching device is the
    Architecture map's job, exactly as it is for every other per-device page.
    """
    scope = _scope()
    return [scope] if scope is not None else []


def _in_scope(appl_id, *, allow_library: bool = False) -> bool:
    """Is a write aimed at the pair this page stands on?

    ``require_device_scope`` already spells out why this is a route gate and
    not a shorter option list: "a page that only hides a link is decorated, not
    scoped". A narrowed ``<select>`` is decoration; a form post carries any id
    its author types.
    """
    scope = _scope()
    if scope is None:
        return False
    raw = str(appl_id or "").strip()
    if not raw:
        return allow_library
    return raw.isdigit() and int(raw) == scope.id


def _row_in_scope(row) -> bool:
    """Is a STORED VERSION this page's to read, edit or destroy?

    ``/blob/<id>``, ``/raw/<id>``, ``delete`` and ``push`` name a version by
    primary key, so the (device, ADOM) never appears in the request at all —
    the id IS the scope. :func:`object_page` already drops another pair's
    versions from the list it renders, but hiding a row is decoration: these
    are the routes the hidden id still opens, and the ids are consecutive
    integers. Library-wide rows (``appliance_id`` NULL) stay in: that is the
    shared bucket this pair reads, which is what :func:`_narrow` and
    ``resolve()`` already say.
    """
    scope = _scope()
    if scope is None:
        return False
    return row.appliance_id in (None, scope.id)


def _no_device_json():
    """JSON callers get 409, never a redirect — ``require_device_scope`` learned
    that a 302 to an HTML page renders as a parse error in a fetch()."""
    return jsonify(ok=False, error="No device selected — /artifacts answers for "
                                   "one device and ADOM at a time. Pick one on "
                                   "the Architecture map."), 409


def _out_of_scope(dest: str):
    """Refuse a write aimed at a device this page is not standing on."""
    scope = _scope()
    where = ("%s / %s" % (scope.host or scope.name, (scope.vdom or "").strip()
                          or "no ADOM")) if scope is not None else "no device"
    flash("That would have written to a device you are not on. This page is "
          "%s — switch device on the Architecture map first." % where, "danger")
    return redirect(dest)


def _appliance_names() -> dict:
    return {a.id: a.name for a in Appliance.query.order_by(Appliance.name).all()}


#: What a library-wide copy is shown as in the DEVICE column. Never a blank
#: cell: an empty device on an inventory row reads as "unknown where this
#: lives", and the opposite is true — it lives everywhere by design.
LIBRARY_DEVICE = "SATOM library"


def _scopes() -> dict:
    """``{appliance_id: {name, device, adom}}`` — the pair, not the label.

    The registered NAME already differs per ADOM (SATOM requires it unique), so
    a name column silently answers "which device and which ADOM" only for
    someone who knows the naming convention. ``host`` is the chassis and
    ``vdom`` is the ADOM, and one chassis legitimately carries four rows.
    """
    out = {}
    for a in Appliance.query.order_by(Appliance.name).all():
        out[a.id] = {"name": a.name, "device": a.host or a.name,
                     "adom": (a.vdom or "").strip()}
    return out


def _scope_of(scopes: dict, appliance_id) -> dict:
    """The (device, ADOM) pair for a scope id — including the library case."""
    if not appliance_id:
        return {"name": "", "device": LIBRARY_DEVICE, "adom": ""}
    return scopes.get(appliance_id,
                      {"name": "#%s" % appliance_id,
                       "device": "#%s" % appliance_id, "adom": ""})


def _verb_dest(back: str, kind: str = "") -> str:
    """Where upload/capture return to. One resolver, three callers.

    The inventory's add-modal posts to the same three verbs the manage page
    does, so it needs the same round trip; a second copy of this mapping is how
    one of the two ends up returning to the page the operator did not start on.
    """
    back = (back or "").strip()
    if back == "manage":
        return url_for("artifacts.manage", kind=kind)
    if back == "inventory":
        return url_for("artifacts.inventory", kind=kind)
    return _safe_back(back, url_for("artifacts.index", kind=kind))


def _used_on(refs: list, scopes: dict) -> list:
    """The DISTINCT (device, ADOM) pairs a set of edges lands on.

    Distinct on the *scope id*, so a device whose four ADOMs each name the
    object appears four times — which is the fact — while one ADOM's twelve
    policies appear once, which is what makes the column readable. The policy
    count rides along, because "used here" and "used here by twelve policies"
    are different answers to whether it is safe to fork a copy.
    """
    seen: dict = {}
    for r in refs:
        aid = r.get("appliance_id")
        row = seen.get(aid)
        if row is None:
            row = dict(_scope_of(scopes, aid), appliance_id=aid, policies=0)
            seen[aid] = row
        row["policies"] += 1
    return sorted(seen.values(), key=lambda s: (s["device"], s["adom"]))


def _narrow(objects: list, usage: dict, scope_id: int) -> tuple:
    """The universe ONE (device, ADOM) pair actually reads.

    Applied BEFORE anything is computed, and to both halves at once. Filtering
    each section as it renders is what shipped and what the operator reported:
    the row table narrowed while the nine counters, the by-type table and
    "where the copies live" kept summing the fleet, so a page cut to one ADOM
    printed 170 objects over a list of 30 and enumerated every other chassis.
    A section added later inherits this narrowing; it cannot forget to repeat
    it.

    ``usage`` is keyed ``(kind, name)`` with no scope in the key, so a copy
    held here whose NAME another chassis also uses arrives carrying that
    chassis's edges. Dropping them is the difference between "used on
    192.0.2.13 / adom_prod" and a column naming a box the operator is not on.
    """
    scoped_usage = {}
    for key, refs in usage.items():
        mine = [r for r in refs if r["appliance_id"] == scope_id]
        if mine:
            scoped_usage[key] = mine
    # A library-wide copy belongs to no pair and IS read by this one: leaving
    # it out would report "not held" for content resolve() serves here today.
    scoped = [o for o in objects
              if o["appliance_id"] == scope_id
              or (not o["appliance_id"]
                  and (o["kind"], o["name"]) in scoped_usage)]
    return scoped, scoped_usage


def _headline(objects: list, usage: dict, cov: list) -> dict:
    """The nine counters, over EXACTLY the rows this page renders.

    Computed from the page's own universe, never from ``wa.stats()`` /
    ``ar.stats()`` — neither takes a scope, so both always answer for the whole
    store. A header that disagrees with the tables under it is not cosmetic:
    the operator cross-reads the two and the bigger number reads as the
    authoritative one.
    """
    edges = [r for refs in usage.values() for r in refs]
    linked = set(usage)
    held = {(o["kind"], o["name"]) for o in objects}
    return {
        # COPIES, not names: the table under this number lists one row per
        # (kind, name, scope), so a name held by three ADOMs is three files and
        # three rows. Counting names printed 78 over a list of 170 — the same
        # header-contradicts-its-page defect this whole change removes. The set
        # arithmetic below still works on NAMES, because "needed and not held"
        # is a question about a name, not about a copy.
        "objects": len(objects),
        "versions": sum(o["versions"] for o in objects),
        "bytes": sum(o["bytes"] for o in objects),
        "edges": len(edges),
        "policies": len({(r["appliance_id"], r["policy_mkey"]) for r in edges}),
        #: Named by a policy of this scope and not held FOR this scope.
        "unheld": len(linked - held),
        "orphans": len(held - linked),
        "stale_edges": sum(1 for r in edges
                           if ar.is_stale(_parse_iso(r["seen_at"]))),
        "failed_scans": sum(1 for c in cov if not c.get("scanned", True)),
    }


def _safe_back(raw: str, fallback: str) -> str:
    """A caller-supplied return path, or the fallback.

    Only a same-site absolute path is honoured. ``//host`` is protocol-relative
    and would send an operator off this appliance with a link that looks local.
    """
    raw = (raw or "").strip()
    if raw.startswith("/") and not raw.startswith("//"):
        return raw
    return fallback


@bp.route("/")
@login_required
def index():
    """Statistics, cut by (device, ADOM) — plus the reference the numbers need.

    No ``history()`` read any more. The page stopped rendering the stored-object
    table when the verbs moved to ``/manage``, and a full scan of every artifact
    version to build a list nothing displays is a cost with no reader.

    Every figure is cut to the (device, ADOM) the SESSION is standing on —
    there is no fleet-wide reading of this page and no control that offers one,
    because "Whole fleet" as a picker's first option is how an operator who
    picked a device kept being shown twelve ADOMs. The ``borrowed`` verdict
    still consults the whole store, because "some other box holds this name" is
    by definition a fact about somewhere else.
    """
    hop = _hop_from_legacy_scope_link()
    if hop is not None:
        return hop
    scope = _scope()
    if scope is None:
        return _to_the_map("the artifact catalogue")
    # ``wa.stats()`` counts the whole store. Printed above a page cut to one
    # pair it states the fleet's totals as this pair's — the same reading that
    # was reported for the inventory's nine counters, still live here. Both
    # figures are re-derived from the narrowed universe, so the header cannot
    # disagree with the page under it. (``ar.stats()`` went with them: this
    # template never rendered a single field of it.)
    objects, _usage = _narrow(af.object_index(), ar.usage_index(), scope.id)
    return render_template("artifacts/index.html",
                           kinds=wa.KINDS, unreadable=wa.UNREADABLE,
                           appliances=[scope],
                           stats={"objects": len(objects),
                                  "bytes": sum(o["bytes"] for o in objects)},
                           fleet=ast_.fleet_stats([scope]),
                           scope_id=scope.id, scope_appl=scope,
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
        return redirect(_verb_dest(back))
    # Library-wide is allowed: it is the shared bucket this pair reads, not
    # another device.
    if not _in_scope(appl_id, allow_library=True):
        return _out_of_scope(_verb_dest(back, kind))
    if not name:
        # An OpenAPI object's name IS its filename, so falling back to the
        # uploaded filename is right for every kind and REQUIRED for that one.
        name = (getattr(fh, "filename", "") or "").strip()
    if not name:
        flash("An object name is required — it is the mkey the device will "
              "store this under.", "danger")
        return redirect(_verb_dest(back, kind))
    if fh is None or not fh.filename:
        flash("No file selected.", "danger")
        return redirect(_verb_dest(back, kind))
    blob = fh.read(MAX_BYTES + 1)
    if len(blob) > MAX_BYTES:
        flash("File is larger than %d KB — these objects are schemas, not "
              "archives." % (MAX_BYTES // 1024), "danger")
        return redirect(_verb_dest(back, kind))
    if not blob:
        # An empty upload is the exact state this whole feature exists to
        # prevent: it would satisfy every "SATOM has a copy" check and still
        # push an empty object the referencing rule rejects with -7694.
        flash("The file is empty. Storing it would let a clone report success "
              "while pushing an object with no content.", "danger")
        return redirect(_verb_dest(back, kind))
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
    return redirect(_verb_dest(back, kind))


@bp.route("/capture", methods=["POST"])
@login_required
@require_permission("config_write")
def capture():
    """Read an artifact off an appliance and keep it. Read-only on the device."""
    kind = (request.form.get("kind") or "").strip()
    name = (request.form.get("name") or "").strip()
    back = request.form.get("back") or ""
    raw_appl = request.form.get("appliance_id") or ""
    if kind not in wa.KINDS or not name:
        abort(400)
    dest = _verb_dest(back, kind)
    # Capture READS a device, so "which device" is the whole question. A
    # capture aimed elsewhere reaches out to a box the operator is not on and
    # files the result under this page.
    if not _in_scope(raw_appl):
        return _out_of_scope(dest)
    appl = Appliance.query.get_or_404(int(raw_appl))
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
    raw_appl = request.form.get("appliance_id") or ""
    from ..models_artifacts import WafArtifact
    row = WafArtifact.query.get_or_404(row_id)
    dest = (url_for("artifacts.object_page", kind=row.kind, name=row.name)
            if back == "object" else _verb_dest(back, row.kind))
    # The only verb here that writes to an appliance. Aiming it off-scope is
    # how content lands on a box nobody is looking at. BOTH ends are checked:
    # the destination, and the row whose bytes are being sent — pushing another
    # pair's copy onto this device is how a file the operator cannot see on
    # this page becomes the file running on it.
    if not _row_in_scope(row) or not _in_scope(raw_appl):
        return _out_of_scope(dest)
    appl = Appliance.query.get_or_404(int(raw_appl))
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
    # 404, not 403: in this page's universe that version does not exist, and
    # "forbidden" would confirm the existence of a row the operator may not see.
    if not _row_in_scope(row):
        abort(404)
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
    """The manage page's rows as JSON — the SAME universe the page renders.

    An unscoped feed is the reported defect with the HTML stripped off: a
    caller that prints these rows under a banner naming one ADOM prints
    twelve. The narrowing is pushed into the query, BEFORE the row limit, so
    the cap cannot silently eat this pair's rows to make room for another's.
    ``stats`` is re-derived from the rows returned, because a store-wide total
    printed over a scoped list is the header/table contradiction already fixed
    on the inventory page.
    """
    scope = _scope()
    if scope is None:
        return _no_device_json()
    rows = wa.history(scope_id=scope.id)
    blobs = {r["sha256"]: r["size"] for r in rows}
    return jsonify(ok=True, rows=rows,
                   stats={"versions": len(rows),
                          "objects": len({(r["kind"], r["name"],
                                           r["appliance_id"]) for r in rows}),
                          "blobs": len(blobs), "bytes": sum(blobs.values())},
                   scope={"appliance_id": scope.id,
                          "device": scope.host or scope.name,
                          "adom": (scope.vdom or "").strip()})


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
    hop = _hop_from_legacy_scope_link()
    if hop is not None:
        return hop
    scope = _scope()
    if scope is None:
        return _to_the_map("artifact management")

    kind = (request.args.get("kind") or "").strip()
    # Same universe as the inventory, from the same narrowing: a verbs page
    # that lists the fleet offers `delete` and `push` on rows belonging to a
    # device the operator is not standing on, one mis-clicked row apart.
    objects, usage = _narrow(af.object_index(), ar.usage_index(), scope.id)
    if kind in wa.KINDS:
        objects = [o for o in objects if o["kind"] == kind]
    names = _appliance_names()
    for o in objects:
        o["appliance"] = names.get(o["appliance_id"], "") if o["appliance_id"] else ""
        o["used_by"] = usage.get((o["kind"], o["name"]), [])
    return render_template("artifacts/manage.html", objects=objects,
                           kinds=wa.KINDS, unreadable=wa.UNREADABLE,
                           appliances=_scope_choices(),
                           stats={"objects": len(objects),
                                  "versions": sum(o["versions"] for o in objects),
                                  "bytes": sum(o["bytes"] for o in objects)},
                           scope_appl=scope,
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

    **A save on a SHARED copy is refused without an answer.** One library-wide
    copy that three ADOMs resolve to is one file: editing it "for prod" edits
    dev and dmz as well, the two devices keep working, and the divergence only
    surfaces the next time somebody diffs them. So the impact is computed
    first, and when more than one (device, ADOM) reads the copy the operator
    must say ``all`` (a new version everyone gets) or ``only`` (fork a copy
    scoped to one pair and leave the shared one exactly as it was).
    """
    kind = (request.form.get("kind") or "").strip()
    name = (request.form.get("name") or "").strip()
    appl_id = (request.form.get("appliance_id") or "").strip()
    text = request.form.get("content")
    if text is None:
        abort(400)
    target = int(appl_id) if appl_id.isdigit() else None
    back = request.form.get("back") or ""
    # A save can RE-SCOPE a copy (the picker sets where it lives), so the
    # target is checked like any other write. Library-wide stays allowed: it
    # is the shared bucket, and the fork question below is what governs it.
    if not _in_scope(appl_id, allow_library=True):
        return _out_of_scope(_safe_back(
            back, url_for("artifacts.object_page", kind=kind, name=name)))

    impact = af.scope_impact(kind, name, target) if name and kind in wa.KINDS \
        else {"shared": False, "affected": []}
    mode = (request.form.get("scope_mode") or "").strip()
    forked_to = None
    if impact["shared"]:
        scopes = _scopes()
        pairs = ", ".join("%s / %s" % (s["device"], s["adom"] or "no ADOM")
                          for s in (_scope_of(scopes, a)
                                    for a in impact["affected"]))
        if mode not in (af.SCOPE_ALL, af.SCOPE_ONLY):
            # NOT saved. Picking a default here is the whole defect: "all" would
            # edit devices the operator never named, and "only" would quietly
            # stop a fleet-wide fix from reaching the fleet.
            flash("Not saved — this copy is read by %d device/ADOM pairs (%s). "
                  "Say whether the change goes to all of them or only to one, "
                  "in which case SATOM forks a copy scoped to that pair."
                  % (len(impact["affected"]), pairs), "danger")
            return redirect(_safe_back(
                back, url_for("artifacts.object_page", kind=kind, name=name)))
        if mode == af.SCOPE_ONLY:
            # "Only" can mean exactly one pair: the one this page stands on.
            # The picker it replaces offered every affected pair, i.e. it was
            # a control that forked a copy onto a device the page is not named
            # for — the same class of write the gates above refuse.
            scope = _scope()
            if scope.id not in impact["affected"]:
                # A fork for a pair whose policies never walk to this copy is a
                # file nothing reads, and it SHADOWS whatever that pair does
                # read. The earlier round refused it; scoping the target does
                # not make it sane.
                flash("Not saved — no walked policy on this device/ADOM reads "
                      "this copy, so a fork scoped here would be a file nothing "
                      "resolves to. The pairs that read it are %s." % pairs,
                      "danger")
                return redirect(_safe_back(
                    back, url_for("artifacts.object_page", kind=kind, name=name)))
            forked_to = scope.id
            target = forked_to

    row, created, err = af.save_text(
        kind, name, text,
        appliance_id=target,
        by=getattr(current_user, "username", "") or "",
        note=(request.form.get("note") or "edited in SATOM").strip())
    if err:
        flash(err.capitalize() + ".", "danger")
        return redirect(request.form.get("back") or url_for("artifacts.manage"))
    warn = wa.name_warning(kind, name)
    log_action("artifact.save", "%s %s (%d bytes, %s, %s%s)"
               % (wa.label(kind), name, row.size, row.sha256[:12],
                  "new version" if created else "unchanged",
                  ", forked to appliance #%s" % forked_to if forked_to else ""))
    if forked_to:
        fs = _scope_of(_scopes(), forked_to)
        # The fork is reported as what it IS — a second copy that from now on
        # shadows the shared one for this pair only. An operator told merely
        # "saved" would expect the next edit of the shared copy to reach here.
        msg = ("Forked %s \"%s\" into a copy scoped to %s / %s (%s, %d bytes). "
               "The shared copy is unchanged, and this pair now reads its own "
               "— a later edit of the shared copy will NOT reach it."
               % (wa.label(kind), name, fs["device"], fs["adom"] or "no ADOM",
                  row.sha256[:12], row.size)) if created else \
              ("%s \"%s\" already reads identical content on %s / %s — nothing "
               "was forked." % (wa.label(kind), name, fs["device"],
                                fs["adom"] or "no ADOM"))
    else:
        msg = ("Saved %s \"%s\" as a new version (%s, %d bytes)%s."
               % (wa.label(kind), name, row.sha256[:12], row.size,
                  " — it reaches %d device/ADOM pairs"
                  % len(impact["affected"]) if impact.get("shared") else "")) \
              if created else \
              ("%s \"%s\" is unchanged — the stored copy already has this exact "
               "content, so no version was created." % (wa.label(kind), name))
    flash(msg + ((" Warning: " + warn) if warn else ""),
          "warning" if warn else "success")
    # No ``appl=``: the scope is the session's, and re-emitting it as a query
    # argument is what gave this blueprint two answers to "which device".
    return redirect(url_for("artifacts.object_page", kind=kind, name=name,
                            back=back or None))


@bp.route("/delete", methods=["POST"])
@login_required
@require_permission("config_write")
def delete():
    """Remove ONE stored version. The blob survives if another version shares it."""
    row_id = int(request.form.get("id") or 0)
    from ..models_artifacts import WafArtifact
    row = WafArtifact.query.get_or_404(row_id)
    # The only DESTRUCTIVE verb in this blueprint, and the only one whose
    # target is named by a bare row id — nothing in the request says which
    # device it belongs to. Unscoped, one id types away another pair's version.
    if not _row_in_scope(row):
        return _out_of_scope(url_for("artifacts.manage", kind=row.kind))
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
    hop = _hop_from_legacy_scope_link()
    if hop is not None:
        return hop
    scope = _scope()
    if scope is None:
        return _to_the_map("an artifact")
    rows = af.versions(kind, name, any_scope=True)
    if not rows:
        abort(404)
    # Versions belonging to another (device, ADOM) are not this page's to show:
    # the version list is where "held elsewhere" would otherwise become a row
    # the operator can open, edit and save from a page that names their device.
    rows = [r for r in rows if r.appliance_id in (None, scope.id)]
    if not rows:
        abort(404)
    names = _appliance_names()
    scopes = _scopes()
    vlist = []
    for r in rows:
        d = r.to_dict()
        d["appliance"] = names.get(r.appliance_id, "") if r.appliance_id else ""
        d["scope"] = _scope_of(scopes, r.appliance_id)
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
        u["scope"] = _scope_of(scopes, u["appliance_id"])
        u["stale"] = ar.is_stale(_parse_iso(u["seen_at"]))

    # The (device, ADOM) the operator arrived FROM. It decides which box a
    # "only here" fork is scoped to, so it is read from the URL rather than
    # guessed from the version list: guessing would silently fork the copy for
    # whichever device happened to sort first.
    working = scope.id
    impact = af.scope_impact(kind, name, current.appliance_id)
    impact["scope_label"] = _scope_of(scopes, current.appliance_id)
    # Each pair carries its own id, so the template never pairs a label with an
    # id by list POSITION — the fork would then be scoped to whichever device
    # happened to line up, and nothing would look wrong on screen.
    impact["affected_scopes"] = [dict(_scope_of(scopes, a), appliance_id=a)
                                 for a in impact["affected"]]
    impact["other_scopes"] = [dict(_scope_of(scopes, a), appliance_id=a)
                              for a in impact["others"]]
    impact["working"] = working
    impact["working_scope"] = _scope_of(scopes, working) if working else None

    return render_template(
        "artifacts/object.html", kind=kind, name=name, label=wa.label(kind),
        readable=wa.is_readable(kind), versions=vlist, current=current.to_dict(),
        current_id=current.id, content=text, clean_utf8=clean,
        editable=editable, why_not=why_not, appliances=_scope_choices(),
        diff=diff, diff_stat=af.diff_stat(diff), a_id=a_row.id, b_id=b_row.id,
        used_by=used, name_warning=wa.name_warning(kind, name),
        impact=impact, scopes=scopes, scope_appl=scope,
        back=_safe_back(request.args.get("back"),
                        url_for("artifacts.inventory", q=name)),
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
    if not _row_in_scope(row):
        abort(404)
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
    """Everything held BY ONE (device, ADOM), its users, and what blocks a move.

    The universe is the (device, ADOM) the SESSION is standing on — the one
    the operator picked on the Architecture map and the one the banner names.
    It is applied in :func:`_narrow` before a single figure is computed, and
    there is no argument and no control that widens it.
    """
    hop = _hop_from_legacy_scope_link()
    if hop is not None:
        return hop
    scope = _scope()
    if scope is None:
        return _to_the_map("the artifact inventory")

    kind = (request.args.get("kind") or "").strip()
    source = (request.args.get("source") or "").strip()
    usage_f = (request.args.get("usage") or "").strip()
    #: WITHIN the scope, not across scopes: "everything here", "only the copies
    #: this pair holds itself", "only the shared ones it reads". The control
    #: this replaces was an appliance picker whose neutral option was "Any",
    #: i.e. the page's own way back to the fleet.
    held_f = (request.args.get("held") or "").strip()
    query = (request.args.get("q") or "").strip().lower()

    names = _appliance_names()
    scopes = _scopes()
    scope_id = scope.id

    usage = ar.usage_index()
    objects = af.object_index()
    #: "Some OTHER scope holds this name" is by definition a fact about
    #: somewhere else, so it is read before the narrowing — the same exception
    #: services.artifact_stats makes for its ``borrowed`` verdict.
    held_anywhere = {(o["kind"], o["name"]) for o in objects}
    objects, usage = _narrow(objects, usage, scope_id)
    for o in objects:
        refs = usage.get((o["kind"], o["name"]), [])
        for r in refs:
            r["appliance"] = names.get(r["appliance_id"], "#%s" % r["appliance_id"])
        o["appliance"] = names.get(o["appliance_id"], "") if o["appliance_id"] else ""
        o["scope"] = _scope_of(scopes, o["appliance_id"])
        # WHERE it is used, as (device, ADOM) and nothing else. The policy and
        # profile names are still one click away on the object page; on a
        # fleet-sized list they are four lines per row of detail nobody scans,
        # and they pushed the one fact this page is read for — which box and
        # which ADOM — off the right-hand edge.
        o["used_on"] = _used_on(refs, scopes)
        o["used_by"] = refs
        # A library-wide copy is ONE file. How many OTHER pairs read it is the
        # copy-on-write warning, and it is a fact about this row rather than an
        # excursion into another device's inventory — so it survives the
        # narrowing as a count. A scoped copy is served to exactly one pair, so
        # the question does not arise there.
        o["shared_with"] = 0
        if not o["appliance_id"]:
            o["shared_with"] = max(
                0, len(af.scope_impact(o["kind"], o["name"], None)["affected"]) - 1)
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
                        "readable": wa.is_readable(k), "used_by": refs,
                        # Held for some OTHER scope. Rendering that as a plain
                        # "not held" hides that resolve() would fall back to
                        # another box's bytes — the `borrowed` guess the audit
                        # page exists to flag — and rendering it as held would
                        # claim this pair owns a file it does not.
                        "elsewhere": (k, n) in held_anywhere,
                        "used_on": _used_on(refs, scopes)})

    rows = objects
    if kind in wa.KINDS:
        rows = [o for o in rows if o["kind"] == kind]
        missing = [m for m in missing if m["kind"] == kind]
    if source in ("uploaded", "captured"):
        rows = [o for o in rows if source in o["sources"]]
    if held_f == "library":
        rows = [o for o in rows if not o["appliance_id"]]
    elif held_f == "own":
        rows = [o for o in rows if o["appliance_id"]]
    # Nothing else re-filters by scope: _narrow() already made this pair the
    # only universe there is. Re-filtering per section is how the other five
    # came to be forgotten.
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
        sc = o["scope"]
        key = "%s | %s" % (sc["device"], sc["adom"])
        agg = by_scope.setdefault(key, {"objects": 0, "bytes": 0,
                                        "device": sc["device"],
                                        "adom": sc["adom"]})
        agg["objects"] += 1
        agg["bytes"] += o["bytes"]

    cov = ar.coverage_fleet(scope_id)
    for c in cov:
        c["appliance"] = names.get(c["appliance_id"], "#%s" % c["appliance_id"])

    return render_template(
        "artifacts/inventory.html", rows=rows, missing=missing,
        kinds=wa.KINDS, unreadable=wa.UNREADABLE, appliances=_scope_choices(),
        head=_headline(objects, usage, cov), by_kind=by_kind,
        scope_id=scope_id, scope_appl=_scope_of(scopes, scope_id),
        by_scope=sorted(by_scope.items()), coverage=cov,
        active_kind=kind, active_source=source, active_usage=usage_f,
        active_held=held_f, query=request.args.get("q") or "",
        stale_days=ar.STALE_AFTER.days, max_kb=MAX_BYTES // 1024,
        back=request.full_path)


@bp.route("/refs/refresh", methods=["POST"])
@login_required
@require_permission("config_write")
def refresh_refs():
    """Re-derive the policy→artifact index for one appliance (or one policy).

    Read-only against the device — it is the clone planner's source walk with
    no destination — but it writes SATOM's own state, so it sits behind the
    same permission as ``capture``.
    """
    raw_appl = request.form.get("appliance_id") or ""
    if not _in_scope(raw_appl):
        return _out_of_scope(url_for("artifacts.inventory"))
    appl = Appliance.query.get_or_404(int(raw_appl))
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
    """Which policies of THIS pair name an artifact.

    An edge is a fact about one (device, ADOM) — it carries ``appliance_id`` —
    so a fleet-wide list here answers "who uses this file" with policies that
    live on boxes the operator is not on. ``ar.stats()`` went with it for the
    same reason its siblings did: it counts the whole index.
    """
    scope = _scope()
    if scope is None:
        return _no_device_json()
    kind = (request.args.get("kind") or "").strip()
    name = (request.args.get("name") or "").strip()
    if kind and name:
        refs = ar.refs_for(kind, name, appliance_id=scope.id)
    else:
        refs = [r for group in ar.usage_index().values() for r in group
                if r["appliance_id"] == scope.id]
    return jsonify(ok=True, refs=refs,
                   stats={"edges": len(refs),
                          "linked_objects": len({(r["kind"], r["name"])
                                                 for r in refs}),
                          "policies": len({r["policy_mkey"] for r in refs}),
                          "devices": 1 if refs else 0},
                   scope={"appliance_id": scope.id,
                          "device": scope.host or scope.name,
                          "adom": (scope.vdom or "").strip()})


@bp.route("/api/coverage/<int:appliance_id>/<path:policy>")
@login_required
def api_coverage(appliance_id: int, policy: str):
    """Machine-readable migration verdict for ONE policy of THIS pair.

    The appliance id is in the PATH, so this route was the one place where the
    whole scope could be typed. The audit page that links it is scoped to the
    session device, so the only ids it can emit are this pair's; any other is
    somebody addressing the route directly.
    """
    scope = _scope()
    if scope is None:
        return _no_device_json()
    if appliance_id != scope.id:
        return jsonify(ok=False, error="That policy belongs to a device this "
                                       "page is not standing on."), 404
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
    hop = _hop_from_legacy_scope_link()
    if hop is not None:
        return hop
    scope = _scope()
    if scope is None:
        return _to_the_map("the artifact audit")
    verdict_f = (request.args.get("verdict") or "").strip()
    fmt = (request.args.get("format") or "").strip().lower()

    # One device, like every other page in this group. A fleet-wide export is
    # a real thing to want, but it is a DIFFERENT button — an audit that
    # silently covers twelve ADOMs while the banner names one is the reading
    # this whole change removes.
    appliances = selected = [scope]
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
        appliances=appliances, active_appl=str(scope.id),
        scope_appl=scope, active_verdict=verdict_f,
        generated=generated, stale_days=ar.STALE_AFTER.days,
        kinds=wa.KINDS, unreadable=wa.UNREADABLE)
