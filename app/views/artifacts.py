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
"""
from __future__ import annotations

from flask import (Blueprint, abort, flash, jsonify, redirect, render_template,
                   request, url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Appliance
from ..services import waf_artifacts as wa
from ..services.audit import log_action

bp = Blueprint("artifacts", __name__, url_prefix="/artifacts")

#: A schema/IDL is text. The cap is generous next to the real files (the lab's
#: largest is a few KB) and exists only so a mis-picked ISO cannot fill the
#: partition the SoT store shares.
MAX_BYTES = 4 * 1024 * 1024


def _appliances():
    return Appliance.query.filter_by(kind="fortiweb").order_by(Appliance.name).all()


@bp.route("/")
@login_required
def index():
    kind = (request.args.get("kind") or "").strip()
    rows = wa.history(kind=kind if kind in wa.KINDS else "")
    by_id = {a.id: a.name for a in _appliances()}
    for r in rows:
        r["appliance"] = by_id.get(r["appliance_id"], "") if r["appliance_id"] else ""
    return render_template("artifacts/index.html", rows=rows,
                           kinds=wa.KINDS, unreadable=wa.UNREADABLE,
                           appliances=_appliances(), stats=wa.stats(),
                           active_kind=kind)


@bp.route("/upload", methods=["POST"])
@login_required
@require_permission("config_write")
def upload():
    """Store a file an operator supplies. Touches no appliance."""
    kind = (request.form.get("kind") or "").strip()
    name = (request.form.get("name") or "").strip()
    appl_id = (request.form.get("appliance_id") or "").strip()
    fh = request.files.get("file")
    if kind not in wa.KINDS:
        flash("Unknown artifact type %r." % kind, "danger")
        return redirect(url_for("artifacts.index"))
    if not name:
        flash("An object name is required — it is the mkey the device will "
              "store this under.", "danger")
        return redirect(url_for("artifacts.index"))
    if fh is None or not fh.filename:
        flash("No file selected.", "danger")
        return redirect(url_for("artifacts.index"))
    blob = fh.read(MAX_BYTES + 1)
    if len(blob) > MAX_BYTES:
        flash("File is larger than %d KB — these objects are schemas, not "
              "archives." % (MAX_BYTES // 1024), "danger")
        return redirect(url_for("artifacts.index"))
    if not blob:
        # An empty upload is the exact state this whole feature exists to
        # prevent: it would satisfy every "SATOM has a copy" check and still
        # push an empty object the referencing rule rejects with -7694.
        flash("The file is empty. Storing it would let a clone report success "
              "while pushing an object with no content.", "danger")
        return redirect(url_for("artifacts.index"))
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
    return redirect(url_for("artifacts.index", kind=kind))


@bp.route("/capture", methods=["POST"])
@login_required
@require_permission("config_write")
def capture():
    """Read an artifact off an appliance and keep it. Read-only on the device."""
    kind = (request.form.get("kind") or "").strip()
    name = (request.form.get("name") or "").strip()
    appl = Appliance.query.get_or_404(int(request.form.get("appliance_id") or 0))
    if kind not in wa.KINDS or not name:
        abort(400)
    if not wa.is_readable(kind):
        flash("%s cannot be read back from any FortiWeb (7.6.8 answers -20005 "
              "on every request shape, and it is absent from the device's own "
              "full-config backup). Upload the file instead." % wa.label(kind),
              "danger")
        return redirect(url_for("artifacts.index", kind=kind))
    from ..clients.fortiweb import FortiWebClient
    blob, err = wa.fetch(FortiWebClient(appl), kind, name,
                         vdom=str(getattr(appl, "vdom", "") or ""))
    if blob is None:
        flash("Could not capture %s \"%s\" from %s: %s"
              % (wa.label(kind), name, appl.name, err), "danger")
        return redirect(url_for("artifacts.index", kind=kind))
    row, created = wa.put(kind, name, blob, appliance_id=appl.id, source="captured",
                          by=getattr(current_user, "username", "") or "",
                          note="captured from %s" % appl.name)
    log_action("artifact.capture", "%s %s from %s (%d bytes)"
               % (wa.label(kind), name, appl.name, len(blob)))
    flash("Captured %s \"%s\" from %s — %d bytes%s."
          % (wa.label(kind), name, appl.name, len(blob),
             "" if created else " (unchanged, no new version)"), "success")
    return redirect(url_for("artifacts.index", kind=kind))


@bp.route("/push", methods=["POST"])
@login_required
@require_permission("config_write")
def push():
    """Create the object on an appliance WITH its stored content."""
    row_id = int(request.form.get("id") or 0)
    appl = Appliance.query.get_or_404(int(request.form.get("appliance_id") or 0))
    from ..models_artifacts import WafArtifact
    row = WafArtifact.query.get_or_404(row_id)
    blob = wa.load(row.sha256)
    if blob is None:
        flash("The stored blob for %s is missing from data/artifacts — the "
              "index row survived its content." % row.sha256[:12], "danger")
        return redirect(url_for("artifacts.index"))
    from ..clients.fortiweb import FortiWebClient
    ok, err = wa.push(FortiWebClient(appl), row.kind, row.name, blob,
                      vdom=str(getattr(appl, "vdom", "") or ""))
    log_action("artifact.push", "%s %s -> %s (%s)"
               % (wa.label(row.kind), row.name, appl.name, "ok" if ok else err))
    flash(("Pushed %s \"%s\" to %s." % (wa.label(row.kind), row.name, appl.name))
          if ok else
          ("Push failed on %s: %s" % (appl.name, err)),
          "success" if ok else "danger")
    return redirect(url_for("artifacts.index", kind=row.kind))


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
