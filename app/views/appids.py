"""AppIDs — admin console for the billing + access-control catalog.

Global ADOM, admin-only (USER_MANAGE). Lets an operator:

  * see the AppID catalog (manual + imported, active/stale badges);
  * add an AppID by hand;
  * UPLOAD a file (CSV/txt/PDF), MAP its columns to DB fields ONCE, and import —
    the mapping is saved and reused by later uploads and the nightly action
    (that is the "auto-adapt, no need to come back" the operator asked for);
  * configure an external URL source (for the nightly) + save the mapping;
  * assign a Server Policy to an AppID (1 per policy).

The heavy lifting is in :mod:`app.services.appids`; this file is thin request
plumbing + audit.
"""
from __future__ import annotations

from flask import (Blueprint, flash, jsonify, redirect, render_template,
                   request, url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Appliance, Permission
from ..services import appids as svc
from ..services.audit import log_action

bp = Blueprint("appids", __name__, url_prefix="/appids")

_ALLOWED_EXT = {"csv", "tsv", "txt", "pdf"}


def _who() -> str:
    return getattr(current_user, "username", "") or ""


@bp.route("/", methods=["GET"])
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    mapping = svc.get_mapping()
    # Never leak encrypted secrets to the template.
    src = dict(mapping.get("source") or {})
    src["has_password"] = bool(src.pop("password_enc", None))
    src["has_token"] = bool(src.pop("token_enc", None))
    # GLOBAL catalog: assignment spans BOTH products' appliances.
    appliances = (Appliance.query
                  .filter(Appliance.kind.in_(("fortiweb", "fortiadc")))
                  .order_by(Appliance.name).all())
    return render_template(
        "appids/index.html",
        catalog=svc.catalog(),
        mapping=mapping,
        source=src,
        appliances=appliances,
        bindings=[b.to_dict() for b in svc.AppIdPolicy.query.all()],
    )


@bp.route("/create", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def create():
    try:
        row = svc.create_manual(
            app_id=request.form.get("app_id", ""),
            customer=request.form.get("customer", ""),
            label=request.form.get("label", ""),
            rate=request.form.get("rate", ""),
            created_by=_who(),
        )
    except ValueError as exc:
        flash(str(exc), "warning")
        return redirect(url_for("appids.index"))
    log_action("appid.create", target=row.app_id,
               extra={"customer": row.customer})
    flash(f"AppID {row.app_id} created.", "success")
    return redirect(url_for("appids.index"))


@bp.route("/<int:app_id_pk>/delete", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def delete(app_id_pk):
    row = svc.get(app_id_pk)
    if row is not None:
        name = row.app_id
        svc.delete(app_id_pk)
        log_action("appid.delete", target=name)
        flash(f"AppID {name} deleted (and its policy bindings).", "success")
    return redirect(url_for("appids.index"))


@bp.route("/preview", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def preview():
    """AJAX: parse an uploaded file → columns + first rows so the operator can
    build the column→field mapping. Does NOT import."""
    file = request.files.get("catalog_file")
    if file is None or not file.filename:
        return jsonify({"error": "no file"}), 400
    ext = file.filename.lower().rsplit(".", 1)[-1] if "." in file.filename else ""
    if ext not in _ALLOWED_EXT:
        return jsonify({"error": f"unsupported .{ext} (use CSV/TSV/TXT/PDF)"}), 400
    try:
        table = svc.parse_upload(file.filename, file.read())
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"parse failed: {exc}"}), 400
    return jsonify(table.preview())


@bp.route("/import", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def do_import():
    """Save the mapping + import the uploaded file additively."""
    file = request.files.get("catalog_file")
    if file is None or not file.filename:
        flash("Choose a file to import.", "warning")
        return redirect(url_for("appids.index"))

    mapping = _mapping_from_form()
    # Preserve any previously-saved external source config on save.
    prev = svc.get_mapping()
    mapping.setdefault("source", prev.get("source", {"type": "manual"}))
    svc.save_mapping(mapping=mapping)

    try:
        table = svc.parse_upload(file.filename, file.read())
        records = svc.apply_mapping(table, mapping)
    except ValueError as exc:
        flash(f"Could not import: {exc}", "danger")
        return redirect(url_for("appids.index"))
    if not records:
        flash("No rows with a non-empty AppID were found — check the AppID "
              "column mapping.", "warning")
        return redirect(url_for("appids.index"))

    res = svc.import_records(records, source="import",
                             created_by=_who())
    log_action("appid.import", target=file.filename, extra=res.as_dict())
    flash(f"Imported from {file.filename}: {res.summary()}.", "success")
    return redirect(url_for("appids.index"))


@bp.route("/source", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def save_source():
    """Persist the external URL source + mapping used by the nightly action."""
    mapping = svc.get_mapping()
    # Update the mapping fields if the source form also carried them.
    fm = _mapping_from_form()
    if fm.get("fields"):
        mapping["fields"] = fm["fields"]
        mapping["extra"] = fm.get("extra", {})
        mapping["has_header"] = fm.get("has_header", True)
    source = {
        "type": request.form.get("source_type", "manual"),
        "url": request.form.get("source_url", "").strip(),
        "auth": request.form.get("source_auth", "none"),
        "username": request.form.get("source_username", "").strip(),
    }
    if request.form.get("source_password"):
        source["password"] = request.form["source_password"]
    if request.form.get("source_token"):
        source["token"] = request.form["source_token"]
    # keep existing encrypted secrets if the form left them blank
    prev = (svc.get_mapping().get("source") or {})
    if "password" not in source and prev.get("password_enc"):
        source["password_enc"] = prev["password_enc"]
    if "token" not in source and prev.get("token_enc"):
        source["token_enc"] = prev["token_enc"]
    mapping["source"] = source
    svc.save_mapping(mapping=mapping)
    log_action("appid.source_save", target=source.get("url", ""),
               extra={"type": source["type"], "auth": source["auth"]})
    flash("External source + mapping saved. The nightly action will reuse it.",
          "success")
    return redirect(url_for("appids.index"))


@bp.route("/assign", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def assign():
    try:
        app_id_pk = int(request.form.get("app_id_pk", "0"))
        appliance_id = int(request.form.get("appliance_id", "0"))
    except (TypeError, ValueError):
        flash("Pick an AppID and a device.", "warning")
        return redirect(url_for("appids.index"))
    policy = request.form.get("server_policy", "").strip()
    try:
        row = svc.assign(app_id_pk=app_id_pk, appliance_id=appliance_id,
                         server_policy=policy, by=_who())
    except ValueError as exc:
        flash(str(exc), "warning")
        return redirect(url_for("appids.index"))
    log_action("appid.assign", target=policy,
               extra={"app_id_pk": app_id_pk, "appliance_id": appliance_id})
    flash(f"Policy {policy} assigned.", "success")
    return redirect(url_for("appids.index"))


@bp.route("/unassign", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def unassign():
    try:
        appliance_id = int(request.form.get("appliance_id", "0"))
    except (TypeError, ValueError):
        return redirect(url_for("appids.index"))
    policy = request.form.get("server_policy", "").strip()
    if svc.unassign(appliance_id, policy):
        log_action("appid.unassign", target=policy,
                   extra={"appliance_id": appliance_id})
        flash(f"Policy {policy} unassigned.", "success")
    return redirect(url_for("appids.index"))


# --------------------------------------------------------------------------- #
def _mapping_from_form() -> dict:
    """Build the mapping dict from the map form fields.

    Field refs come as ``map_app_id`` / ``map_customer`` / ``map_label`` /
    ``map_rate`` (column name or index), plus repeatable ``extra_name[]`` /
    ``extra_col[]`` pairs for the extra source columns.
    """
    fields = {}
    for f in ("app_id", "customer", "label", "rate"):
        v = request.form.get(f"map_{f}", "").strip()
        if v:
            fields[f] = v
    extra = {}
    names = request.form.getlist("extra_name")
    cols = request.form.getlist("extra_col")
    for name, col in zip(names, cols):
        name, col = name.strip(), col.strip()
        if name and col:
            extra[name] = col
    return {
        "has_header": request.form.get("has_header", "1") == "1",
        "fields": fields,
        "extra": extra,
    }
