"""/api/v1 intent — templates, baselines and bindings, read and written by
machines.

In the NAF Framework's vocabulary this is the **Intent** block: the desired
state SATOM keeps as Templates (versioned, reviewed bodies), Baselines (a
scoped assembly of approved templates) and Template bindings (which device a
template family governs, with its per-device values). Until this module the
only way to read or change any of them was the console.

Reading needs the ``read`` scope and an owner who may open the Templates
page (``operations.view``); everything is scoped to the token's ADOM exactly
like a console session of that ADOM.

Writing follows the WAF carve-out model (``app.api_v1.waf``): the caller never
picks its own privilege, the administrator does, by granting a capability on
the token:

* ``template_draft`` — create a template or a new version of one, delete an
  unlocked one, bind or unbind a device, author baselines. **Never touches an
  appliance.** The owner must hold ``operations.template_save``.
* ``template_apply`` — approve / reject / revoke a template (owner must hold
  ``operations.template_approve``) and push a template to devices
  (``operations.template_apply``). A push is the console's own path and
  nothing else: a dry-run preview unless ``confirm`` is true, and then the
  canary-gated background job, with the firmware-compatibility gate in front
  of it. There is no direct device write in this module.

Both capabilities are EXPLICIT-only (``models_api_token.EXPLICIT_ONLY_
CAPABILITIES``): a token minted before this surface existed gains nothing.
Every change is audited with the token's public id.
"""
from __future__ import annotations

import json

from flask import g, jsonify, request

from ..extensions import db, limiter
from ..models import Appliance, Baseline, Template, visible_appliances
from ..models_tpl_binding import TemplateBinding
from ..services import api_object_rules as rules
from ..services import baselines as baselines_lib
from ..services import template_bindings as tb
from ..services import template_compat as tc
from ..services import templates as lib
from ..services.audit import log_action
from ..services.product_scope import scope_query, visible_product
from . import bp
from .auth import (_err, audit_extra, declares_capability, owner_permission,
                   token_required)

PERM_VIEW = "operations.view"
PERM_SAVE = "operations.template_save"
PERM_APPROVE = "operations.template_approve"
PERM_APPLY = "operations.template_apply"
PERM_FLEET = "operations.apply"

CAP_DRAFT = "template_draft"
CAP_APPLY = "template_apply"


def _owner():
    return getattr(g, "api_token_owner", None)


def _by() -> str:
    return rules.author_ref(g.api_token)


def _body() -> dict | None:
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else None


# --------------------------------------------------------------------------- #
#  JSON shapes                                                                 #
# --------------------------------------------------------------------------- #
def _template_json(row: Template, *, full: bool = False) -> dict:
    out = {
        "id": row.id,
        "kind": row.kind,
        "name": row.name,
        "version": row.version,
        "product": row.product or "",
        "status": row.status,
        "locked": bool(row.locked),
        "author": row.author or "",
        "note": row.note or "",
        "provenance": row.provenance or "",
        "source_firmware": row.source_firmware or "",
        "reviewed_by": row.reviewed_by or "",
        "reviewed_at": row.reviewed_at.isoformat() if row.reviewed_at else None,
        "reject_reason": row.reject_reason or "",
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }
    if full:
        out["body"] = row.body_dict
        try:
            out["exceptions"] = json.loads(row.exceptions or "null")
        except (ValueError, TypeError):
            out["exceptions"] = None
        out["validated_builds"] = row.validated_builds_dict
        out["versions"] = [
            {"id": v.id, "version": v.version, "status": v.status,
             "author": v.author or "",
             "created_at": v.created_at.isoformat() if v.created_at else None}
            for v in _family(row)]
        out["review_history"] = [
            {"action": e.action, "reviewer": e.reviewer or "",
             "reason": e.reason or "",
             "at": e.created_at.isoformat() if e.created_at else None}
            for e in lib.review_history(row.id)]
        out["bindings"] = [_binding_json(b) for b in tb.for_template(row)]
    return out


def _binding_json(b: TemplateBinding) -> dict:
    return {
        "id": b.id,
        "appliance_id": b.appliance_id,
        "product": b.product or "",
        "kind": b.kind,
        "name": b.name,
        "pinned_version": b.pinned_version,
        "variables": b.variables_dict,
        "note": b.note or "",
        "created_by": b.created_by or "",
        "created_at": b.created_at.isoformat() if b.created_at else None,
        "updated_at": b.updated_at.isoformat() if b.updated_at else None,
    }


def _baseline_json(b: Baseline, *, full: bool = False) -> dict:
    out = {
        "id": b.id,
        "name": b.name,
        "product": b.product or "",
        "zone": b.zone or "",
        "line": b.line or "",
        "department": b.department or "",
        "note": b.note or "",
        "author": b.author or "",
        "template_count": len(b.items or []),
        "created_at": b.created_at.isoformat() if b.created_at else None,
        "updated_at": b.updated_at.isoformat() if b.updated_at else None,
    }
    if full:
        rows = []
        for it in (b.items or []):
            t = db.session.get(Template, it.template_id)
            rows.append({"id": it.template_id, "section": it.section,
                         "position": it.position,
                         "name": t.name if t else "", "kind": t.kind if t else "",
                         "version": t.version if t else None})
        out["templates"] = rows
    return out


# --------------------------------------------------------------------------- #
#  Lookups, ADOM-scoped (404, never 403: do not confirm another ADOM's rows)   #
# --------------------------------------------------------------------------- #
def _family(row: Template) -> list[Template]:
    return (Template.query.filter_by(kind=row.kind, name=row.name)
            .order_by(Template.version.desc()).all())


def _template_or_none(template_id: int) -> Template | None:
    row = db.session.get(Template, int(template_id))
    if row is None or not visible_product(row.product):
        return None
    return row


def _baseline_or_none(baseline_id: int) -> Baseline | None:
    row = db.session.get(Baseline, int(baseline_id))
    if row is None or not visible_product(row.product):
        return None
    return row


def _visible_appliance(appliance_id) -> Appliance | None:
    try:
        aid = int(appliance_id)
    except (TypeError, ValueError):
        return None
    return visible_appliances(user=_owner()).filter(Appliance.id == aid).first()


def _draft_gate():
    """The floor for every write here: the capability, then the owner."""
    ok, code, msg = g.api_token.authorize_object(CAP_DRAFT)
    if not ok:
        log_action("api.intent.denied", extra=audit_extra(reason=code, wanted=CAP_DRAFT))
        return _err(403, code, msg)
    return owner_permission(PERM_SAVE)


def _apply_gate(perm: str):
    ok, code, msg = g.api_token.authorize_object(CAP_APPLY)
    if not ok:
        log_action("api.intent.denied", extra=audit_extra(reason=code, wanted=CAP_APPLY))
        return _err(403, code, msg)
    return owner_permission(perm)


# --------------------------------------------------------------------------- #
#  Templates — read                                                            #
# --------------------------------------------------------------------------- #
@bp.route("/templates", methods=["GET"])
@token_required("read")
def intent_list_templates():
    """Templates of the token's ADOM, newest version first.

    Filters: ``?kind=``, ``?status=pending|approved|rejected``, ``?name=``.
    Bodies are not in the list; ``GET /templates/<id>`` carries them.

    Responses:
        200: ``{"templates": [...]}``.
        403: The owner may not open the Templates page.
    """
    denied = owner_permission(PERM_VIEW)
    if denied is not None:
        return denied
    q = scope_query(Template.query, Template.product)
    kind = (request.args.get("kind") or "").strip()
    status = (request.args.get("status") or "").strip().lower()
    name = (request.args.get("name") or "").strip()
    if kind:
        q = q.filter(Template.kind == kind)
    if status:
        if status not in Template.STATUSES:
            return _err(400, "bad_request",
                        "'status' must be one of pending, approved, rejected.")
        q = q.filter(Template.status == status)
    if name:
        q = q.filter(Template.name == name)
    rows = q.order_by(Template.kind, Template.name, Template.version.desc()).all()
    return jsonify({"templates": [_template_json(r) for r in rows]})


@bp.route("/templates/<int:template_id>", methods=["GET"])
@token_required("read")
def intent_get_template(template_id):
    """One template: body, every version of its family, review history and bindings.

    Responses:
        200: The template.
        404: No such template in the token's ADOM.
    """
    denied = owner_permission(PERM_VIEW)
    if denied is not None:
        return denied
    row = _template_or_none(template_id)
    if row is None:
        return _err(404, "not_found", "No such template.")
    return jsonify(_template_json(row, full=True))


# --------------------------------------------------------------------------- #
#  Templates — write (capability template_draft)                               #
# --------------------------------------------------------------------------- #
@bp.route("/templates", methods=["POST"])
@limiter.limit("30 per minute")
@declares_capability(CAP_DRAFT)
@token_required("write")
def intent_create_template():
    """Create a template, or a new version when the kind/name already exists.

    Body: ``{"kind": ..., "name": ..., "body": {...}, "note": "",
    "exceptions": null, "source_firmware": ""}``. The template is a pending
    draft of the token's ADOM, authored by the token. Never touches a device.

    Responses:
        201: ``{"ok": true, "template": {...}}``.
        400: Unknown kind, missing name, body not a JSON object, unknown build.
        403: Missing ``template_draft``, or the owner may not save templates.
    """
    denied = _draft_gate()
    if denied is not None:
        return denied
    body = _body()
    if body is None:
        return _err(400, "bad_request", "Body must be a JSON object.")
    kind = str(body.get("kind") or "").strip()
    name = str(body.get("name") or "").strip()
    payload = body.get("body")
    if not isinstance(payload, dict):
        return _err(400, "bad_request", "'body' must be a JSON object.")
    try:
        stamp = None
        fw = str(body.get("source_firmware") or "").strip()
        if fw:
            stamp = tc.stamp_authored(tc.session_product(), fw)
        row = lib.save_template(kind, name, payload,
                                note=str(body.get("note") or ""),
                                exceptions=body.get("exceptions"),
                                author=_by(), new_version=True, stamp=stamp)
    except ValueError as exc:
        return _err(400, "bad_request", str(exc))
    log_action("api.template.create", target=f"{row.kind}/{row.name}",
               extra=audit_extra(template_id=row.id, version=row.version))
    return jsonify({"ok": True, "template": _template_json(row, full=True)}), 201


@bp.route("/templates/<int:template_id>", methods=["PUT"])
@limiter.limit("30 per minute")
@declares_capability(CAP_DRAFT)
@token_required("write")
def intent_edit_template(template_id):
    """Save a NEW version of a template (the console's Edit); versions are immutable.

    Body: ``{"body": {...}, "note": "", "exceptions": null}``. The new version
    keeps the build its predecessor was written for and starts as pending.

    Responses:
        200: ``{"ok": true, "template": {...}}`` — the new version.
        400: Body not a JSON object.
        403: Missing ``template_draft``, or the owner may not save templates.
        404: No such template in the token's ADOM.
    """
    denied = _draft_gate()
    if denied is not None:
        return denied
    row = _template_or_none(template_id)
    if row is None:
        return _err(404, "not_found", "No such template.")
    body = _body()
    if body is None:
        return _err(400, "bad_request", "Body must be a JSON object.")
    payload = body.get("body", row.body_dict)
    if not isinstance(payload, dict):
        return _err(400, "bad_request", "'body' must be a JSON object.")
    try:
        new = lib.save_template(row.kind, row.name, payload,
                                note=str(body.get("note", row.note or "")),
                                exceptions=body.get("exceptions", row.exceptions),
                                author=_by(), new_version=True,
                                stamp=tc.inherit_stamp(row))
    except ValueError as exc:
        return _err(400, "bad_request", str(exc))
    log_action("api.template.edit", target=f"{new.kind}/{new.name}",
               extra=audit_extra(template_id=new.id, version=new.version,
                                 from_id=row.id))
    return jsonify({"ok": True, "template": _template_json(new, full=True)})


@bp.route("/templates/<int:template_id>", methods=["DELETE"])
@limiter.limit("30 per minute")
@declares_capability(CAP_DRAFT)
@token_required("write")
def intent_delete_template(template_id):
    """Delete one template version. A locked (curated) template is refused.

    Responses:
        200: ``{"ok": true}``.
        403: Missing ``template_draft``, or the owner may not save templates.
        404: No such template in the token's ADOM.
        409: The template is locked.
    """
    denied = _draft_gate()
    if denied is not None:
        return denied
    row = _template_or_none(template_id)
    if row is None:
        return _err(404, "not_found", "No such template.")
    label = f"{row.kind}/{row.name} v{row.version}"
    if not lib.delete_template(row.id):
        return _err(409, "locked", "This template is locked and cannot be deleted.")
    log_action("api.template.delete", target=label,
               extra=audit_extra(template_id=template_id))
    return jsonify({"ok": True})


# --------------------------------------------------------------------------- #
#  Templates — review lifecycle (capability template_apply)                    #
# --------------------------------------------------------------------------- #
def _review(template_id, action: str):
    denied = _apply_gate(PERM_APPROVE)
    if denied is not None:
        return denied
    row = _template_or_none(template_id)
    if row is None:
        return _err(404, "not_found", "No such template.")
    body = _body() or {}
    reviewer = _by()
    try:
        if action == "approve":
            row = lib.approve_template(row.id, reviewer)
        elif action == "reject":
            row = lib.reject_template(row.id, reviewer,
                                      reason=str(body.get("reason") or ""))
        else:
            row = lib.unapprove_template(row.id, reviewer)
    except ValueError as exc:
        # The four-eyes rule: the authoring token may not approve its own work.
        return _err(409, "review_refused", str(exc))
    log_action(f"api.template.{action}", target=f"{row.kind}/{row.name}",
               extra=audit_extra(template_id=row.id, version=row.version,
                                 reason=str(body.get("reason") or "")[:500]))
    return jsonify({"ok": True, "template": _template_json(row)})


@bp.route("/templates/<int:template_id>/approve", methods=["POST"])
@limiter.limit("30 per minute")
@declares_capability(CAP_APPLY)
@token_required("write")
def intent_approve_template(template_id):
    """Approve a template (fleet-deployable). Four-eyes: not by its own author.

    Responses:
        200: ``{"ok": true, "template": {...}}``.
        403: Missing ``template_apply``, or the owner may not approve.
        404: No such template in the token's ADOM.
        409: The token authored this template (``review_refused``).
    """
    return _review(template_id, "approve")


@bp.route("/templates/<int:template_id>/reject", methods=["POST"])
@limiter.limit("30 per minute")
@declares_capability(CAP_APPLY)
@token_required("write")
def intent_reject_template(template_id):
    """Reject a template with a reason (``{"reason": "..."}``).

    Responses:
        200: ``{"ok": true, "template": {...}}``.
        403: Missing ``template_apply``, or the owner may not approve.
        404: No such template in the token's ADOM.
    """
    return _review(template_id, "reject")


@bp.route("/templates/<int:template_id>/unapprove", methods=["POST"])
@limiter.limit("30 per minute")
@declares_capability(CAP_APPLY)
@token_required("write")
def intent_unapprove_template(template_id):
    """Revoke an approval: the template returns to pending.

    Responses:
        200: ``{"ok": true, "template": {...}}``.
        403: Missing ``template_apply``, or the owner may not approve.
        404: No such template in the token's ADOM.
    """
    return _review(template_id, "unapprove")


# --------------------------------------------------------------------------- #
#  Templates — apply (capability template_apply; the console's own path)       #
# --------------------------------------------------------------------------- #
@bp.route("/templates/<int:template_id>/apply", methods=["POST"])
@limiter.limit("10 per minute")
@declares_capability(CAP_APPLY)
@token_required("write")
def intent_apply_template(template_id):
    """Push a template to devices: a dry-run preview, or the canary-gated job.

    Body: ``{"appliance_ids": [..], "confirm": false, "override_reason": ""}``.
    Without ``confirm`` the answer is the preview the console shows before its
    own Confirm button (per-device plan, firmware-compatibility verdicts,
    unresolved variables) and no device is contacted for real. With
    ``confirm: true`` the same gates run and the apply starts as the
    background job the console uses (canary device first, the rest only if
    the canary succeeds); poll it with ``GET /jobs/<id>`` in the console or
    wait for the audit row. More than one device is a fleet rollout: the
    template must be approved and the owner must hold ``operations.apply``.
    This module never writes to a device itself.

    Responses:
        200: ``{"ok": true, "mode": "preview", ...}``.
        202: ``{"ok": true, "mode": "apply", "job_id": "..."}``.
        400: No appliance ids.
        403: Missing ``template_apply``, the owner may not apply, or a fleet rollout without ``operations.apply``.
        404: No such template, or an appliance outside the token's ADOM.
        409: Unresolved variables, an unapproved template for a fleet rollout, or the firmware gate refused (``apply_refused``).
    """
    denied = _apply_gate(PERM_APPLY)
    if denied is not None:
        return denied
    row = _template_or_none(template_id)
    if row is None:
        return _err(404, "not_found", "No such template.")
    body = _body()
    if body is None:
        return _err(400, "bad_request", "Body must be a JSON object.")
    raw_ids = body.get("appliance_ids")
    if not isinstance(raw_ids, list) or not raw_ids:
        return _err(400, "bad_request", "'appliance_ids' must be a non-empty list.")
    device_ids: list[int] = []
    for v in raw_ids:
        try:
            device_ids.append(int(v))
        except (TypeError, ValueError):
            return _err(400, "bad_request", "'appliance_ids' must be integers.")
    device_ids = list(dict.fromkeys(device_ids))
    targets = visible_appliances(user=_owner()).filter(Appliance.id.in_(device_ids)).all()
    if len(targets) != len(device_ids):
        # 404, not 403: never confirm that another ADOM's device exists.
        return _err(404, "not_found", "Unknown appliance.")
    fleet = len(device_ids) > 1
    owner = _owner()
    if fleet:
        if owner is None or not owner.can(PERM_FLEET):
            return _err(403, "owner_forbidden",
                        "A fleet rollout needs an owner holding 'operations.apply'.")
        if row.status != Template.STATUS_APPROVED:
            return _err(409, "apply_refused",
                        "The template must be approved before a multi-device rollout.")

    from ..services.bulk import BulkRunner, iter_push_items
    items = iter_push_items(row.body_dict)
    bodies, missing_vars = tb.render_for_devices(row, device_ids)
    items_by_device = {aid: iter_push_items(b) for aid, b in bodies.items()}
    names = {a.id: a.name for a in targets}
    var_blocks = ["%s: no value for %s (set it on the device binding)"
                  % (names.get(aid, aid), ", ".join(m))
                  for aid, m in sorted(missing_vars.items())]
    confirm = body.get("confirm") is True
    label = f"{row.kind}/{row.name}"

    if not confirm:
        compat = tc.for_appliances(row, targets, require_validated=fleet)
        if var_blocks:
            compat["blocked"] = True
            compat["blocks"] = var_blocks + list(compat.get("blocks") or [])
        compat["variables_missing"] = {str(k): v for k, v in missing_vars.items()}
        preview = BulkRunner(items, skips=compat.get("skips"),
                             items_by_device=items_by_device).preview(device_ids)
        log_action("api.template.apply.preview", target=label,
                   extra=audit_extra(template_id=row.id, devices=device_ids,
                                     items=len(items), compat_blocked=compat["blocked"]))
        return jsonify({"ok": True, "mode": "preview",
                        "template": {"id": row.id, "name": row.name,
                                     "kind": row.kind, "version": row.version},
                        "item_count": len(items), "preview": preview,
                        "compat": compat})

    if var_blocks:
        log_action("api.template.apply.refused", target=label,
                   extra=audit_extra(template_id=row.id, reason="variables",
                                     blocks=var_blocks[:10]))
        return _err(409, "apply_refused", "Refused: " + "; ".join(var_blocks))
    allowed, compat = tc.enforce(
        row, targets, user=owner,
        override_reason=str(body.get("override_reason") or ""),
        require_validated=fleet, action="template.apply")
    if not allowed:
        log_action("api.template.apply.refused", target=label,
                   extra=audit_extra(template_id=row.id, reason="firmware",
                                     blocks=list(compat.get("blocks") or [])[:10]))
        return jsonify({"error": "apply_refused",
                        "message": "Refused by the firmware compatibility check.",
                        "compat": compat}), 409

    from flask import current_app
    from ..services.bulk import start_apply_job
    job = start_apply_job(
        current_app._get_current_object(),
        title=f'Apply "{row.name}" v{row.version} to {len(device_ids)} device(s)',
        items=items, device_ids=device_ids, by=_by(),
        meta={"template_id": row.id, "kind": row.kind, "name": row.name,
              "compat_overridden": compat.get("overridden"), "via": "api"},
        audit_action="template.apply", audit_target=label,
        skips=compat.get("skips"), items_by_device=items_by_device)
    log_action("api.template.apply.start", target=label,
               extra=audit_extra(template_id=row.id, devices=device_ids,
                                 items=len(items), job_id=job["id"]))
    return jsonify({"ok": True, "mode": "apply", "job_id": job["id"]}), 202


# --------------------------------------------------------------------------- #
#  Bindings                                                                    #
# --------------------------------------------------------------------------- #
@bp.route("/bindings", methods=["GET"])
@token_required("read")
def intent_list_bindings():
    """Template bindings of the token's ADOM; ``?appliance=<id>`` narrows to one device.

    Responses:
        200: ``{"bindings": [...]}``.
        403: The owner may not open the Templates page.
        404: ``?appliance`` names a device outside the token's ADOM.
    """
    denied = owner_permission(PERM_VIEW)
    if denied is not None:
        return denied
    visible = visible_appliances(user=_owner())
    appliance = (request.args.get("appliance") or "").strip()
    if appliance:
        appl = _visible_appliance(appliance)
        if appl is None:
            return _err(404, "not_found", "No such appliance.")
        visible = visible.filter(Appliance.id == appl.id)
    ids = [a.id for a in visible.with_entities(Appliance.id).all()]
    rows = (TemplateBinding.query.filter(TemplateBinding.appliance_id.in_(ids))
            .order_by(TemplateBinding.appliance_id, TemplateBinding.kind,
                      TemplateBinding.name).all()) if ids else []
    return jsonify({"bindings": [_binding_json(b) for b in rows]})


@bp.route("/bindings", methods=["POST"])
@limiter.limit("30 per minute")
@declares_capability(CAP_DRAFT)
@token_required("write")
def intent_bind():
    """Bind a device to a template family (create or update the binding).

    Body: ``{"template_id": .., "appliance_id": .., "pinned_version": null,
    "variables": {"name": "value"}, "note": ""}``. The device must belong to
    the template's ADOM. Desired state only: nothing is pushed.

    Responses:
        200: ``{"ok": true, "binding": {...}}``.
        400: The device is of another product, or a pinned version that does not exist.
        403: Missing ``template_draft``, or the owner may not save templates.
        404: No such template or appliance in the token's ADOM.
    """
    denied = _draft_gate()
    if denied is not None:
        return denied
    body = _body()
    if body is None:
        return _err(400, "bad_request", "Body must be a JSON object.")
    row = _template_or_none(body.get("template_id") or 0) \
        if str(body.get("template_id") or "").isdigit() else None
    if row is None:
        return _err(404, "not_found", "No such template.")
    appl = _visible_appliance(body.get("appliance_id"))
    if appl is None:
        return _err(404, "not_found", "No such appliance.")
    try:
        b = tb.bind(appl, row, pinned_version=body.get("pinned_version"),
                    variables=body.get("variables") or {},
                    note=str(body.get("note") or "").strip(), by=_by())
        db.session.commit()
    except ValueError as exc:
        db.session.rollback()
        return _err(400, "bad_request", str(exc))
    log_action("api.template.bind", target=f"{row.kind}/{row.name}",
               extra=audit_extra(appliance_id=appl.id, binding_id=b.id,
                                 pinned=b.pinned_version,
                                 variables=sorted(b.variables_dict)))
    return jsonify({"ok": True, "binding": _binding_json(b)})


@bp.route("/bindings/<int:binding_id>", methods=["DELETE"])
@limiter.limit("30 per minute")
@declares_capability(CAP_DRAFT)
@token_required("write")
def intent_unbind(binding_id):
    """Remove a binding. Desired state only: the device keeps what it has.

    Responses:
        200: ``{"ok": true}``.
        403: Missing ``template_draft``, or the owner may not save templates.
        404: No such binding in the token's ADOM.
    """
    denied = _draft_gate()
    if denied is not None:
        return denied
    b = db.session.get(TemplateBinding, int(binding_id))
    if b is None or _visible_appliance(b.appliance_id) is None:
        return _err(404, "not_found", "No such binding.")
    label = f"{b.kind}/{b.name}"
    aid = b.appliance_id
    tb.unbind(b.id)
    db.session.commit()
    log_action("api.template.unbind", target=label,
               extra=audit_extra(appliance_id=aid, binding_id=binding_id))
    return jsonify({"ok": True})


# --------------------------------------------------------------------------- #
#  Baselines                                                                   #
# --------------------------------------------------------------------------- #
@bp.route("/baselines", methods=["GET"])
@token_required("read")
def intent_list_baselines():
    """Baselines of the token's ADOM (a scoped assembly of approved templates).

    Responses:
        200: ``{"baselines": [...]}``.
        403: The owner may not open the Templates page.
    """
    denied = owner_permission(PERM_VIEW)
    if denied is not None:
        return denied
    rows = (scope_query(Baseline.query, Baseline.product)
            .order_by(Baseline.name).all())
    return jsonify({"baselines": [_baseline_json(b) for b in rows]})


@bp.route("/baselines/<int:baseline_id>", methods=["GET"])
@token_required("read")
def intent_get_baseline(baseline_id):
    """One baseline with the templates that compose it.

    Responses:
        200: The baseline.
        404: No such baseline in the token's ADOM.
    """
    denied = owner_permission(PERM_VIEW)
    if denied is not None:
        return denied
    row = _baseline_or_none(baseline_id)
    if row is None:
        return _err(404, "not_found", "No such baseline.")
    return jsonify(_baseline_json(row, full=True))


def _template_ids(body: dict) -> list[int] | None:
    ids = body.get("template_ids")
    if ids is None:
        return None
    if not isinstance(ids, list):
        raise ValueError("'template_ids' must be a list of template ids")
    out = []
    for v in ids:
        try:
            out.append(int(v))
        except (TypeError, ValueError) as exc:
            raise ValueError("'template_ids' must be integers") from exc
    for tid in out:
        if _template_or_none(tid) is None:
            raise ValueError(f"template {tid} is not in this ADOM")
    return out


@bp.route("/baselines", methods=["POST"])
@limiter.limit("30 per minute")
@declares_capability(CAP_DRAFT)
@token_required("write")
def intent_create_baseline():
    """Create a baseline: ``{"name", "zone", "line", "department", "template_ids": [..], "note"}``.

    Only approved templates of the token's ADOM can compose it. Desired state
    only: creating a baseline pushes nothing.

    Responses:
        201: ``{"ok": true, "baseline": {...}}``.
        400: Missing name, a name already in use, or a template that is not approved or not in this ADOM.
        403: Missing ``template_draft``, or the owner may not save templates.
    """
    denied = _draft_gate()
    if denied is not None:
        return denied
    body = _body()
    if body is None:
        return _err(400, "bad_request", "Body must be a JSON object.")
    try:
        ids = _template_ids(body) or []
        row = baselines_lib.create_baseline(
            str(body.get("name") or ""), zone=str(body.get("zone") or ""),
            line=str(body.get("line") or ""),
            department=str(body.get("department") or ""),
            template_ids=ids, note=str(body.get("note") or ""), author=_by())
    except ValueError as exc:
        db.session.rollback()
        return _err(400, "bad_request", str(exc))
    from ..services.product_scope import stamp
    try:
        row.product = stamp() or "fortiweb"
        db.session.commit()
    except Exception:  # noqa: BLE001 — the default product stays
        db.session.rollback()
    log_action("api.baseline.create", target=row.name,
               extra=audit_extra(baseline_id=row.id, templates=ids))
    return jsonify({"ok": True, "baseline": _baseline_json(row, full=True)}), 201


@bp.route("/baselines/<int:baseline_id>", methods=["PUT"])
@limiter.limit("30 per minute")
@declares_capability(CAP_DRAFT)
@token_required("write")
def intent_update_baseline(baseline_id):
    """Update a baseline's name, scope, note or templates (fields absent stay).

    Responses:
        200: ``{"ok": true, "baseline": {...}}``.
        400: A name already in use, or a template that is not approved or not in this ADOM.
        403: Missing ``template_draft``, or the owner may not save templates.
        404: No such baseline in the token's ADOM.
    """
    denied = _draft_gate()
    if denied is not None:
        return denied
    row = _baseline_or_none(baseline_id)
    if row is None:
        return _err(404, "not_found", "No such baseline.")
    body = _body()
    if body is None:
        return _err(400, "bad_request", "Body must be a JSON object.")
    try:
        ids = _template_ids(body)
        row = baselines_lib.update_baseline(
            row.id,
            name=body.get("name") if "name" in body else None,
            zone=body.get("zone") if "zone" in body else None,
            line=body.get("line") if "line" in body else None,
            department=body.get("department") if "department" in body else None,
            template_ids=ids, note=body.get("note") if "note" in body else None)
    except ValueError as exc:
        db.session.rollback()
        return _err(400, "bad_request", str(exc))
    log_action("api.baseline.update", target=row.name,
               extra=audit_extra(baseline_id=row.id, fields=sorted(body)))
    return jsonify({"ok": True, "baseline": _baseline_json(row, full=True)})


@bp.route("/baselines/<int:baseline_id>", methods=["DELETE"])
@limiter.limit("30 per minute")
@declares_capability(CAP_DRAFT)
@token_required("write")
def intent_delete_baseline(baseline_id):
    """Delete a baseline. The templates it assembled are untouched.

    Responses:
        200: ``{"ok": true}``.
        403: Missing ``template_draft``, or the owner may not save templates.
        404: No such baseline in the token's ADOM.
    """
    denied = _draft_gate()
    if denied is not None:
        return denied
    row = _baseline_or_none(baseline_id)
    if row is None:
        return _err(404, "not_found", "No such baseline.")
    name = row.name
    baselines_lib.delete_baseline(row.id)
    log_action("api.baseline.delete", target=name,
               extra=audit_extra(baseline_id=baseline_id))
    return jsonify({"ok": True})
