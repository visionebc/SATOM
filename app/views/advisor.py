"""AI Advisor — chat UI, provider-agnostic, read-only by default.

Sits OUTSIDE the ``/web`` ADOM prefix (like ``monitoring``/``metrics``/
``firmware``): reachable from every ADOM, because a WAF question, a Lua
question, and a report search are all things an operator asks regardless of
which product tab they happen to be on. Context (attachable policies,
exceptions, SoT) is still scoped per-ADOM through the same
``product_scope``/``visible_appliances`` machinery every other multi-product
page uses.
"""
from __future__ import annotations

from flask import Blueprint, render_template, request, jsonify, abort
from flask_login import login_required, current_user

from ..auth.decorators import require_permission
from ..models import Permission, Appliance, LuaScript, visible_appliances
from ..models_advisor import AdvisorConversation, AdvisorProposal
from ..services import advisor as svc
from ..services.advisor_providers import ProviderError

bp = Blueprint("advisor", __name__, url_prefix="/advisor")


def _conv_or_404(cid: int) -> AdvisorConversation:
    conv = AdvisorConversation.query.get_or_404(cid)
    if conv.username != current_user.username and not current_user.can(Permission.USER_MANAGE):
        abort(404)
    return conv


@bp.route("/")
@login_required
@require_permission('advisor.use')
def index():
    svc.ensure_default_ollama()
    conversations = svc.list_conversations(current_user.username)
    return render_template(
        "advisor/index.html", conversations=conversations,
        active=None, enabled=svc.enabled(), tools_on=svc.tools_enabled(),
        external_on=svc.external_allowed(), providers=svc.list_providers())


@bp.route("/<int:cid>")
@login_required
@require_permission('advisor.use')
def open_conversation(cid):
    svc.ensure_default_ollama()
    conv = _conv_or_404(cid)
    conversations = svc.list_conversations(current_user.username)
    return render_template(
        "advisor/index.html", conversations=conversations, active=conv,
        enabled=svc.enabled(), tools_on=svc.tools_enabled(),
        external_on=svc.external_allowed(), providers=svc.list_providers())


@bp.route("/new", methods=["POST"])
@login_required
@require_permission('advisor.use')
def new_conversation():
    body = request.get_json(silent=True) or {}
    conv = svc.create_conversation(
        current_user.username, provider_key=body.get("provider_key", ""))
    return jsonify(ok=True, id=conv.id)


@bp.route("/<int:cid>/messages")
@login_required
@require_permission('advisor.use')
def messages(cid):
    conv = _conv_or_404(cid)
    return jsonify(ok=True, messages=[m.to_dict() for m in conv.messages],
                   proposals=[p.to_dict() for p in conv.proposals])


@bp.route("/<int:cid>/preview", methods=["POST"])
@login_required
@require_permission('advisor.use')
def preview(cid):
    """What would leave the LAN if /send were called right now, with no
    side effects — the pre-send review for an external provider."""
    conv = _conv_or_404(cid)
    body = request.get_json(silent=True) or {}
    result = svc.preview_outbound(conv, body.get("text") or "", body.get("attachments") or [])
    return jsonify(ok=True, **result)


@bp.route("/<int:cid>/send", methods=["POST"])
@login_required
@require_permission('advisor.use')
def send(cid):
    if not svc.enabled():
        return jsonify(ok=False, error="AI Advisor is disabled — enable it in "
                        "Settings → AI Advisor"), 409
    conv = _conv_or_404(cid)
    body = request.get_json(silent=True) or {}
    text = (body.get("text") or "").strip()
    attachments = body.get("attachments") or []
    if not text and not attachments:
        return jsonify(ok=False, error="message is empty"), 400
    try:
        msg = svc.send_message(conv, current_user.username, text, attachments)
    except ProviderError as exc:
        return jsonify(ok=False, error=str(exc)), 502
    return jsonify(ok=True, message=msg.to_dict())


@bp.route("/attachable")
@login_required
@require_permission('advisor.use')
def attachable():
    """What Mode-B can attach, for the picker: server policies + exception
    lists per visible appliance, and existing Lua scripts. Read-only, DB/cache
    only — matches the rest of this product's "a page load never touches an
    appliance" rule."""
    appliances = visible_appliances().order_by(Appliance.name).all()
    return jsonify(ok=True, appliances=[
        {"id": a.id, "name": a.name, "kind": a.kind} for a in appliances
    ], lua_scripts=svc.tool_list_lua_scripts())


@bp.route("/attach/exceptions/<int:appliance_id>")
@login_required
@require_permission('advisor.use')
def attach_exceptions(appliance_id):
    items = svc.tool_list_exceptions(appliance_id)
    return jsonify(ok=True, content=items)


@bp.route("/attach/sot-search")
@login_required
@require_permission('advisor.use')
def attach_sot_search():
    q = request.args.get("q", "")
    return jsonify(ok=True, content=svc.tool_sot_search(q))


@bp.route("/tools")
@login_required
@require_permission('advisor.use')
def tools():
    return jsonify(ok=True, enabled=svc.tools_enabled(), catalog=svc.tools_catalog())


def _can_apply(prop: AdvisorProposal) -> bool:
    if prop.kind == "waf_exception":
        return current_user.can(Permission.CONFIG_WRITE)
    if prop.kind == "lua_script":
        # Same super-admin gate the manual Lua Studio form requires — an AI
        # proposal must never be an easier path to a Lua draft than typing
        # it in by hand.
        return current_user.can("studio.lua_studio")
    return False


@bp.route("/<int:cid>/proposal/<int:pid>/apply", methods=["POST"])
@login_required
@require_permission('advisor.use')
def apply_proposal(cid, pid):
    conv = _conv_or_404(cid)
    prop = AdvisorProposal.query.filter_by(id=pid, conversation_id=conv.id).first_or_404()
    if not _can_apply(prop):
        abort(403)
    try:
        ref = svc.apply_proposal(prop, applied_by=current_user.username)
    except ValueError as exc:
        return jsonify(ok=False, error=str(exc)), 400
    return jsonify(ok=True, applied_ref=ref)


@bp.route("/<int:cid>/proposal/<int:pid>/dismiss", methods=["POST"])
@login_required
@require_permission('advisor.use')
def dismiss_proposal(cid, pid):
    conv = _conv_or_404(cid)
    prop = AdvisorProposal.query.filter_by(id=pid, conversation_id=conv.id).first_or_404()
    try:
        svc.dismiss_proposal(prop, by=current_user.username)
    except ValueError as exc:
        return jsonify(ok=False, error=str(exc)), 400
    return jsonify(ok=True)
