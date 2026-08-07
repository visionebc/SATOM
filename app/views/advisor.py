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

import json

from flask import (Blueprint, render_template, request, jsonify, abort, current_app,
                   Response, stream_with_context)
from flask_login import login_required, current_user

from ..auth.decorators import require_permission
from ..models import Permission, Appliance, LuaScript, visible_appliances
from ..models_advisor import (
    AdvisorConversation, AdvisorProposal, AdvisorRequestLog,
)
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


def _sse(event: str, payload: dict) -> str:
    """One SSE frame. ``json.dumps`` escapes newlines, so a multi-line reply
    can never split into two frames."""
    return "event: %s\ndata: %s\n\n" % (event, json.dumps(payload, default=str))


@bp.route("/<int:cid>/send-stream", methods=["POST"])
@login_required
@require_permission('advisor.use')
def send_stream(cid):
    """The chat's own send path: the reply as it is generated.

    Two things here are load-bearing and easy to lose:

    ``X-Accel-Buffering: no`` -- nginx buffers proxied responses by default,
    and this product's vhost is written by the installer rather than kept in
    git, so a directive in the vhost would not reach installations that
    already exist. Sent per-response, it travels with the feature. Without it
    the whole stream arrives at once at the end, which is indistinguishable
    from the frozen page this endpoint exists to fix.

    Readiness is checked BEFORE the response starts. Once a stream is open the
    status is already 200, so a misconfigured provider could only be reported
    as an error frame -- a failure every client would have to remember to
    handle. Failing here makes it an ordinary HTTP error.
    """
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
        svc.check_ready(conv)
    except ProviderError as exc:
        return jsonify(ok=False, error=str(exc)), 502

    # Both resolved before the generator starts: it runs after this view has
    # returned, when the request-bound objects are gone.
    username = current_user.username
    app_obj = current_app._get_current_object()
    conv_id = conv.id

    def generate():
        # An immediate comment frame so headers reach the browser now rather
        # than with the first token -- which may be a cold model load away.
        yield ": open\n\n"
        try:
            for kind, val in svc.stream_message(app_obj, conv_id, username, text, attachments):
                if kind == "done":
                    yield _sse("done", {"message": val.to_dict()})
                elif kind == "delta":
                    yield _sse("delta", {"text": val})
                elif kind == "status":
                    yield _sse("status", val or {})
                elif kind == "heartbeat":
                    yield _sse("heartbeat", {})
                elif kind == "error":
                    yield _sse("error", val or {"error": "provider call failed"})
        except ProviderError as exc:
            yield _sse("error", {"error": str(exc)})

    resp = Response(stream_with_context(generate()), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache, no-transform"
    resp.headers["X-Accel-Buffering"] = "no"
    return resp


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


@bp.route("/usage")
@login_required
@require_permission('advisor.use')
def usage():
    """The request ledger: every provider call, local and external, successes
    and failures.

    Scoped like the conversations themselves -- an operator sees their own
    calls; a user administrator sees everyone's. A per-user ledger that
    silently showed only your own rows to an admin would understate fleet-wide
    AI spend, which is one of the two questions this page exists to answer.
    """
    q = AdvisorRequestLog.query
    if not current_user.can(Permission.USER_MANAGE):
        q = q.filter_by(username=current_user.username)
    rows = q.order_by(AdvisorRequestLog.id.desc()).limit(200).all()

    reported = [r for r in rows if r.total_tokens() is not None]
    totals = {
        "calls": len(rows),
        "failed": sum(1 for r in rows if not r.ok),
        "external": sum(1 for r in rows if r.external),
        "tool_calls": sum(r.tool_calls for r in rows),
        # Averaged over the calls that HAVE a duration, and token totals over
        # the calls that actually reported usage -- mixing in unreported rows
        # as zero would drag both averages toward a number nothing measured.
        "avg_ms": (round(sum(r.duration_ms for r in rows) / len(rows)) if rows else 0),
        "tokens": sum(r.total_tokens() for r in reported),
        "tokens_from": len(reported),
    }
    return jsonify(ok=True, totals=totals, rows=[r.to_dict() for r in rows])


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
