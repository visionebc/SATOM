"""Admin UI to mint / list / revoke third-party API tokens.

Admin-only (``user_manage``): a token is an infrastructure credential, so who
can create one is deliberately narrow. The plaintext is shown exactly once, on
creation, and never again.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from flask import (Blueprint, abort, flash, redirect, render_template, request,
                   url_for)
from flask_login import login_required

from ..auth.decorators import require_permission
from ..extensions import db
from ..models import Permission, User
from ..models import AppId
from ..models_api_token import (CAPABILITIES, CAPABILITY_DESC, CAPABILITY_GROUPS,
                                CATALOG_EXPLICIT_CAPABILITIES,
                                EXPLICIT_ONLY_CAPABILITIES, SCOPES, VALID_PRODUCTS,
                                GRANT_KINDS, GRANT_LABEL, ApiToken,
                                SCOPE_REQUIRED_PERMISSION, mint_token)
from ..services import token_grants as TG
from ..services.audit import log_action

bp = Blueprint("api_tokens", __name__, url_prefix="/api-tokens",
               template_folder="../templates")


def _render_index(**extra):
    """Shared render — the create form needs the AppID catalog for its scope
    multiselect (active, non-stale AppIDs grouped by product on the client)."""
    tokens = ApiToken.query.order_by(ApiToken.created_at.desc()).all()
    users = User.query.filter_by(is_active=True).order_by(User.username).all()
    appid_catalog = (AppId.query.filter_by(active=True)
                     .order_by(AppId.product, AppId.app_id).all())
    ctx = dict(tokens=tokens, users=users, scopes=SCOPES, products=VALID_PRODUCTS,
               capabilities=CAPABILITIES, appid_catalog=appid_catalog,
               cap_groups=CAPABILITY_GROUPS, cap_desc=CAPABILITY_DESC,
               cap_explicit=sorted(EXPLICIT_ONLY_CAPABILITIES | CATALOG_EXPLICIT_CAPABILITIES),
               grant_candidates={k: TG.candidates(k) for k in GRANT_KINDS},
               grant_status={t.id: TG.status(t) for t in tokens},
               new_token=None)
    ctx.update(extra)
    return render_template("api_tokens/index.html", **ctx)


def _scopes_owner_lacks(owner, scopes) -> list[str]:
    """Scopes whose mapped permission (SCOPE_REQUIRED_PERMISSION) the owner
    does not hold. Minting them made a token that looked more powerful than it
    was -- and the one handler that branched on ``admin`` honoured it."""
    return [s for s in scopes
            if owner is None or not owner.can(SCOPE_REQUIRED_PERMISSION.get(s, ""))]


def _save_grants(tok, by) -> dict:
    """Apply the form's grant pickers (``grant_process`` / ``grant_app``) to
    *tok*; flash what the token's ADOM or owner cannot reach. Returns the
    keys now granted, for the audit row."""
    for kind in GRANT_KINDS:
        refused = TG.select(tok, kind, request.form.getlist("grant_" + kind), by)
        if refused:
            flash(f"Not granted ({GRANT_LABEL[kind]}): {', '.join(refused)} — not offered "
                  f"in the token's ADOM, or its owner may not use it.", "warning")
    return {kind: [g["key"] for g in tok.grants(kind)] for kind in GRANT_KINDS}


@bp.route("/", methods=["GET"])
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    return _render_index()


@bp.route("/create", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def create():
    from flask_login import current_user

    name = (request.form.get("name") or "").strip()
    owner_id = request.form.get("owner_id", type=int)
    product = (request.form.get("product") or "fortiweb").strip()
    scopes = request.form.getlist("scopes")
    capabilities = [c for c in request.form.getlist("capabilities")
                    if c in CAPABILITIES]
    app_ids = [a.strip() for a in request.form.getlist("app_ids") if a.strip()]
    days = request.form.get("expires_days", type=int)

    owner = db.session.get(User, owner_id) if owner_id else None
    if owner is None:
        flash("Choose a valid owner for the token.", "danger")
        return redirect(url_for("api_tokens.index"))
    if product not in VALID_PRODUCTS:
        flash("Invalid product.", "danger")
        return redirect(url_for("api_tokens.index"))
    scopes = [s for s in scopes if s in SCOPES] or ["read"]
    denied = _scopes_owner_lacks(owner, scopes)
    if denied:
        flash(f"{owner.username} cannot hold the {', '.join(denied)} scope(s): "
              "a token never carries more than its owner may do.", "danger")
        return redirect(url_for("api_tokens.index"))

    expires_at = None
    if days and days > 0:
        expires_at = datetime.utcnow() + timedelta(days=days)

    tok, plaintext = mint_token(
        name=name, owner=owner, scopes=scopes, product=product,
        expires_at=expires_at, created_by=getattr(current_user, "username", ""),
        capabilities=capabilities, app_ids=app_ids,
    )
    grants = _save_grants(tok, getattr(current_user, "username", ""))
    db.session.commit()
    log_action("api_token.create", target=f"token:{tok.public_id}",
               extra={"name": tok.name, "owner": owner.username,
                      "scopes": scopes, "product": product,
                      "capabilities": capabilities, "app_ids": app_ids,
                      "grants": grants})

    return _render_index(new_token=plaintext, new_token_row=tok)


@bp.route("/<int:id>/edit", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def edit(id):
    """Change a live token's authorization (name/ADOM/scopes/capabilities/AppID
    scope/expiry). The SECRET is a one-way hash and is never re-issued here."""
    tok = db.session.get(ApiToken, id)
    if tok is None:
        abort(404)

    name = (request.form.get("name") or "").strip()
    product = (request.form.get("product") or tok.product).strip()
    scopes = [s for s in request.form.getlist("scopes") if s in SCOPES] or ["read"]
    capabilities = [c for c in request.form.getlist("capabilities")
                    if c in CAPABILITIES]
    app_ids = [a.strip() for a in request.form.getlist("app_ids") if a.strip()]
    days = request.form.get("expires_days", type=int)

    if product not in VALID_PRODUCTS:
        flash("Invalid product.", "danger")
        return redirect(url_for("api_tokens.index"))
    denied = _scopes_owner_lacks(tok.owner, scopes)
    if denied:
        flash(f"The owner cannot hold the {', '.join(denied)} scope(s).", "danger")
        return redirect(url_for("api_tokens.index"))

    if name:
        tok.name = name[:128]
    tok.product = product
    tok.set_scopes(scopes)
    tok.set_capabilities(capabilities)
    tok.set_app_ids(app_ids)
    from flask_login import current_user
    grants = _save_grants(tok, getattr(current_user, "username", ""))
    # Expiry: a positive day count re-anchors from now; -1 clears (never expires);
    # blank/0 leaves it unchanged.
    if days is not None:
        if days > 0:
            tok.expires_at = datetime.utcnow() + timedelta(days=days)
        elif days < 0:
            tok.expires_at = None
    db.session.commit()
    log_action("api_token.edit", target=f"token:{tok.public_id}",
               extra={"name": tok.name, "scopes": scopes, "product": product,
                      "capabilities": capabilities, "app_ids": app_ids,
                      "grants": grants})
    flash(f"Token “{tok.name}” updated.", "success")
    return redirect(url_for("api_tokens.index"))


@bp.route("/<int:id>/grants/<kind>/<int:oid>/approve", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def approve_grant(id, kind, oid):
    """Re-approve a PAUSED grant: the token may run the object's CURRENT
    version. One deliberate click per object, audited with both
    fingerprints -- ticking the box again in the edit form does not do it."""
    from flask_login import current_user
    tok = db.session.get(ApiToken, id)
    if tok is None or kind not in GRANT_KINDS:
        abort(404)
    res = TG.reapprove(tok, kind, oid, getattr(current_user, "username", ""))
    if res is None:
        flash("That grant cannot be re-approved: it is gone, or the token's ADOM "
              "or owner can no longer reach the object.", "danger")
        return redirect(url_for("api_tokens.index"))
    db.session.commit()
    log_action("api_token.grant_approve", target=f"token:{tok.public_id}",
               extra={"kind": kind, "key": res["key"], "from": res["from"], "to": res["to"]})
    flash(f"Token “{tok.name}” may run the current version of {res['key']}.", "success")
    return redirect(url_for("api_tokens.index"))


@bp.route("/<int:id>/revoke", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def revoke(id):
    tok = db.session.get(ApiToken, id)
    if tok is None:
        abort(404)
    tok.revoked = True
    db.session.commit()
    log_action("api_token.revoke", target=f"token:{tok.public_id}",
               extra={"name": tok.name})
    flash(f"Token “{tok.name}” revoked.", "success")
    return redirect(url_for("api_tokens.index"))


@bp.route("/<int:id>/delete", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def delete(id):
    tok = db.session.get(ApiToken, id)
    if tok is None:
        abort(404)
    pub = tok.public_id
    db.session.delete(tok)
    db.session.commit()
    log_action("api_token.delete", target=f"token:{pub}")
    flash("Token deleted.", "success")
    return redirect(url_for("api_tokens.index"))
