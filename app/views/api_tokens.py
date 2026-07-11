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
from ..models_api_token import (CAPABILITIES, SCOPES, VALID_PRODUCTS, ApiToken,
                                mint_token)
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
               new_token=None)
    ctx.update(extra)
    return render_template("api_tokens/index.html", **ctx)


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

    expires_at = None
    if days and days > 0:
        expires_at = datetime.utcnow() + timedelta(days=days)

    tok, plaintext = mint_token(
        name=name, owner=owner, scopes=scopes, product=product,
        expires_at=expires_at, created_by=getattr(current_user, "username", ""),
        capabilities=capabilities, app_ids=app_ids,
    )
    log_action("api_token.create", target=f"token:{tok.public_id}",
               extra={"name": tok.name, "owner": owner.username,
                      "scopes": scopes, "product": product,
                      "capabilities": capabilities, "app_ids": app_ids})

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

    if name:
        tok.name = name[:128]
    tok.product = product
    tok.set_scopes(scopes)
    tok.set_capabilities(capabilities)
    tok.set_app_ids(app_ids)
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
                      "capabilities": capabilities, "app_ids": app_ids})
    flash(f"Token “{tok.name}” updated.", "success")
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
