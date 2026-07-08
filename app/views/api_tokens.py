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
from ..models_api_token import (SCOPES, VALID_PRODUCTS, ApiToken, mint_token)
from ..services.audit import log_action

bp = Blueprint("api_tokens", __name__, url_prefix="/api-tokens",
               template_folder="../templates")


@bp.route("/", methods=["GET"])
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    tokens = ApiToken.query.order_by(ApiToken.created_at.desc()).all()
    users = User.query.filter_by(is_active=True).order_by(User.username).all()
    return render_template(
        "api_tokens/index.html",
        tokens=tokens, users=users, scopes=SCOPES, products=VALID_PRODUCTS,
        new_token=None,
    )


@bp.route("/create", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def create():
    from flask_login import current_user

    name = (request.form.get("name") or "").strip()
    owner_id = request.form.get("owner_id", type=int)
    product = (request.form.get("product") or "fortiweb").strip()
    scopes = request.form.getlist("scopes")
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
    )
    log_action("api_token.create", target=f"token:{tok.public_id}",
               extra={"name": tok.name, "owner": owner.username,
                      "scopes": scopes, "product": product})

    tokens = ApiToken.query.order_by(ApiToken.created_at.desc()).all()
    users = User.query.filter_by(is_active=True).order_by(User.username).all()
    return render_template(
        "api_tokens/index.html",
        tokens=tokens, users=users, scopes=SCOPES, products=VALID_PRODUCTS,
        new_token=plaintext, new_token_row=tok,
    )


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
