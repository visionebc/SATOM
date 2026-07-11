"""Lua Studio — author, lint, analyse and (dry-run) deploy device Lua scripts.

Super-admin only. Linting never executes device code (``luac -p``); analysis is
static; deploy is dry-run by default and needs config_write + confirm for a real
push. FortiWeb "Web Scripting" and FortiADC "Scripting" are both targeted.
"""
from __future__ import annotations

import json
from datetime import datetime
from functools import wraps

from flask import (Blueprint, render_template, request, redirect, url_for,
                   flash, abort, jsonify)
from flask_login import login_required, current_user

from ..extensions import db
from ..models import LuaScript, Permission, Appliance
from ..services import lua_studio as lua
from ..services import lua_examples as examples
from ..services.audit import log_action
from ..services.product_scope import stamp, scope_query

bp = Blueprint("lua_studio", __name__, url_prefix="/lua")


def _examples_json(target: str) -> str:
    """Example catalog for one target, serialized for the editor JSON island."""
    return json.dumps(examples.for_target(target)).replace("</", "<\\/")


def superadmin_required(fn):
    """Super-admin = full admin capability set (User.is_admin_capable)."""
    @wraps(fn)
    @login_required
    def wrapper(*a, **kw):
        if not current_user.can("studio.lua_studio"):
            abort(403)
        return fn(*a, **kw)
    return wrapper


def _appliances(target):
    return (Appliance.query.filter_by(kind=target)
            .order_by(Appliance.name).all())


@bp.route("/")
@superadmin_required
def index():
    scripts = (scope_query(LuaScript.query, LuaScript.product)
               .order_by(LuaScript.updated_at.desc()).all())
    return render_template("lua_studio/list.html", scripts=scripts)


@bp.route("/new")
@superadmin_required
def new():
    target = request.args.get("target", "fortiweb")
    if target not in LuaScript.TARGETS:
        target = "fortiweb"
    return render_template("lua_studio/editor.html", script=None, target=target,
                           appliances=_appliances(target),
                           examples_json=_examples_json(target),
                           example_cats=examples.categories(target))


@bp.route("/<int:sid>/edit")
@superadmin_required
def edit(sid):
    script = LuaScript.query.get_or_404(sid)
    return render_template("lua_studio/editor.html", script=script,
                           target=script.target,
                           appliances=_appliances(script.target),
                           examples_json=_examples_json(script.target),
                           example_cats=examples.categories(script.target))


@bp.route("/save", methods=["POST"])
@bp.route("/<int:sid>/save", methods=["POST"])
@superadmin_required
def save(sid=None):
    f = request.form
    name = (f.get("name") or "").strip()
    if not name:
        flash("A name is required.", "error")
        return redirect(url_for("lua_studio.new"))
    target = f.get("target") if f.get("target") in LuaScript.TARGETS else "fortiweb"
    if sid:
        script = LuaScript.query.get_or_404(sid)
    else:
        script = LuaScript(created_by=current_user.username, product=stamp())
        db.session.add(script)
    script.name = name
    script.target = target
    script.deploy_object = (f.get("deploy_object") or "").strip()
    script.code = f.get("code") or ""
    aid = f.get("appliance_id")
    script.appliance_id = int(aid) if (aid or "").isdigit() else None
    db.session.commit()
    log_action("lua.save", target=script.name, extra={"id": script.id})
    flash(f"Saved “{script.name}”.", "success")
    return redirect(url_for("lua_studio.edit", sid=script.id))


@bp.route("/analyze", methods=["POST"])
@superadmin_required
def analyze():
    """Lint + static analysis of a (possibly unsaved) script. JSON."""
    code = request.form.get("code") or (request.get_json(silent=True) or {}).get("code", "")
    target = request.form.get("target") or "fortiweb"
    lint = lua.lint(code, target)
    report = lua.analyze(code, target)
    return jsonify(ok=True, lint=lint, analysis=report)


@bp.route("/<int:sid>/mark-tested", methods=["POST"])
@superadmin_required
def mark_tested(sid):
    script = LuaScript.query.get_or_404(sid)
    lint = lua.lint(script.code, script.target)
    report = lua.analyze(script.code, script.target)
    script.analysis = json.dumps({"lint": lint, "analysis": report})
    if lint.get("ok"):
        script.status = "tested"
        flash("Lint passed — marked tested.", "success")
    else:
        flash("Lint failed — fix the reported errors first.", "error")
    db.session.commit()
    return redirect(url_for("lua_studio.edit", sid=script.id))


@bp.route("/<int:sid>/status", methods=["POST"])
@superadmin_required
def set_status(sid):
    """Lifecycle transitions with gates: draft <-> tested. ``deployed`` is set
    ONLY by a successful real deploy — you can't stamp it by hand. Promoting to
    ``tested`` re-runs the lint gate."""
    script = LuaScript.query.get_or_404(sid)
    new_status = request.form.get("status")
    if new_status not in ("draft", "tested"):
        abort(400)
    if new_status == "tested":
        lint = lua.lint(script.code, script.target)
        report = lua.analyze(script.code, script.target)
        script.analysis = json.dumps({"lint": lint, "analysis": report})
        if not lint.get("ok"):
            flash("Lint failed — fix the reported errors before marking tested.",
                  "error")
            db.session.commit()
            return redirect(url_for("lua_studio.edit", sid=script.id))
    script.status = new_status
    db.session.commit()
    log_action("lua.status", target=script.name, extra={"status": new_status})
    flash(f"“{script.name}” is now {new_status}.", "success")
    return redirect(url_for("lua_studio.edit", sid=script.id))


@bp.route("/<int:sid>/deploy", methods=["POST"])
@superadmin_required
def deploy(sid):
    """Dry-run by default; a real push needs config_write + confirm=yes."""
    script = LuaScript.query.get_or_404(sid)
    perms = getattr(current_user, "effective_permissions", set())
    want_real = request.form.get("confirm") == "yes"
    if want_real and Permission.CONFIG_WRITE not in perms:
        abort(403)
    appliance = (Appliance.query.get(script.appliance_id)
                 if script.appliance_id else None)
    dry = not want_real
    # Always lint before any push.
    lint = lua.lint(script.code, script.target)
    if not lint.get("ok"):
        return jsonify(ok=False, error="Lint failed — refusing to deploy.",
                       lint=lint), 400
    result = lua.deploy(script, script.code, appliance, dry_run=dry)
    if not dry and not result.get("error"):
        script.status = "deployed"
        script.deployed_at = datetime.utcnow()
        db.session.commit()
    log_action("lua.deploy", target=script.name,
               extra={"dry_run": dry, "appliance_id": script.appliance_id})
    return jsonify(ok=(not result.get("error")), dry_run=dry, result=result)


@bp.route("/<int:sid>/delete", methods=["POST"])
@superadmin_required
def delete(sid):
    script = LuaScript.query.get_or_404(sid)
    db.session.delete(script)
    db.session.commit()
    log_action("lua.delete", target=script.name)
    flash("Script deleted.", "success")
    return redirect(url_for("lua_studio.index"))
