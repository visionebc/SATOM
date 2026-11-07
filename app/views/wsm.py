"""Web Server Manager (Linux ADOM) -- /webserver/.

Pages are thin: they render the chrome and a JSON config, and the page's
script talks to ``POST /webserver/<server>/api/<op>``. Every call -- page,
API, job -- goes through ``services.wsm.execute``, which applies SATOM's
permissions, the credential's rules and the server's Allow changes before
anything leaves this node.
"""
from __future__ import annotations

import csv
import io
import json

from flask import (Blueprint, Response, abort, current_app, flash, jsonify, redirect,
                   render_template, request, url_for)
from flask_login import current_user, login_required

from ..extensions import db
from ..models_wsm import WsmCredential, WsmRun, WsmSchedule, WsmScript
from ..rbac import require_permission
from ..services import wsm as W
from ..services import wsm_cron as CR
from ..services import wsm_htaccess as HT
from ..services import wsm_transport as T

bp = Blueprint("wsm", __name__, url_prefix="/webserver")


@bp.before_request
def _module_on():
    """Switched off in every ADOM (Settings > ADOMs > Web Server Manager): the
    pages do not exist."""
    if not W.module_active():
        abort(404)

PAGES = ("health", "maintenance", "files", "sites", "certs", "security", "htaccess", "scripts", "cron", "packages",
         "services", "logs", "users", "ssh")


def _me() -> str:
    return getattr(current_user, "username", "")


def _json_error(exc, status):
    return jsonify({"ok": False, "error": str(exc)}), status


def _server_or_404(slug):
    """A server the signed-in user reaches (device scope), or 404 -- never
    403: a server outside the scope does not exist for them."""
    if not W.may_see_server(current_user, slug):
        abort(404)
    try:
        return W.server(slug)
    except W.WsmDenied:
        abort(404)


def _modules_for(slug):
    """The modules of this server the user's scope opens: all of them, or only
    the site pages when it reaches only some sites."""
    if W.site_scope(current_user, slug) is None:
        return W.MODULES
    return {k: v for k, v in W.MODULES.items() if k in W.SITE_PAGES}


def _creds_payload(c) -> list[dict]:
    out = []
    for r in W.visible_credentials(c.slug, current_user):
        out.append({"id": r.id, "name": r.name, "ssh_user": r.ssh_user, "auth_type": r.auth_type,
                    "escalation": r.escalation, "run_as": r.run_as,
                    "sudo_password": r.sudo_password, "store_secret": r.store_secret,
                    "shared": r.shared, "owner": r.owner, "state": r.state,
                    "modules": r.modules, "description": r.description,
                    "expires_at": r.expires_at.strftime("%Y-%m-%d") if r.expires_at else "",
                    "last_used_at": r.last_used_at.strftime("%Y-%m-%d %H:%M")
                    if r.last_used_at else "",
                    "usable": W.usable(r, current_user) and r.state == "active",
                    "manageable": W.manageable(r, current_user),
                    "has_secret": W.has(r, "secret") if r.store_secret else False,
                    "public_key": W.public_key(r) if r.auth_type in ("key", "agent") else ""})
    return out


def _chrome(c, page: str) -> dict:
    st = W.server_state(c)
    perms = {p: W.can(current_user, "webserver." + p)
             for p in ("view", "files", "sites", "system", "root", "credentials")}
    sites = W.site_scope(current_user, c.slug)
    jail = W.jail_roots(sites, c.slug) if sites is not None else []
    return {"server": c, "state": st, "page": page, "modules": _modules_for(c.slug),
            "perms": perms, "sites": sorted(sites) if sites is not None else None,
            "cfg": {"slug": c.slug, "name": c.name, "host": c.host, "page": page,
                    "api": url_for("wsm.api", slug=c.slug, op="OP"),
                    "job": url_for("wsm.job_start", slug=c.slug, op="OP"),
                    "jobs": url_for("wsm.job_state", job_id="JOB"),
                    "allow_writes": st["allow_writes"], "trusted": bool(st["host_key"]),
                    "credentials": _creds_payload(c), "perms": perms,
                    "base": url_for("wsm.server_home", slug=c.slug),
                    "jail": jail}}


# --------------------------------------------------------------------------- #
#  home and servers                                                            #
# --------------------------------------------------------------------------- #
@bp.route("/")
@login_required
@require_permission(W.VIEW_PERM)
def index():
    from ..services import server_health as SH
    rows = []
    for c in W.visible_servers(current_user):
        st = W.server_state(c)
        creds = W.visible_credentials(c.slug, current_user)
        rows.append({"c": c, "state": st, "creds": len(creds),
                     "mine": sum(1 for r in creds if r.owner == _me()),
                     "health": SH.last(c.slug).get("state") or ""})
    return render_template("wsm/index.html", servers=rows, modules=W.MODULES,
                           can_add=W.can(current_user, W.SYSTEM_PERM))


@bp.route("/servers", methods=["POST"])
@login_required
@require_permission(W.SYSTEM_PERM)
def server_create():
    try:
        c = W.create_server(request.form, _me())
    except Exception as exc:  # noqa: BLE001 -- the form says what is wrong
        flash(str(exc), "danger")
        return redirect(url_for("wsm.index"))
    from ..services.audit import log_action
    log_action("wsm.server.create", target=c.slug, extra={"host": c.host, "port": c.port})
    from ..services import server_health as SH
    SH.ensure_scheduled()
    flash("Server %s added. Next: trust its host key, then add your SSH account." % c.name,
          "success")
    return redirect(url_for("wsm.server_home", slug=c.slug))


@bp.route("/<slug>/")
@login_required
@require_permission(W.VIEW_PERM)
def server_home(slug):
    c = _server_or_404(slug)
    W.ensure_agent_credential(c, _me())
    return render_template("wsm/server.html", **_chrome(c, "home"))


@bp.route("/<slug>/settings", methods=["POST"])
@login_required
@require_permission(W.SYSTEM_PERM)
def server_settings(slug):
    c = _server_or_404(slug)
    try:
        dropped = W.update_server(c, request.form, _me())
    except Exception as exc:  # noqa: BLE001
        flash(str(exc), "danger")
        return redirect(url_for("wsm.server_home", slug=slug))
    from ..services.audit import log_action
    log_action("wsm.server.update", target=slug,
               extra={"host": c.host, "port": c.port,
                      "allow_writes": bool(request.form.get("allow_writes"))})
    flash("Saved." + (" The address changed: trust the host key again." if dropped else ""),
          "success")
    return redirect(url_for("wsm.server_home", slug=slug))


@bp.route("/<slug>/hostkey", methods=["POST"])
@login_required
@require_permission(W.SYSTEM_PERM)
def server_hostkey(slug):
    from ..services import studio_connections as SC
    from ..services.studio_server import fingerprint
    c = _server_or_404(slug)
    try:
        if request.form.get("forget"):
            SC.forget_host_key(c)
            msg = "Host key forgotten: nothing reaches this server until a key is trusted."
        else:
            key = SC.trust_host_key(c)
            msg = "Trusted host key %s." % fingerprint(key)
    except Exception as exc:  # noqa: BLE001
        flash(str(exc), "danger")
        return redirect(url_for("wsm.server_home", slug=slug))
    from ..services.audit import log_action
    log_action("wsm.server.hostkey", target=slug, extra={"forget": bool(request.form.get("forget"))})
    flash(msg, "success")
    return redirect(url_for("wsm.server_home", slug=slug))


# --------------------------------------------------------------------------- #
#  credentials                                                                 #
# --------------------------------------------------------------------------- #
@bp.route("/<slug>/credentials", methods=["POST"])
@bp.route("/<slug>/credentials/<int:cid>", methods=["POST"])
@login_required
@require_permission(W.VIEW_PERM)
def credential_save(slug, cid=None):
    c = _server_or_404(slug)
    cred = None
    if cid:
        cred = db.session.get(WsmCredential, cid)
        if cred is None or cred.connection_slug != slug or not W.manageable(cred, current_user):
            abort(404)
    data = request.get_json(silent=True) or request.form
    try:
        cred = W.save_credential(cred, c.slug, data, current_user)
    except W.WsmDenied as exc:
        return _json_error(exc, 400)
    return jsonify({"ok": True, "id": cred.id, "public_key": W.public_key(cred),
                    "credentials": _creds_payload(c)})


@bp.route("/<slug>/credentials/<int:cid>/status", methods=["POST"])
@login_required
@require_permission(W.VIEW_PERM)
def credential_status(slug, cid):
    c = _server_or_404(slug)
    cred = db.session.get(WsmCredential, cid)
    if cred is None or cred.connection_slug != slug or not W.manageable(cred, current_user):
        abort(404)
    data = request.get_json(silent=True) or {}
    try:
        if data.get("delete"):
            W.delete_credential(cred)
        else:
            W.set_status(cred, data.get("status") or "", current_user)
    except W.WsmDenied as exc:
        return _json_error(exc, 400)
    return jsonify({"ok": True, "credentials": _creds_payload(c)})


@bp.route("/<slug>/credentials/<int:cid>/check", methods=["POST"])
@login_required
@require_permission(W.VIEW_PERM)
def credential_check(slug, cid):
    """Who the credential is on the server, and whether it can become root."""
    data = request.get_json(silent=True) or {}
    secrets = data.get("secrets") or {}
    out = {"ok": True}
    try:
        r = W.execute(slug, cid, "whoami", {}, user=current_user, run_as="self",
                      provided=secrets)
        out["self"] = r["result"]
        out["identity"] = r["who"]
    except W.NeedSecret as exc:
        return jsonify({"ok": False, "need": exc.fields, "why": exc.why,
                        "credential": exc.cred.name, "ssh_user": exc.cred.ssh_user}), 401
    except (W.WsmDenied, T.WsmError) as exc:
        return _json_error(exc, 502 if isinstance(exc, T.WsmError) else 403)
    cred = db.session.get(WsmCredential, cid)
    if cred.can_escalate and W.can(current_user, W.ROOT_PERM):
        try:
            r = W.execute(slug, cid, "whoami", {}, user=current_user, run_as="root",
                          provided=secrets)
            out["root"] = {"ok": r["who"].get("uid") == 0, "who": r["who"]}
        except W.NeedSecret as exc:
            out["root"] = {"ok": False, "need": exc.fields, "why": exc.why}
        except (W.WsmDenied, T.WsmError) as exc:
            out["root"] = {"ok": False, "error": str(exc)}
    else:
        out["root"] = {"ok": False, "error": "this credential is not set to use sudo"
                       if not cred.can_escalate else "your profile cannot run as root"}
    return jsonify(out)


# --------------------------------------------------------------------------- #
#  module pages                                                                #
# --------------------------------------------------------------------------- #
@bp.route("/<slug>/<page>")
@login_required
@require_permission(W.VIEW_PERM)
def module(slug, page):
    if page not in PAGES:
        abort(404)
    c = _server_or_404(slug)
    if page not in _modules_for(slug):
        abort(404)
    ctx = _chrome(c, page)
    if page == "htaccess":
        ctx["cfg"]["rules"] = HT.RULE_TYPES
        ctx["cfg"]["templates"] = {k: {"label": v[0], "text": v[1]} for k, v in HT.TEMPLATES.items()}
    if page == "scripts":
        ctx["cfg"]["scripts"] = [_script_dict(s) for s in _scripts()]
        ctx["cfg"]["runs"] = [_run_dict(r) for r in WsmRun.query.filter_by(connection_slug=slug)
                              .order_by(WsmRun.id.desc()).limit(50)]
    if page == "cron":
        ctx["cfg"]["presets"] = {k: v[1] for k, v in CR.PRESETS.items()}
        ctx["cfg"]["schedules"] = [_schedule_dict(s) for s in WsmSchedule.query.filter_by(
            connection_slug=slug).order_by(WsmSchedule.name)]
        ctx["cfg"]["scripts"] = [_script_dict(s) for s in _scripts()]
    if page == "health":
        ctx["cfg"]["health"] = _health_payload(c)
    if page == "maintenance":
        ctx["cfg"]["maint"] = _maint_payload(c)
    if page == "certs":
        try:
            from ..services import cert_providers as CP
            ctx["cfg"]["providers"] = [p["key"] for p in CP.providers()]
        except Exception:  # noqa: BLE001
            ctx["cfg"]["providers"] = []
        ctx["cfg"]["can_sign"] = current_user.can("user_manage")
    return render_template("wsm/%s.html" % page, **ctx)


# --------------------------------------------------------------------------- #
#  health (services.server_health): stored readings, read on demand            #
# --------------------------------------------------------------------------- #
def _health_payload(c) -> dict:
    from ..services import server_health as SH
    cfg = SH.conf(c.slug)
    ch = SH.channel(c, cfg)
    rec = SH.last(c.slug)
    return {"conf": dict(cfg, ignore_units="\n".join(cfg["ignore_units"])),
            "channel": {"via": ch["via"], "credential": ch["credential"].name
                        if ch["credential"] else "", "why": ch["why"]},
            "agent_key": W.server_state(c)["agent_key"],
            "eligible": [{"id": r.id, "name": r.name, "ssh_user": r.ssh_user}
                         for r in W.service_credentials(c.slug)],
            "last": rec, "can_configure": W.can(current_user, W.SYSTEM_PERM),
            "urls": {"collect": url_for("wsm.health_collect", slug=c.slug),
                     "settings": url_for("wsm.health_settings", slug=c.slug),
                     "series": url_for("wsm.health_series", slug=c.slug)}}


def _health_whole_server(slug):
    """Health is the whole machine: a profile that reaches only some sites of
    the server does not read it (the chassis rule of the device scope)."""
    _server_or_404(slug)
    if W.site_scope(current_user, slug) is not None:
        abort(404)


@bp.route("/<slug>/health/collect", methods=["POST"])
@login_required
@require_permission(W.VIEW_PERM)
def health_collect(slug):
    """Read the server NOW (an explicit action that goes to the server; audited
    like any other reading, and it rings the bell like the scheduler would)."""
    from ..services import server_health as SH
    _health_whole_server(slug)
    rec = SH.collect(W.server(slug), by=_me() or "user")
    return jsonify({"ok": rec["ok"], "error": rec["error"], "health": _health_payload(
        W.server(slug))}), (200 if rec["ok"] else 502)


@bp.route("/<slug>/health/settings", methods=["POST"])
@login_required
@require_permission(W.SYSTEM_PERM)
def health_settings(slug):
    from ..services import server_health as SH
    _health_whole_server(slug)
    try:
        SH.save_conf(slug, request.get_json(silent=True) or {}, _me())
    except ValueError as exc:
        return _json_error(exc, 400)
    return jsonify({"ok": True, "health": _health_payload(W.server(slug))})


@bp.route("/<slug>/health/series")
@login_required
@require_permission(W.VIEW_PERM)
def health_series(slug):
    from ..services import server_health as SH
    _health_whole_server(slug)
    return jsonify(SH.history(slug, request.args.get("range", "24h")))


# --------------------------------------------------------------------------- #
#  maintenance with pool drain (services.server_maint)                         #
# --------------------------------------------------------------------------- #
def _maint_payload(c) -> dict:
    from ..services import server_maint as SM
    found = SM.last_found(c.slug)
    return {"links": SM.links(c.slug), "pending": SM.pending(c.slug),
            "found": {"at": found.get("at") or "", "rows": found.get("found") or [],
                      "errors": found.get("errors") or [],
                      "addresses": found.get("addresses") or []},
            "drain": {k: list(v[1]) for k, v in SM.DRAIN.items()},
            "scripts": [{"id": s.id, "name": s.name} for s in _scripts()],
            "can_apply": W.can(current_user, SM.APPLY_PERM),
            "can_link": W.can(current_user, W.SYSTEM_PERM),
            "urls": {"discover": url_for("wsm.maint_discover", slug=c.slug),
                     "links": url_for("wsm.maint_links", slug=c.slug),
                     "run": url_for("wsm.maint_run", slug=c.slug),
                     "return": url_for("wsm.maint_return", slug=c.slug),
                     "state": url_for("wsm.maint_state", slug=c.slug)}}


@bp.route("/<slug>/maintenance/state")
@login_required
@require_permission(W.VIEW_PERM)
def maint_state(slug):
    _health_whole_server(slug)
    return jsonify({"ok": True, "maint": _maint_payload(W.server(slug))})


@bp.route("/<slug>/maintenance/discover", methods=["POST"])
@login_required
@require_permission(W.SYSTEM_PERM)
def maint_discover(slug):
    from ..services import server_maint as SM
    _health_whole_server(slug)
    try:
        out = SM.start_discover(current_app._get_current_object(), slug, user=current_user)
    except SM.MaintError as exc:
        return _json_error(exc, 409)
    return jsonify(dict(out, ok=True))


@bp.route("/<slug>/maintenance/links", methods=["POST"])
@login_required
@require_permission(W.SYSTEM_PERM)
def maint_links(slug):
    from ..services import server_maint as SM
    _health_whole_server(slug)
    keys = (request.get_json(silent=True) or {}).get("keys") or []
    if not isinstance(keys, list):
        return _json_error("bad request", 400)
    SM.save_links(slug, keys, _me())
    return jsonify({"ok": True, "maint": _maint_payload(W.server(slug))})


@bp.route("/<slug>/maintenance/run", methods=["POST"])
@login_required
@require_permission(W.VIEW_PERM)
def maint_run(slug):
    from ..services import server_maint as SM
    _health_whole_server(slug)
    data = request.get_json(silent=True) or {}
    secrets = data.get("secrets") or {}
    if not isinstance(secrets, dict):
        return _json_error("bad request", 400)
    try:
        out = SM.start(current_app._get_current_object(), slug, data, user=current_user,
                       provided=secrets)
    except W.NeedSecret as exc:
        return jsonify({"ok": False, "need": exc.fields, "why": exc.why,
                        "credential": exc.cred.name, "ssh_user": exc.cred.ssh_user}), 401
    except (SM.MaintError, W.WsmDenied) as exc:
        return _json_error(exc, 409)
    return jsonify(dict(out, ok=True))


@bp.route("/<slug>/maintenance/return", methods=["POST"])
@login_required
@require_permission(W.VIEW_PERM)
def maint_return(slug):
    from ..services import server_maint as SM
    _health_whole_server(slug)
    try:
        out = SM.start_return(current_app._get_current_object(), slug, user=current_user)
    except SM.MaintError as exc:
        return _json_error(exc, 409)
    return jsonify(dict(out, ok=True))


# --------------------------------------------------------------------------- #
#  the API every page uses                                                     #
# --------------------------------------------------------------------------- #
def _call(slug, op, data, *, as_job=False, title="", run_kind="", run_meta=None,
          script_id=None):
    cred = data.get("cred")
    run_as = data.get("run_as") or ""
    secrets = data.get("secrets") or {}
    args = data.get("args") or {}
    if not isinstance(args, dict) or not isinstance(secrets, dict):
        return _json_error("bad request", 400)
    try:
        if as_job:
            out = W.start_job(current_app._get_current_object(), slug, cred, op, args,
                              user=current_user, run_as=run_as, provided=secrets,
                              title=title or "%s on %s" % (op, slug), run_kind=run_kind,
                              run_meta=run_meta, script_id=script_id)
            return jsonify(dict(out, ok=True))
        r = W.execute(slug, cred, op, args, user=current_user, run_as=run_as, provided=secrets)
    except W.NeedSecret as exc:
        return jsonify({"ok": False, "need": exc.fields, "why": exc.why,
                        "credential": exc.cred.name, "ssh_user": exc.cred.ssh_user}), 401
    except W.WsmDenied as exc:
        return _json_error(exc, 403)
    except T.WsmError as exc:
        return jsonify({"ok": False, "error": str(exc), "code": exc.code,
                        "remote_error": exc.remote_error}), 502
    return jsonify({"ok": True, "result": r["result"], "who": r["who"], "sudo": r["sudo"],
                    "ms": r["ms"], "credential": r["credential"]})


@bp.route("/<slug>/api/<op>", methods=["POST"])
@login_required
@require_permission(W.VIEW_PERM)
def api(slug, op):
    _server_or_404(slug)
    return _call(slug, op, request.get_json(silent=True) or {})


@bp.route("/<slug>/job/<op>", methods=["POST"])
@login_required
@require_permission(W.VIEW_PERM)
def job_start(slug, op):
    _server_or_404(slug)
    data = request.get_json(silent=True) or {}
    kind = {"pkg.apply": "package", "script.run": "script", "acme.issue": "certbot",
            "acme.renew": "certbot"}.get(op, "")
    args = data.get("args") or {}
    title = data.get("title") or "%s on %s" % (op, slug)
    meta = {k: v for k, v in args.items() if k in ("action", "names", "interpreter", "cwd",
                                                   "args", "domains")}
    return _call(slug, op, data, as_job=True, title=str(title)[:300], run_kind=kind,
                 run_meta=meta)


@bp.route("/job/<job_id>")
@login_required
@require_permission(W.VIEW_PERM)
def job_state(job_id):
    from ..services import jobs
    j = jobs.get_job(job_id)
    if not j or not str(j.get("type", "")).startswith("wsm_") or (
            j.get("by") != _me() and not current_user.can("user_manage")):
        abort(404)
    res = j.get("result")
    return jsonify({"status": j.get("status"), "percent": j.get("percent"),
                    "message": j.get("message"), "error": j.get("error"),
                    "result": res, "steps": ((j.get("meta") or {}).get("steps") or [])[-60:]})


# --------------------------------------------------------------------------- #
#  .htaccess and cron helpers (pure, no server)                               #
# --------------------------------------------------------------------------- #
@bp.route("/htaccess/render", methods=["POST"])
@login_required
@require_permission(W.VIEW_PERM)
def htaccess_render():
    data = request.get_json(silent=True) or {}
    try:
        text = HT.render(data.get("rules") or [], data.get("existing") or "")
    except HT.RuleError as exc:
        return _json_error(exc, 400)
    return jsonify({"ok": True, "text": text, "nginx": HT.to_nginx(text)})


@bp.route("/htaccess/convert", methods=["POST"])
@login_required
@require_permission(W.VIEW_PERM)
def htaccess_convert():
    data = request.get_json(silent=True) or {}
    return jsonify(dict(HT.to_nginx(str(data.get("text") or "")), ok=True))


@bp.route("/<slug>/cron/load", methods=["POST"])
@login_required
@require_permission(W.VIEW_PERM)
def cron_load(slug):
    data = request.get_json(silent=True) or {}
    resp = _call(slug, "cron.get", data)
    body = resp[0].get_json() if isinstance(resp, tuple) else resp.get_json()
    if body.get("ok"):
        body["rows"] = CR.parse(body["result"].get("content") or "")
    return (jsonify(body), resp[1]) if isinstance(resp, tuple) else jsonify(body)


@bp.route("/<slug>/cron/save", methods=["POST"])
@login_required
@require_permission(W.VIEW_PERM)
def cron_save(slug):
    data = request.get_json(silent=True) or {}
    try:
        text = CR.render(data.get("rows") or [])
    except CR.CronFormatError as exc:
        return _json_error(exc, 400)
    data["args"] = {"user": (data.get("args") or {}).get("user") or "",
                    "content": text, "base_sha256": (data.get("args") or {}).get("base_sha256")}
    return _call(slug, "cron.put", data)


@bp.route("/cron/preset", methods=["POST"])
@login_required
@require_permission(W.VIEW_PERM)
def cron_preset():
    d = request.get_json(silent=True) or {}
    try:
        expr = CR.preset(d.get("kind") or "", hour=int(d.get("hour") or 0),
                         minute=int(d.get("minute") or 0), dow=int(d.get("dow") or 0),
                         dom=int(d.get("dom") or 1))
        if d.get("kind") == "custom":
            expr = CR.validate_schedule(d.get("expr") or "")
    except (CR.CronFormatError, ValueError) as exc:
        return _json_error(exc, 400)
    return jsonify({"ok": True, "expr": expr, "human": CR.describe(expr)})


# --------------------------------------------------------------------------- #
#  scripts library and SATOM schedules                                         #
# --------------------------------------------------------------------------- #
def _scripts():
    q = WsmScript.query.order_by(WsmScript.name)
    return [s for s in q if s.owner == _me() or s.shared or current_user.can("user_manage")]


def _script_dict(s: WsmScript) -> dict:
    return {"id": s.id, "name": s.name, "description": s.description,
            "interpreter": s.interpreter, "content": s.content, "args": s.args, "cwd": s.cwd,
            "timeout": s.timeout, "owner": s.owner, "shared": s.shared,
            "mine": s.owner == _me()}


def _run_dict(r: WsmRun) -> dict:
    return {"id": r.id, "kind": r.kind, "title": r.title, "by": r.by, "status": r.status,
            "exit_code": r.exit_code, "ssh_user": r.ssh_user,
            "effective_user": r.effective_user, "sudo": r.sudo,
            "started": r.started_at.strftime("%Y-%m-%d %H:%M:%S") if r.started_at else "",
            "finished": r.finished_at.strftime("%H:%M:%S") if r.finished_at else "",
            "meta": r.meta}


def _schedule_dict(s: WsmSchedule) -> dict:
    cred = db.session.get(WsmCredential, s.credential_id) if s.credential_id else None
    script = db.session.get(WsmScript, s.script_id) if s.script_id else None
    return {"id": s.id, "name": s.name, "cron": s.cron, "human": CR.describe(s.cron),
            "enabled": s.enabled, "state": s.state, "detail": s.state_detail,
            "run_as": s.run_as, "credential_id": s.credential_id,
            "credential": cred.name if cred else "(deleted)",
            "script_id": s.script_id, "script": script.name if script else "(deleted)",
            "last_run": s.last_run_at.strftime("%Y-%m-%d %H:%M") if s.last_run_at else "",
            "last_exit": s.last_exit, "problem": W.schedule_problem(s)}


@bp.route("/scripts", methods=["POST"])
@bp.route("/scripts/<int:sid>", methods=["POST"])
@login_required
@require_permission(W.SYSTEM_PERM)
def script_save(sid=None):
    d = request.get_json(silent=True) or {}
    s = db.session.get(WsmScript, sid) if sid else None
    if sid and (s is None or (s.owner != _me() and not current_user.can("user_manage"))):
        abort(404)
    if d.get("delete") and s is not None:
        if WsmSchedule.query.filter_by(script_id=s.id).first():
            return _json_error("a scheduled job uses this script: delete the schedule first", 400)
        db.session.delete(s)
        db.session.commit()
        return jsonify({"ok": True})
    name = (d.get("name") or "").strip()[:120]
    interp = d.get("interpreter") or "bash"
    content = d.get("content") or ""
    if not name or interp not in WsmScript.INTERPRETERS or not content.strip():
        return _json_error("a name, an interpreter and the script text are required", 400)
    if len(content) > 1024 * 1024:
        return _json_error("scripts up to 1 MiB", 400)
    args = [a for a in (d.get("args") or []) if isinstance(a, str)][:50]
    if s is None:
        s = WsmScript(owner=_me())
        db.session.add(s)
    s.name, s.interpreter, s.content = name, interp, content
    s.description = (d.get("description") or "")[:2000]
    s.args_json, s.cwd = json.dumps(args), (d.get("cwd") or "")[:1024]
    s.timeout = max(1, min(int(d.get("timeout") or 300), 3600))
    s.shared = bool(d.get("shared"))
    from datetime import datetime
    s.updated_at = datetime.utcnow()
    db.session.commit()
    from ..services.audit import log_action
    log_action("wsm.script.save", target=name, extra={"id": s.id, "interpreter": interp})
    return jsonify({"ok": True, "script": _script_dict(s),
                    "scripts": [_script_dict(x) for x in _scripts()]})


@bp.route("/<slug>/runs/<int:rid>")
@login_required
@require_permission(W.VIEW_PERM)
def run_detail(slug, rid):
    r = db.session.get(WsmRun, rid)
    if r is None or r.connection_slug != slug or (r.by not in (_me(), "scheduler")
                                                  and not current_user.can("user_manage")):
        abort(404)
    return jsonify(dict(_run_dict(r), stdout=r.stdout, stderr=r.stderr))


@bp.route("/<slug>/schedules", methods=["POST"])
@bp.route("/<slug>/schedules/<int:sch_id>", methods=["POST"])
@login_required
@require_permission(W.SYSTEM_PERM)
def schedule_save(slug, sch_id=None):
    _server_or_404(slug)
    d = request.get_json(silent=True) or {}
    s = db.session.get(WsmSchedule, sch_id) if sch_id else None
    if sch_id and (s is None or s.connection_slug != slug):
        abort(404)
    if s is not None and d.get("delete"):
        db.session.delete(s)
        db.session.commit()
        return jsonify({"ok": True})
    if s is not None and "enabled" in d and len(d) == 1:
        s.enabled = bool(d["enabled"])
        db.session.commit()
        return jsonify({"ok": True, "schedule": _schedule_dict(s)})
    name = (d.get("name") or "").strip()[:120]
    expr = (d.get("cron") or "").strip()
    bad = W.cron_ok(expr)
    if not name or bad:
        return _json_error(bad or "a name is required", 400)
    cred = db.session.get(WsmCredential, int(d.get("credential_id") or 0))
    if cred is None or cred.connection_slug != slug or not W.usable(cred, current_user):
        return _json_error("pick a credential of this server you may use", 400)
    script = db.session.get(WsmScript, int(d.get("script_id") or 0))
    if script is None or not (script.owner == _me() or script.shared):
        return _json_error("pick a script of the library", 400)
    run_as = d.get("run_as") or "self"
    if run_as not in ("self", "root"):
        run_as = "self"
    if run_as == "root" and not W.can(current_user, W.ROOT_PERM):
        return _json_error("your profile cannot run as root", 403)
    if s is None:
        s = WsmSchedule(connection_slug=slug, created_by=_me())
        db.session.add(s)
    s.name, s.cron, s.credential_id, s.script_id, s.run_as = name, expr, cred.id, script.id, run_as
    s.enabled = bool(d.get("enabled", True))
    db.session.flush()
    why = W.schedule_problem(s)
    s.state, s.state_detail = ("pending_auth", why) if why else (
        s.state if s.state != "pending_auth" else "never", "")
    db.session.commit()
    W.ensure_scheduled(_me())
    from ..services.audit import log_action
    log_action("wsm.schedule.save", target="%s/%s" % (slug, name),
               extra={"cron": expr, "credential": cred.name, "script": script.name,
                      "run_as": run_as})
    return jsonify({"ok": True, "schedule": _schedule_dict(s), "warning": why})


# --------------------------------------------------------------------------- #
#  certificates signed by the internal CA                                      #
# --------------------------------------------------------------------------- #
@bp.route("/<slug>/certs/sign", methods=["POST"])
@login_required
@require_permission(W.VIEW_PERM)
def cert_sign(slug):
    """Make a request on the server (the key never leaves it), have a
    Certificate Manager provider sign it, install the certificate there."""
    if not current_user.can("user_manage"):
        return _json_error("signing with the Certificate Manager needs the user_manage "
                           "permission", 403)
    d = request.get_json(silent=True) or {}
    args = d.get("args") or {}
    csr_resp = _call(slug, "cert.csr", dict(d, args={
        "name": args.get("name"), "common_name": args.get("common_name"),
        "sans": args.get("sans") or [], "key_type": args.get("key_type") or "ec256"}))
    body = csr_resp[0].get_json() if isinstance(csr_resp, tuple) else csr_resp.get_json()
    if not body.get("ok"):
        return csr_resp
    from ..services import cert_manager as CM
    from ..services.audit import log_action
    try:
        cert_pem, _log = CM.sign_csr("server", body["result"]["csr"], args.get("provider") or "")
    except CM.CertManagerError as exc:
        log_action("wsm.cert.sign", target="%s %s" % (slug, args.get("name")),
                   extra={"ok": False, "error": str(exc)[:300]})
        return _json_error("the provider did not sign: %s" % str(exc)[:500], 502)
    log_action("wsm.cert.sign", target="%s %s" % (slug, args.get("name")),
               extra={"ok": True, "provider": args.get("provider") or ""})
    return _call(slug, "cert.install", dict(d, args={"name": body["result"]["name"],
                                                       "certificate": cert_pem}))


def _cell(v):
    """A CSV cell a spreadsheet will not run as a formula."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


# --------------------------------------------------------------------------- #
#  operations log                                                              #
# --------------------------------------------------------------------------- #
@bp.route("/audit")
@login_required
@require_permission(W.VIEW_PERM)
def audit():
    f = {k: request.args.get(k, "") for k in ("slug", "user", "op", "ok")}
    days = int(request.args.get("days") or 30)
    mine_only = not current_user.can("audit.view")
    if mine_only:
        f["user"] = _me()
    rows = W.audit_rows(slug=f["slug"], user=f["user"], op=f["op"], ok=f["ok"],
                        since_days=days, limit=1000)
    if request.args.get("format") == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["at (UTC)", "SATOM user", "SSH user", "effective user", "sudo", "server",
                    "host", "module", "operation", "target", "result", "error", "detail",
                    "exit code", "credential", "auth", "session", "ms", "client ip"])
        for r in rows:
            w.writerow([_cell(v) for v in [r.at.isoformat(timespec="seconds"), r.app_user, r.ssh_user,
                        r.effective_user, "yes" if r.sudo else "no", r.connection_slug, r.host,
                        r.module, r.op, r.target, "ok" if r.ok else "failed", r.error,
                        r.detail, "" if r.exit_code is None else r.exit_code,
                        r.credential_name, r.auth_mode, r.session_id, r.ms or "", r.ip]])
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": "attachment; filename=wsm-operations.csv"})
    return render_template("wsm/audit.html", rows=rows, f=f, days=days,
                           servers=W.servers(), mine_only=mine_only)
