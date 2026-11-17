"""Monitoring › Service checks — /observability/monitoring/checks/ (2026-11-17).

"A more specific monitoring": a web page with its screenshot and certificate,
the health of a service — SSL VPN, OpenVPN, IPsec, WireGuard, HTTP/HTTPS and
other ports and protocols — proven at the protocol level, because "the port
can be open while the service is not" (operator). The work is in
``services.service_checks`` / ``service_probes`` / ``web_screenshot``.

Gates:

* reading the page, its feed, a history or a screenshot: ``view`` (and the
  area's ``observability.access``, enforced by path);
* creating, editing, deleting, muting, running: ``config_write`` AND the
  free-target key ``monitoring.probe_free`` (or user management), the same
  rule as the certificate inspector and the tracer — every check dials a host
  of the operator's choosing from inside the management network. Each write is
  in the audit log, refusals included.

Rows are scoped by ADOM (the ADOM a check was created in).
"""
from __future__ import annotations

import json

from flask import Blueprint, abort, jsonify, render_template, request, send_file
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Permission
from ..services import service_checks as sc
from ..services import service_probes as sp
from ..services.audit import log_action

bp = Blueprint("service_checks", __name__, url_prefix="/observability/monitoring/checks")


def _may_write() -> bool:
    from ..services.net_guard import FREE_PERMISSION
    return bool(current_user.can("config_write")
                and (current_user.can(FREE_PERMISSION) or current_user.can("user_manage")))


def _require_write():
    if not _may_write():
        log_action("service_check.refused", target=request.path,
                   extra={"reason": "needs config_write + monitoring.probe_free"})
        abort(403)


def _form() -> dict:
    data = request.get_json(silent=True)
    if data is None:
        data = request.form.to_dict()
        raw = data.pop("target_json", "") or "{}"
        try:
            data["target"] = json.loads(raw)
        except ValueError:
            data["target"] = {}
    return data if isinstance(data, dict) else {}


def _row(c) -> dict:
    d = c.as_dict()
    last = sc.latest(c)
    d["latest"] = last.as_dict() if last else None
    d["uptime_24h"] = sc.uptime(c, 24)
    d["kind_label"] = sp.KIND_LABEL.get(c.kind, c.kind)
    return d


@bp.route("/")
@login_required
@require_permission(Permission.VIEW)
def index():
    from ..services import web_screenshot
    fgts = []
    try:
        from ..models import visible_appliances
        fgts = [{"id": a.id, "name": a.name} for a in visible_appliances()
                if a.kind == "fortigate"]
    except Exception:  # noqa: BLE001
        fgts = []
    return render_template(
        "monitoring/checks.html",
        groups=sc.GROUPS, kinds=sp.KINDS, kind_label=sp.KIND_LABEL,
        cert_kinds=sorted(sp.CERT_KINDS), web_kinds=sorted(sc.WEB_KINDS),
        intervals=sc.INTERVALS, may_write=_may_write(),
        shots=web_screenshot.available(), fortigates=fgts,
        secret_placeholder=sc.SECRET_PLACEHOLDER)


@bp.route("/data")
@login_required
@require_permission(Permission.VIEW)
def data():
    rows = [_row(c) for c in sc.visible_checks()]
    return jsonify({"checks": rows, "overview": sc.overview()})


@bp.route("/<int:cid>/history")
@login_required
@require_permission(Permission.VIEW)
def history(cid: int):
    c = sc.visible_check_or_404(cid)
    hours = request.args.get("hours", 24, type=int) or 24
    return jsonify({"check": _row(c), "results": sc.history(c, hours=hours)})


@bp.route("/<int:cid>/screenshot")
@bp.route("/<int:cid>/screenshot/<name>")
@login_required
@require_permission(Permission.VIEW)
def screenshot(cid: int, name: str | None = None):
    c = sc.visible_check_or_404(cid)
    path = sc.shot_path(c.id, name or c.last_shot)
    if not path:
        abort(404)
    resp = send_file(path, mimetype="image/png", max_age=0)
    resp.headers["Content-Security-Policy"] = "default-src 'none'"
    return resp


@bp.route("/", methods=["POST"])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def create():
    _require_write()
    from ..services.product_scope import session_product
    form = _form()
    try:
        c = sc.create(form, product=session_product() or "global", author=current_user.username)
    except sc.CheckError as exc:
        log_action("service_check.create_refused", target=str(form.get("name") or ""),
                   extra={"kind": form.get("kind"), "error": str(exc)})
        return jsonify({"ok": False, "error": str(exc)}), 400
    log_action("service_check.create", target=c.name,
               extra={"id": c.id, "kind": c.kind, "target": c.target, "product": c.product})
    sc.run_one(c, force_shot=True)
    return jsonify({"ok": True, "check": _row(c)})


@bp.route("/<int:cid>", methods=["POST"])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def update(cid: int):
    _require_write()
    c = sc.visible_check_or_404(cid)
    form = _form()
    try:
        sc.update(c, form)
    except sc.CheckError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    log_action("service_check.update", target=c.name,
               extra={"id": c.id, "kind": c.kind, "target": c.target})
    return jsonify({"ok": True, "check": _row(c)})


@bp.route("/<int:cid>/run", methods=["POST"])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def run_now(cid: int):
    _require_write()
    c = sc.visible_check_or_404(cid)
    r = sc.run_one(c, force_shot=True)
    log_action("service_check.run", target=c.name, extra={"id": c.id, "status": r.status})
    return jsonify({"ok": True, "result": r.as_dict(), "check": _row(c)})


@bp.route("/<int:cid>/toggle", methods=["POST"])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def toggle(cid: int):
    _require_write()
    c = sc.visible_check_or_404(cid)
    field = (request.get_json(silent=True) or request.form).get("field", "enabled")
    if field not in ("enabled", "muted"):
        abort(400)
    setattr(c, field, not getattr(c, field))
    from ..extensions import db
    db.session.commit()
    log_action("service_check.%s" % field, target=c.name,
               extra={"id": c.id, field: bool(getattr(c, field))})
    return jsonify({"ok": True, "check": _row(c)})


@bp.route("/<int:cid>/delete", methods=["POST"])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def delete(cid: int):
    _require_write()
    c = sc.visible_check_or_404(cid)
    name, kind = c.name, c.kind
    sc.delete(c)
    log_action("service_check.delete", target=name, extra={"id": cid, "kind": kind})
    return jsonify({"ok": True})


@bp.route("/wireguard-keypair", methods=["POST"])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def wireguard_keypair():
    """A fresh key pair for a WireGuard check's monitoring peer. Generated
    here, returned once; the private half is stored only when the check is
    saved (as a secret)."""
    _require_write()
    priv, pub = sp.wireguard_keypair()
    log_action("service_check.wireguard_keypair", target=pub)
    return jsonify({"ok": True, "private_key": priv, "public_key": pub})
