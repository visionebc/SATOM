"""Administrator → Diagnostic Battery.

The administrator picks, per device ADOM, the commands Diagnose Log Collection
runs. Candidates come from the discovery catalogs of that product
(:mod:`app.services.diag_battery`): a walk of a real device's ``diagnose``
tree, stored per build. Every save is validated by
:func:`app.services.diag_battery.save_battery`, which refuses a destructive or
never-returning command whether it was ticked or typed by hand.

The page works on the ACTIVE ADOM (:func:`product_scope.session_product`). The
Global ADOM has no battery of its own: it shows a read-only summary of the
five device ADOMs.
"""
from __future__ import annotations

from collections import OrderedDict

from flask import (Blueprint, flash, jsonify, redirect, render_template,
                   request, url_for)
from flask_babel import gettext as _, ngettext
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Appliance, Permission
from ..services import diag_battery as svc
from ..services.audit import log_action

bp = Blueprint("diag_battery", __name__, url_prefix="/diag-battery")

ALL_BUILDS = "all"


def _adom() -> str:
    from ..services.product_scope import session_product
    return session_product() or "global"


def _product_name(key: str) -> str:
    from ..branding import get_product
    try:
        return get_product(key).get("name") or key
    except Exception:  # noqa: BLE001 - a label must never 500 the page
        return key


def _norm(cmd: str) -> str:
    return " ".join(str(cmd or "").split()).lower()


def _username() -> str:
    return getattr(current_user, "username", "") or ""


def _appliances(adom: str) -> list:
    """Visible appliances of this ADOM's kind (FortiWeb rows may have no kind)."""
    from ..models import visible_appliances
    rows = visible_appliances().order_by(Appliance.name).all()
    return [a for a in rows if (a.kind or "fortiweb") == adom]


def _nodes_for(adom: str, build: str):
    """(nodes, selected build key, catalog row or None)."""
    if build and build != ALL_BUILDS:
        cat = svc.catalog_for(adom, build)
        if cat is not None:
            return svc.current_verdicts(cat.node_map()), build, cat
    return svc.current_verdicts(svc.merged_nodes(adom)), ALL_BUILDS, None


def _row_state(n: dict) -> str:
    if n.get("blocked"):
        return "blocked"
    if n.get("runnable"):
        return "pick"
    if n.get("takes_args"):
        return "args"
    if n.get("branch"):
        return "branch"
    return "other"


def _tree(nodes: dict[str, dict], picked: set[str]) -> list[dict]:
    """Nodes grouped by top-level branch (``diagnose system`` ...)."""
    groups: "OrderedDict[str, dict]" = OrderedDict()
    for path in sorted(nodes, key=lambda p: p.split()):
        toks = path.split()
        if len(toks) < 2:
            continue  # the ``diagnose`` root itself
        top = " ".join(toks[:2])
        g = groups.setdefault(top, {"path": top, "desc": "", "rows": [],
                                    "pickable": 0, "picked": 0, "blocked": 0})
        n = nodes[path]
        state = _row_state(n)
        if path == top:
            g["desc"] = n.get("desc") or ""
            if state == "branch":
                continue  # the group header already names it
        row = {
            "path": path,
            "name": toks[-1],
            "depth": len(toks) - 2,
            "desc": n.get("desc") or "",
            "state": state,
            "blocked": n.get("blocked") or "",
            "arg_hint": n.get("arg_hint") or "",
            "note": n.get("note") or "",
            "checked": state == "pick" and _norm(path) in picked,
        }
        if state == "pick":
            g["pickable"] += 1
            g["picked"] += 1 if row["checked"] else 0
        elif state == "blocked":
            g["blocked"] += 1
        g["rows"].append(row)
    return [g for g in groups.values() if g["rows"]]


def _pickable(nodes: dict[str, dict]) -> set[str]:
    return {_norm(p) for p, n in nodes.items()
            if len(p.split()) >= 2 and _row_state(n) == "pick"}


def _own_progress(adom: str):
    p = svc.discovery_status()
    return p if p and p.get("product") == adom else None


def _summary() -> list[dict]:
    out = []
    for p in svc.PRODUCTS:
        cmds, meta = svc.get_battery(p)
        out.append({"key": p, "name": _product_name(p), "count": len(cmds),
                    "meta": meta, "builds": len(svc.catalogs(p))})
    return out


def _render(adom: str, *, error: str | None = None, picks: list[str] | None = None,
            extra: str | None = None, status: int = 200):
    ctx = {"adom": adom, "adom_name": _product_name(adom), "error": error,
           "status_url": url_for("diag_battery.discover_status"),
           "state_labels": {"running": _("running"), "done": _("done"),
                            "error": _("error")}}
    if adom not in svc.PRODUCTS:
        ctx["adom_summary"] = _summary()
        return render_template("diag_battery/index.html", **ctx), status

    commands, meta = svc.get_battery(adom)
    build = (request.values.get("build") or "").strip() or ALL_BUILDS
    nodes, build, catalog = _nodes_for(adom, build)
    pickable = _pickable(nodes)
    if picks is None:
        picked = {_norm(c) for c in commands if _norm(c) in pickable}
    else:
        picked = {_norm(c) for c in picks}
    if extra is None:
        extra = "\n".join(c for c in commands if _norm(c) not in pickable)
    cats = svc.catalogs(adom)
    ctx.update(
        commands=commands, meta=meta,
        default_count=len(svc.default_battery(adom)),
        build=build, catalog=catalog,
        builds=[(c.build, c.firmware or c.build) for c in cats],
        catalogs=[(c, c.counts()) for c in cats],
        groups=_tree(nodes, picked),
        node_count=len(nodes),
        extra=extra,
        appliances=_appliances(adom),
        # Discovery is one at a time fleet-wide; another ADOM's walk is not
        # this page's business (its device names stay in their ADOM).
        progress=_own_progress(adom),
    )
    return render_template("diag_battery/index.html", **ctx), status


@bp.route("/")
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    return _render(_adom())


def _compose(adom: str, picks: list[str], extra_lines: list[str]) -> list[str]:
    """Ticked + hand-typed commands, keeping the current battery's order for the
    commands it already holds and appending the new ones."""
    wanted: list[str] = []
    seen: set[str] = set()
    for c in list(picks) + list(extra_lines):
        c = " ".join(str(c or "").split())
        if c and _norm(c) not in seen:
            seen.add(_norm(c))
            wanted.append(c)
    current, _meta = svc.get_battery(adom)
    by_key = {_norm(c): c for c in wanted}
    ordered = [by_key[_norm(c)] for c in current if _norm(c) in by_key]
    kept = {_norm(c) for c in ordered}
    return ordered + [c for c in wanted if _norm(c) not in kept]


@bp.route("/save", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def save():
    adom = _adom()
    build = (request.form.get("build") or "").strip() or None
    if adom not in svc.PRODUCTS:
        flash(_("Batteries are chosen inside each device ADOM."), "warning")
        return redirect(url_for("diag_battery.index"))
    picks = request.form.getlist("pick")
    extra = request.form.get("extra") or ""
    commands = _compose(adom, picks, extra.splitlines())
    try:
        saved = svc.save_battery(adom, commands, _username())
    except svc.BatteryError as e:
        # 422 so Turbo renders the answer in place (it refuses a 200 to a form post).
        return _render(adom, error=str(e), picks=picks, extra=extra, status=422)
    log_action("diag_battery.save", target=adom,
               extra={"commands": len(saved), "list": saved})
    flash(ngettext("Diagnostic battery saved: %(num)d command.",
                   "Diagnostic battery saved: %(num)d commands.", len(saved)), "success")
    return redirect(url_for("diag_battery.index", build=build))


@bp.route("/reset", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def reset():
    adom = _adom()
    if adom not in svc.PRODUCTS:
        flash(_("Batteries are chosen inside each device ADOM."), "warning")
        return redirect(url_for("diag_battery.index"))
    svc.reset_battery(adom)
    log_action("diag_battery.reset", target=adom,
               extra={"commands": len(svc.default_battery(adom))})
    flash(_("Diagnostic battery reset to the product default."), "success")
    return redirect(url_for("diag_battery.index"))


@bp.route("/discover", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def discover():
    adom = _adom()
    if adom not in svc.PRODUCTS:
        return jsonify({"started": False,
                        "reason": _("Discovery runs inside a device ADOM.")}), 400
    raw = request.form.get("appliance_id") or (request.get_json(silent=True) or {}).get("appliance_id")
    try:
        aid = int(raw)
    except (TypeError, ValueError):
        return jsonify({"started": False, "reason": _("Choose an appliance.")}), 400
    appliance = next((a for a in _appliances(adom) if a.id == aid), None)
    if appliance is None:
        # Another ADOM's device, one in maintenance, or no such row: one answer.
        return jsonify({"started": False,
                        "reason": _("No such appliance in this ADOM.")}), 404
    result = svc.start_discovery(appliance, _username())
    if result.get("started"):
        log_action("diag_battery.discover_start", target=appliance.name,
                   extra={"product": adom, "appliance_id": appliance.id,
                          "build": svc.build_of(appliance.firmware)})
    return jsonify(result), (200 if result.get("started") else 409)


@bp.route("/discover/status")
@login_required
@require_permission(Permission.USER_MANAGE)
def discover_status():
    return jsonify(_own_progress(_adom()) or {"state": "idle"})
