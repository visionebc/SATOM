"""Build compatibility — which fields exist on which firmware build, by which channel.

API library area. Pick a product and 2..N builds (default: the builds running
in the fleet plus every build the library knows) and read a matrix per
endpoint/field: present by both channels, CLI only, hidden (only ``show
full-configuration``), REST only, REST bookkeeping (meta), absent, or unknown.
A two-build diff reads ``api_library.compare`` (both channels) and each field
links to its history (``api_library.field_history``).

Everything is filtered and paginated server-side: a FortiWeb build carries
about 4-5k fields, and the page renders one page of rows, never the matrix.
Read-only; gated like the other API library pages (``Permission.REGISTRY_EDIT``).
"""
from __future__ import annotations

from flask import Blueprint, abort, jsonify, render_template, request
from flask_login import login_required

from ..auth.decorators import require_permission
from ..extensions import db
from ..models import Permission
from ..services import api_library as lib
from ..services import build_compat as bc
from ..services import firmware_versions as fv

bp = Blueprint('build_compat', __name__, url_prefix='/registry/build-compat')

PER_PAGE = 100
MAX_BUILDS = 8

#: Cell states of the matrix, in the order the legend shows them.
CELL_LABEL = {
    "both": "both", "cli_only": "CLI only", "hidden": "hidden", "rest_only": "REST only",
    "cli": "CLI (REST not measured)", "meta": "meta", "absent": "absent",
    "unknown": "unknown",
}
CELL_BADGE = {
    "both": "fw-badge-success", "cli_only": "fw-badge-warning", "hidden": "fw-badge-warning",
    "rest_only": "fw-badge-info", "cli": "fw-badge-info", "meta": "fw-badge-secondary",
    "absent": "fw-badge-danger", "unknown": "fw-badge-secondary",
}
ONLY = ("diff", "cli_only", "all")


def _products() -> list:
    try:
        have = {r["product"] for r in lib.products() or [] if r.get("builds")}
    except Exception:  # noqa: BLE001
        db.session.rollback()
        have = set()
    return [p for p in lib.PRODUCTS if p in have] or ["fortiweb"]


def _known_builds(product: str) -> list:
    try:
        rows = lib.builds(product)
    except Exception:  # noqa: BLE001
        db.session.rollback()
        return []
    return [r for r in rows if not r.get("line_only")]


def _picked(product: str, known: list) -> list:
    """Builds asked for, or the default: fleet builds + library builds."""
    raw = [fv.normalize(b) or b for b in request.args.getlist("b") if b]
    if not raw and request.args.get("builds"):
        raw = [fv.normalize(b.strip()) or b.strip()
               for b in request.args["builds"].split(",") if b.strip()]
    if not raw:
        fleet = [r["version"] for r in known if r.get("in_fleet")]
        rest = [r["version"] for r in known if not r.get("in_fleet")]
        raw = fleet + rest
    out = []
    for b in raw:
        if b and b not in out:
            out.append(b)
    return sorted(out[:MAX_BUILDS], key=fv.sort_key)


def cell(view: dict, key: str, field: str) -> str:
    """The state of ``key.field`` on one build view (see :data:`CELL_LABEL`)."""
    if not view.get("known"):
        return "unknown"
    ep = view["endpoints"].get(key)
    if ep is None:
        return "absent" if (view["tree_measured"] and view["path_rule"] == "verified") \
            else "unknown"
    f = ep["fields"].get(field)
    if f is None:
        if ep["present"] == "no":
            return "absent"
        if (ep["cli_has"] and view["tree_measured"]) or ep["rest_fields_known"]:
            return "absent"
        return "unknown"
    ch = f["channel"]
    if ch == lib.CH_UNKNOWN:
        return "cli" if f["cli"] == "yes" else ("absent" if f["cli"] == "no" else "unknown")
    return ch


_PRESENT = {"both", "cli_only", "hidden", "rest_only", "cli"}
_REST_YES, _REST_NO = {"both", "rest_only"}, {"cli_only", "hidden"}


def differs(cells) -> bool:
    """Do the builds DISAGREE about a field? Presence (present / absent / meta)
    differs, or two builds that both measured REST disagree on serving it. An
    ``unknown`` cell and a "REST not measured" cell disagree with nothing: not
    knowing is not a difference."""
    known = [c for c in cells if c != "unknown"]
    pres = {"present" if c in _PRESENT else c for c in known}
    if len(pres) > 1:
        return True
    rest = {"yes" if c in _REST_YES else "no" for c in known if c in _REST_YES | _REST_NO}
    return len(rest) > 1


def matrix(product: str, builds: list, *, q: str = "", only: str = "diff",
           meta: bool = False, page: int = 1, per_page: int = PER_PAGE) -> dict:
    """One page of the field x build matrix, filtered server-side."""
    views = {b: bc.build_view(product, b) for b in builds}
    names = set()
    for v in views.values():
        for key, ep in v["endpoints"].items():
            for f in ep["fields"]:
                names.add((key, f))
    ql = (q or "").strip().lower()
    rows = []
    counts = {"rows": 0, "diff": 0, "cli_only": 0}
    for key, f in sorted(names):
        if ql and ql not in key.lower() and ql not in f.lower():
            continue
        cells = [cell(views[b], key, f) for b in builds]
        if not meta and all(c in ("meta", "absent", "unknown") for c in cells) \
                and "meta" in cells:
            continue
        diff = differs(cells)
        cli_only = any(c in ("cli_only", "hidden") for c in cells)
        counts["rows"] += 1
        counts["diff"] += diff
        counts["cli_only"] += cli_only
        if only == "diff" and not diff:
            continue
        if only == "cli_only" and not cli_only:
            continue
        rows.append({"endpoint": key, "field": f, "cells": cells, "differs": diff})
    total = len(rows)
    pages = max(1, (total + per_page - 1) // per_page)
    page = min(max(1, page), pages)
    return {"builds": builds, "rows": rows[(page - 1) * per_page: page * per_page],
            "total": total, "page": page, "pages": pages, "counts": counts,
            "views": {b: {"known": v["known"], "tree_measured": v["tree_measured"],
                          "rest_measured": v["rest_measured"],
                          "endpoints": len(v["endpoints"])} for b, v in views.items()}}


def _page_arg() -> int:
    try:
        return max(1, int(request.args.get("page", 1)))
    except (TypeError, ValueError):
        return 1


@bp.route('/')
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def index():
    products = _products()
    product = request.args.get("product") or ("fortiweb" if "fortiweb" in products
                                             else products[0])
    if product not in lib.PRODUCTS:
        abort(404)
    known = _known_builds(product)
    builds = _picked(product, known)
    only = request.args.get("only", "diff")
    only = only if only in ONLY else "diff"
    q = (request.args.get("q") or "")[:120]
    meta = request.args.get("meta") == "1"
    m = matrix(product, builds, q=q, only=only, meta=meta, page=_page_arg(),
               per_page=PER_PAGE) \
        if builds else None
    a = request.args.get("a") or (builds[0] if len(builds) >= 2 else "")
    b = request.args.get("b2") or (builds[-1] if len(builds) >= 2 else "")
    # ``product`` is base.html's ADOM product object: never shadow it.
    return render_template("registry/build_compat.html", products=products,
                           sel_product=product, known=known, builds=builds, m=m,
                           only=only, q=q, meta=meta, a=a, b=b,
                           cell_label=CELL_LABEL, cell_badge=CELL_BADGE,
                           max_builds=MAX_BUILDS)


def diff_doc(product: str, a: str, b: str, *, q: str = "", page: int = 1,
             per_page: int = 50) -> dict:
    """``api_library.compare`` of two builds, CLI ``tree`` side paginated."""
    cmp_ = lib.compare(product, a, b)
    ch = cmp_.get("channels") or {}
    tree = ch.get("tree") or {}
    eps = sorted((tree.get("endpoints") or {}).items())
    ql = (q or "").strip().lower()
    if ql:
        eps = [(k, v) for k, v in eps if ql in k.lower() or any(
            ql in str(x).lower() for x in (v.get("added") or []) + (v.get("removed") or []))]
    total = len(eps)
    pages = max(1, (total + per_page - 1) // per_page)
    page = min(max(1, page), pages)
    return {"product": product, "a": cmp_["base"], "b": cmp_["target"],
            "rest_totals": cmp_.get("totals") or {},
            "rest_added": cmp_.get("endpoints_added") or [],
            "rest_removed": cmp_.get("endpoints_removed") or [],
            "tree": bool(tree), "tree_reason": ch.get("tree_reason") or "",
            "totals": tree.get("totals") or {},
            "endpoints_added": tree.get("endpoints_added") or [],
            "endpoints_removed": tree.get("endpoints_removed") or [],
            "endpoint_renames": tree.get("endpoint_rename_candidates") or [],
            "field_moves": tree.get("field_moves") or [],
            "channel_moves": len(ch.get("channel_moves") or []),
            "endpoints": eps[(page - 1) * per_page: page * per_page],
            "total": total, "page": page, "pages": pages}


@bp.route('/diff')
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def diff():
    product = request.args.get("product") or "fortiweb"
    if product not in lib.PRODUCTS:
        abort(404)
    a = fv.normalize(request.args.get("a") or "")
    b = fv.normalize(request.args.get("b") or "")
    if not (a and b):
        abort(400)
    q = (request.args.get("q") or "")[:120]
    d = diff_doc(product, a, b, q=q, page=_page_arg())
    if request.args.get("format") == "json":
        return jsonify(d)
    return render_template("registry/build_compat_diff.html", d=d, sel_product=product,
                           q=q)


@bp.route('/history')
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def history():
    product = request.args.get("product") or "fortiweb"
    endpoint = (request.args.get("ep") or request.args.get("endpoint") or "")[:200]
    field = (request.args.get("field") or "")[:160]
    if product not in lib.PRODUCTS or not endpoint or not field:
        abort(400)
    h = lib.field_history(product, endpoint, field)
    if request.args.get("format") == "json":
        return jsonify(h)
    return render_template("registry/build_compat_history.html", h=h, sel_product=product)
