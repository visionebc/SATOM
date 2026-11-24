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
    "cli": "CLI (REST not measured)", "rest": "REST (CLI not measured)", "meta": "meta",
    "absent": "absent",
    "unknown": "unknown",
}
CELL_BADGE = {
    "both": "fw-badge-success", "cli_only": "fw-badge-warning", "hidden": "fw-badge-warning",
    "rest_only": "fw-badge-info", "cli": "fw-badge-info", "rest": "fw-badge-info",
    "meta": "fw-badge-secondary",
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


def _requested() -> list:
    """Builds the request names, normalised, de-duplicated, in the order given
    (empty when the request names none)."""
    raw = [fv.normalize(b) or b for b in request.args.getlist("b") if b]
    if not raw and request.args.get("builds"):
        raw = [fv.normalize(b.strip()) or b.strip()
               for b in request.args["builds"].split(",") if b.strip()]
    out = []
    for b in raw:
        if b and b not in out:
            out.append(b)
    return out


def _cap(candidates: list, known: list) -> tuple[list, list]:
    """``(shown, left_out)``: at most :data:`MAX_BUILDS` of ``candidates``, the
    builds the fleet runs first (they are the ones writes are checked against),
    then the newest. Both lists come back oldest first."""
    if len(candidates) <= MAX_BUILDS:
        return sorted(candidates, key=fv.sort_key), []
    fleet = {r["version"] for r in known if r.get("in_fleet")}
    ranked = sorted(candidates, key=lambda b: (b not in fleet, tuple(-x for x in fv.sort_key(b))))
    shown = ranked[:MAX_BUILDS]
    return (sorted(shown, key=fv.sort_key),
            sorted(ranked[MAX_BUILDS:], key=fv.sort_key))


def _picked(product: str, known: list) -> dict:
    """What the request asks for, checked against what the library knows.

    ``{"builds": [...shown...], "unknown": [...], "left_out": [...],
    "requested": bool}``. Nothing is dropped silently: a build the library does
    not know and the builds past the cap are both named."""
    asked = _requested()
    names = {r["version"] for r in known}
    if not asked:
        shown, left = _cap([r["version"] for r in known], known)
        return {"builds": shown, "unknown": [], "left_out": left, "requested": False}
    unknown = [b for b in asked if b not in names]
    shown, left = _cap([b for b in asked if b in names], known)
    return {"builds": shown, "unknown": unknown, "left_out": left, "requested": True}


def _known_text(known: list) -> str:
    names = [r["version"] for r in known]
    return ", ".join(names) if names else "none yet"


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
        # One channel measured, the other not: say which one saw it. A build
        # whose CLI schema nobody measured (FortiADC, FortiAnalyzer) still has
        # every field REST serves; calling it "unknown" hid every REST
        # difference between two such builds (2026-10-12: 0 of 1742 differ).
        if f["cli"] == "yes":
            return "cli"
        if f["rest"] == "yes":
            return "rest"
        return "absent" if f["cli"] == "no" else "unknown"
    return ch


_PRESENT = {"both", "cli_only", "hidden", "rest_only", "cli", "rest"}
_REST_YES, _REST_NO = {"both", "rest_only", "rest"}, {"cli_only", "hidden"}


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
    coverage = {b: {} for b in builds}
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
        for b, c in zip(builds, cells):
            coverage[b][c] = coverage[b].get(c, 0) + 1
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
            "coverage": coverage,
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
    pick = _picked(product, known)
    builds = pick["builds"]
    only = request.args.get("only", "diff")
    only = only if only in ONLY else "diff"
    q = (request.args.get("q") or "")[:120]
    meta = request.args.get("meta") == "1"
    notices = []
    error = None
    if pick["unknown"]:
        # A name the library has never seen is refused, not matched against
        # nothing: an all-"not measured" column reads as "no difference".
        error = "Unknown build %s for %s. The library knows: %s." % (
            ", ".join(pick["unknown"]), product, _known_text(known))
    if pick["left_out"]:
        notices.append("At most %d builds are shown (the fleet's builds first, then the newest). "
                       "Left out: %s." % (MAX_BUILDS, ", ".join(pick["left_out"])))
    if len(builds) == 1 and not error:
        only = "all" if only == "diff" else only
        notices.append("A comparison needs two builds. Showing what %s alone has, by channel; "
                       "pick a second build to see differences." % builds[0])
    m = matrix(product, builds, q=q, only=only, meta=meta, page=_page_arg(),
               per_page=PER_PAGE) if builds and not error else None
    a = request.args.get("a") or (builds[0] if len(builds) >= 2 else "")
    b = request.args.get("b2") or (builds[-1] if len(builds) >= 2 else "")
    # ``product`` and ``products`` are layout globals (the ADOM product object
    # and the ADOM registry): a view keyword must never shadow either one.
    html = render_template("registry/build_compat.html",
                           compat_products=products,
                           sel_product=product, known=known, builds=builds, m=m,
                           only=only, q=q, meta=meta, a=a, b=b,
                           cell_label=CELL_LABEL, cell_badge=CELL_BADGE,
                           max_builds=MAX_BUILDS, error=error, notices=notices)
    return (html, 400) if error else html


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
            "total": total, "page": page, "pages": pages,
            "gui": cmp_.get("gui") or {"pages": []}}


def _diff_refusal(product: str, a: str, b: str, known: list) -> tuple[str, str, dict] | None:
    """``(code, sentence, extra)`` when the pair is not a comparison, else None."""
    names = [r["version"] for r in known]
    if a == b:
        return ("same_build", "%s → %s compares a build with itself: pick two different "
                "builds." % (a, b), {})
    unknown = [x for x in (a, b) if x not in names]
    if unknown:
        return ("unknown_build", "Unknown build %s for %s: nothing to compare. The library "
                "knows: %s." % (", ".join(unknown), product, _known_text(known)),
                {"unknown": unknown})
    return None


def _diff_error(product: str, code: str, message: str, known: list, extra: dict,
                a: str = "", b: str = "", q: str = ""):
    """The refusal, as JSON (``format=json``) or as the page, HTTP 400."""
    if request.args.get("format") == "json":
        return jsonify({"ok": False, "error": code, "message": message, "product": product,
                        "a": a, "b": b, "known": [r["version"] for r in known], **extra}), 400
    return render_template("registry/build_compat_diff.html", d=None, error=message,
                           sel_product=product, q=q, a=a, b=b), 400


@bp.route('/diff')
@login_required
@require_permission(Permission.REGISTRY_EDIT)
def diff():
    product = request.args.get("product") or "fortiweb"
    if product not in lib.PRODUCTS:
        abort(404)
    a = fv.normalize(request.args.get("a") or "") or (request.args.get("a") or "").strip()
    b = fv.normalize(request.args.get("b") or "") or (request.args.get("b") or "").strip()
    known = _known_builds(product)
    q = (request.args.get("q") or "")[:120]
    if not (a and b):
        return _diff_error(product, "missing_build", "A diff needs two builds: pass a and b.",
                           known, {}, a, b, q)
    bad = _diff_refusal(product, a, b, known)
    if bad:
        return _diff_error(product, bad[0], bad[1], known, bad[2], a, b, q)
    d = diff_doc(product, a, b, q=q, page=_page_arg())
    if request.args.get("format") == "json":
        return jsonify(d)
    return render_template("registry/build_compat_diff.html", d=d, error=None,
                           sel_product=product, q=q, a=a, b=b)


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
