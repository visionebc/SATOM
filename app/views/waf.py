"""WAF — the fleet-wide FortiWeb picture (read-only).

Four pages over ONE universe (``services/waf_fleet.collect``):

  ``/waf/``           overview — KPIs, posture, six charts, freshness
  ``/waf/inventory``  every server policy in the fleet, filterable + CSV
  ``/waf/profiles``   every web protection profile, its usage and its gaps
  ``/waf/coverage``   protection-by-scope matrix
  ``/waf/artifacts``  file-backed objects: what the estate needs, what SATOM
                      holds, and what therefore cannot be migrated
  ``/waf/api/summary.json``    the chart payload (the templates carry no data)
  ``/waf/api/artifacts.json``  ditto, for the artifacts page

The artifacts page reads a DIFFERENT universe from the other four — the
artifact index, not the configuration snapshot — but it is narrowed by the same
``waf_fleet.fortiweb_scopes`` call, so the scope banner over it means the same
thing. See ``services/waf_artifact_fleet``.

Why the charts fetch instead of being inlined: the CSP drops
``unsafe-inline`` and script-src-attr is ``'none'`` (app/__init__.py), so a
page that embeds its own dataset in a ``<script>`` block needs the nonce and
still ships the numbers twice. Fetching the same JSON the API serves keeps one
source for the figures — the drift that put a total in the header contradicting
its own table on ``/artifacts/inventory`` (safeguards §119) came from having
two.

Scope: fleet-wide BY DESIGN, but only over what this console may see —
``waf_fleet.collect`` narrows through ``visible_appliances()`` once and every
section is a function of that result. Read-only, so ``@login_required`` alone
(same contract as Fleet Objects).
"""
from __future__ import annotations

import csv
import io

from flask import (Blueprint, Response, flash, jsonify, redirect,
                   render_template, request, url_for)
from flask_login import current_user, login_required

from ..services import waf_artifact_fleet as artsvc
from ..services import waf_export as export_svc
from ..services import waf_fleet as svc
from ..services.audit import log_action

bp = Blueprint("waf", __name__, url_prefix="/waf")

#: Inventory table columns — (key, label). Also the CSV header, so the export
#: and the screen cannot describe different tables.
INVENTORY_COLUMNS: tuple[tuple[str, str], ...] = (
    ("scope", "Device / ADOM"),
    ("name", "Server policy"),
    ("posture", "Enforcement"),
    ("status", "Status"),
    ("service", "Service"),
    ("ssl_text", "TLS"),
    ("certificate", "Certificate"),
    ("vserver", "Virtual server"),
    ("pool", "Server pool"),
    ("wpp", "Web protection profile"),
    ("n_protections", "Protections on"),
    ("signature_rule", "Signature policy"),
    ("comment", "Comment"),
)

#: The artifacts table — screen and CSV, one definition.
ARTIFACT_COLUMNS: tuple[tuple[str, str], ...] = (
    ("scope", "Device / ADOM"),
    ("label", "Object type"),
    ("name", "Object"),
    ("state_label", "State"),
    ("policies", "Policies naming it"),
    ("profiles", "Profiles"),
    ("versions", "Versions held"),
    ("size", "Newest bytes"),
    ("source", "Origin"),
    ("sha", "Newest sha"),
    ("created_at", "First stored"),
    ("recoverable", "Recoverable from device"),
    ("remedy", "What to do"),
)

PROFILE_COLUMNS: tuple[tuple[str, str], ...] = (
    ("scope", "Device / ADOM"),
    ("name", "Profile"),
    ("kind", "Type"),
    ("origin", "Origin"),
    ("used_by", "Policies using it"),
    ("n_filled", "Protections on"),
    ("n_applicable", "Slots available"),
    ("signature_rule", "Signature policy"),
    ("comment", "Comment"),
)


def _universe():
    return svc.collect(user=current_user)


def _csv(columns, rows, filename: str) -> Response:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([label for _k, label in columns])
    for row in rows:
        writer.writerow([row.get(k, "") for k, _label in columns])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition":
                             "attachment; filename=%s" % filename})


def _decorate(policies):
    """Presentation-only fields the table and the CSV both need."""
    out = []
    for p in policies:
        out.append(dict(
            p,
            ssl_text=("TLS " + "/".join(p["weak_tls"]) if p["weak_tls"]
                      else ("TLS" if p["ssl"] else "plain HTTP")),
            posture_label=svc.POSTURE_LABELS.get(p["posture"], p["posture"]),
        ))
    return out


@bp.route("/")
@login_required
def index():
    universe = _universe()
    stats = svc.stats(universe)
    return render_template(
        "waf/overview.html",
        stats=stats,
        devices=universe["devices"],
        stale_hours=svc.STALE_AFTER_HOURS,
        posture_order=svc.POSTURE_ORDER,
        posture_labels=svc.POSTURE_LABELS,
    )


@bp.route("/inventory")
@login_required
def inventory():
    universe = _universe()
    rows = _decorate(universe["policies"])

    scope = (request.args.get("scope") or "").strip()
    posture = (request.args.get("posture") or "").strip()
    tls = (request.args.get("tls") or "").strip()
    q = (request.args.get("q") or "").strip().lower()

    if scope:
        rows = [r for r in rows if r["scope"] == scope]
    if posture in svc.POSTURE_ORDER:
        rows = [r for r in rows if r["posture"] == posture]
    if tls == "plain":
        rows = [r for r in rows if not r["ssl"]]
    elif tls == "weak":
        rows = [r for r in rows if r["weak_tls"]]
    elif tls == "tls":
        rows = [r for r in rows if r["ssl"]]
    if q:
        rows = [r for r in rows
                if any(q in str(r.get(k, "")).lower()
                       for k, _l in INVENTORY_COLUMNS)]

    if (request.args.get("format") or "").lower() == "csv":
        return _csv(INVENTORY_COLUMNS, rows, "waf_fleet_policies.csv")

    return render_template(
        "waf/inventory.html",
        columns=INVENTORY_COLUMNS,
        rows=rows,
        total=len(universe["policies"]),
        devices=universe["devices"],
        stale_hours=svc.STALE_AFTER_HOURS,
        posture_order=svc.POSTURE_ORDER,
        posture_labels=svc.POSTURE_LABELS,
        selected={"scope": scope, "posture": posture, "tls": tls, "q": q},
        stats=svc.stats(universe),
    )


@bp.route("/profiles")
@login_required
def profiles():
    universe = _universe()
    used = {(p["scope"], p["wpp"]) for p in universe["policies"] if p["wpp"]}
    rows = []
    for prof in universe["profiles"]:
        rows.append(dict(
            prof,
            origin="predefined" if prof["predefined"] else "custom",
            orphan=(not prof["predefined"]
                    and (prof["scope"], prof["name"]) not in used),
        ))

    scope = (request.args.get("scope") or "").strip()
    origin = (request.args.get("origin") or "").strip()
    only = (request.args.get("only") or "").strip()
    q = (request.args.get("q") or "").strip().lower()

    if scope:
        rows = [r for r in rows if r["scope"] == scope]
    if origin in ("custom", "predefined"):
        rows = [r for r in rows if r["origin"] == origin]
    if only == "orphan":
        rows = [r for r in rows if r["orphan"]]
    elif only == "used":
        rows = [r for r in rows if r["used_by"]]
    if q:
        rows = [r for r in rows
                if any(q in str(r.get(k, "")).lower() for k, _l in PROFILE_COLUMNS)]

    if (request.args.get("format") or "").lower() == "csv":
        return _csv(PROFILE_COLUMNS, rows, "waf_fleet_profiles.csv")

    return render_template(
        "waf/profiles.html",
        columns=PROFILE_COLUMNS,
        rows=rows,
        total=len(universe["profiles"]),
        devices=universe["devices"],
        stale_hours=svc.STALE_AFTER_HOURS,
        selected={"scope": scope, "origin": origin, "only": only, "q": q},
        protection_labels=svc.PROTECTION_LABELS,
        stats=svc.stats(universe),
    )


@bp.route("/coverage")
@login_required
def coverage():
    universe = _universe()
    stats = svc.stats(universe)

    # matrix[protection key][scope] = {"on": n, "applicable": n}
    matrix: dict[str, dict[str, dict[str, int]]] = {
        key: {} for key, _l, _g in svc.PROTECTIONS}
    index = svc._applicable_index(universe["profiles"])  # noqa: SLF001
    for pol in universe["policies"]:
        if not pol.get("wpp_resolved"):
            continue
        filled = set(pol["protections"])
        for key in index.get((pol["scope"], pol["wpp"]), ()):
            cell = matrix[key].setdefault(pol["scope"], {"on": 0, "applicable": 0})
            cell["applicable"] += 1
            if key in filled:
                cell["on"] += 1

    scopes = [d["scope"] for d in universe["devices"] if not d["missing"]]

    if (request.args.get("format") or "").lower() == "csv":
        cols = [("label", "Protection"), ("group", "Group")] + \
               [(s, s) for s in scopes]
        rows = []
        for key, label, group in svc.PROTECTIONS:
            row = {"label": label, "group": group}
            for s in scopes:
                cell = matrix[key].get(s)
                row[s] = ("%d/%d" % (cell["on"], cell["applicable"])) if cell else ""
            rows.append(row)
        return _csv(cols, rows, "waf_fleet_coverage.csv")

    # Grouped HERE, not in Jinja: grouping a tuple by index needs
    # ``selectattr('2', ...)``, and an index-as-attribute filter that matches
    # nothing renders a confident, empty table instead of failing.
    groups = [(group, [(k, lbl) for k, lbl, g in svc.PROTECTIONS if g == group])
              for group in svc.PROTECTION_GROUPS]

    return render_template(
        "waf/coverage.html",
        stats=stats,
        matrix=matrix,
        scopes=scopes,
        groups=groups,
        fleet_coverage={c["key"]: c for c in stats["coverage"]},
        devices=universe["devices"],
        stale_hours=svc.STALE_AFTER_HOURS,
    )


@bp.route("/artifacts")
@login_required
def artifacts():
    """Fleet-wide file-backed objects: demand, supply, and the gap.

    Note what the filters do and do not do: they narrow the TABLE. Every tile
    and every chart above them is the whole visible fleet and says so — the
    header-contradicting-its-table drift of safeguards §119 came from letting a
    filter quietly move one of the two.
    """
    universe = artsvc.collect(user=current_user)
    stats = artsvc.stats(universe)
    rows = [dict(r,
                 recoverable=("yes" if r["readable"] else "no — upload only"),
                 policy_list=", ".join(r["policy_names"][:6]))
            for r in universe["rows"]]

    scope = (request.args.get("scope") or "").strip()
    kind = (request.args.get("kind") or "").strip()
    state = (request.args.get("state") or "").strip()
    flag = (request.args.get("flag") or "").strip()
    q = (request.args.get("q") or "").strip().lower()

    if scope:
        rows = [r for r in rows if r["scope"] == scope]
    if kind:
        rows = [r for r in rows if r["kind"] == kind]
    if state in artsvc.STATES:
        rows = [r for r in rows if r["state"] == state]
    elif state == "unheld":
        # The one compound an operator actually asks for: everything the estate
        # needs and does not have its own copy of, whatever the reason.
        rows = [r for r in rows if r["needed"] and r["state"] != "ok"]
    if flag == "empty":
        rows = [r for r in rows if r["empty"]]
    elif flag == "stale":
        rows = [r for r in rows if r["stale"]]
    if q:
        rows = [r for r in rows
                if any(q in str(r.get(k, "")).lower() for k, _l in ARTIFACT_COLUMNS)]

    if (request.args.get("format") or "").lower() == "csv":
        return _csv(ARTIFACT_COLUMNS, rows, "waf_fleet_artifacts.csv")

    return render_template(
        "waf/artifacts.html",
        columns=ARTIFACT_COLUMNS,
        rows=rows,
        total=len(universe["rows"]),
        stats=stats,
        scopes=universe["scopes"],
        by_kind=artsvc.by_kind(universe),
        devices=universe["devices"],
        stale_hours=svc.STALE_AFTER_HOURS,
        states=artsvc.STATES,
        state_labels=artsvc.STATE_LABELS,
        verdicts=artsvc.VERDICTS,
        kinds=artsvc.kind_choices(),
        library_scope=artsvc.LIBRARY_SCOPE,
        selected={"scope": scope, "kind": kind, "state": state,
                  "flag": flag, "q": q},
    )


@bp.route("/api/artifacts.json")
@login_required
def api_artifacts():
    universe = artsvc.collect(user=current_user)
    stats = artsvc.stats(universe)
    kinds = artsvc.by_kind(universe)
    return jsonify({
        "stats": {k: v for k, v in stats.items() if k != "by_state"},
        "readiness": [{"key": v, "label": artsvc.STATE_LABELS[v],
                       "value": stats["by_state"][v]} for v in artsvc.VERDICTS],
        # Types with nothing at all are dropped HERE and only here: a bar of
        # zeros for an object type the fleet does not use reads as a gap.
        "by_kind": [{"label": k["label"], "held": k["ok"],
                     "blocked": k["blocked"], "at-risk": k["at-risk"],
                     "borrowed": k["borrowed"], "orphan": k["orphan"],
                     "library": k["library"], "empty": k["empty"],
                     "versions": k["versions"], "bytes": k["bytes"]}
                    for k in kinds
                    if k["needed"] or k["versions"] or k["orphan"] or k["library"]],
        "per_scope": universe["scopes"],
        "growth": artsvc.growth_series(universe),
        "generated_at": stats["generated_at"],
    })


@bp.route("/api/summary.json")
@login_required
def api_summary():
    universe = _universe()
    stats = svc.stats(universe)
    return jsonify({
        "stats": {k: v for k, v in stats.items()
                  if k not in ("coverage", "per_scope", "signatures")},
        "posture": [{"key": k, "label": svc.POSTURE_LABELS[k],
                     "value": stats["posture"][k]} for k in svc.POSTURE_ORDER],
        "per_scope": stats["per_scope"],
        "coverage": stats["coverage"],
        "signatures": [{"name": n, "value": v} for n, v in stats["signatures"]],
        "crypto": [
            {"label": "TLS, modern only",
             "value": stats["ssl"] - stats["weak_tls"]},
            {"label": "TLS 1.0/1.1 enabled", "value": stats["weak_tls"]},
            {"label": "Plain HTTP", "value": stats["plain"]},
        ],
        "changes": svc.change_series(universe),
        "generated_at": stats["generated_at"],
    })


# ---------------------------------------------------------------------------
# Export — the whole visible fleet, in the formats the operator ticked
# ---------------------------------------------------------------------------
#: Where the panel may send an operator back to. A literal tuple, never a
#: free-form ``next=``: an open redirect is an open redirect even when the
#: form it hangs off only produces a download.
_EXPORT_BACK: tuple[str, ...] = ("index", "inventory", "profiles", "coverage",
                                 "artifacts")


@bp.context_processor
def _export_choices():
    """What the panel offers, injected for THIS blueprint's templates only.

    A context processor rather than five ``render_template`` kwargs: the panel
    is in a shared partial, and a sixth /waf page added later would otherwise
    render it with empty checkbox lists — silently, because an empty ``for``
    renders nothing at all.
    """
    return {"export_datasets": export_svc.DATASETS,
            "export_formats": export_svc.FORMATS}


@bp.route("/export")
@login_required
def export():
    """Build the ZIP the panel asked for.

    GET on purpose: the entire selection is in the URL, so a bundle is
    bookmarkable ("the one I take to change review") and a support request can
    quote the exact link that produced a file. It reads and mutates nothing.

    Scope is the exporting user's own visibility — ``waf_export`` narrows
    through the same ``waf_fleet.fortiweb_scopes`` call every page here does,
    so this endpoint cannot hand out a scope its caller could not already open.
    """
    keys = request.args.getlist("set")
    formats = request.args.getlist("fmt")
    back = request.args.get("back") or "index"
    endpoint = "waf.%s" % (back if back in _EXPORT_BACK else "index")

    try:
        blob, filename = export_svc.build_zip(
            keys=keys, formats=formats, user=current_user,
            author=getattr(current_user, "username", ""))
    except ValueError as exc:
        # Nothing ticked. Not a 400 page (it loses the operator's place) and
        # never an empty ZIP: that downloads perfectly happily and reads as
        # "the fleet had nothing", which is a claim about the estate rather
        # than about the form.
        flash(str(exc), "warning")
        return redirect(url_for(endpoint))

    # A bulk copy of the fleet's WAF configuration leaving the appliance is
    # worth a row even though nothing changed.
    log_action("waf.export",
               target=",".join(k for k in export_svc.DATASET_KEYS if k in keys),
               extra={"formats": [f for f, _l in export_svc.FORMATS
                                  if f in formats],
                      "bytes": len(blob)})
    return Response(blob, mimetype="application/zip",
                    headers={"Content-Disposition":
                             'attachment; filename="%s"' % filename,
                             "Content-Length": str(len(blob)),
                             "Cache-Control": "no-store"})
