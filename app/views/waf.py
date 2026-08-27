"""WAF — the fleet-wide FortiWeb picture (read-only).

Four pages over ONE universe (``services/waf_fleet.collect``):

  ``/waf/``           overview — KPIs, posture, six charts, freshness
  ``/waf/inventory``  every server policy in the fleet, filterable + CSV
  ``/waf/profiles``   every web protection profile, its usage and its gaps
  ``/waf/coverage``   protection-by-scope matrix
  ``/waf/api/summary.json``  the chart payload (the templates carry no data)

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

from flask import Blueprint, Response, jsonify, render_template, request
from flask_login import current_user, login_required

from ..services import waf_fleet as svc

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
