"""Shared body of the API Versions page (firmware-line matrix).

Mounted twice — FortiWeb (``/web/registry/versions``) and FortiADC
(``/adc/api/versions``) — for the same reason ``_reconcile`` is: the catalog is
product-scoped and each product's API hub is its own ADOM page. One
implementation, two thin routes.

Read-only except ``rebuild``, and ``rebuild`` writes only the DERIVED matrix
file (``data/api_matrix/<product>.json``) — it never touches the registry, an
appliance, or any authored data. That is why it is gated on REGISTRY_EDIT
rather than something stronger: it is the same audience as the reconcile page
and strictly less dangerous.
"""
from __future__ import annotations

from flask import flash, redirect, render_template, request, url_for

from ..services import api_matrix, cli_coverage


def _pick_lines(matrix: dict) -> tuple[str, str]:
    """Default (base, target) for the comparison: oldest → newest known line.

    Newest-as-target is the direction an operator actually asks about ("what
    does the upgrade add?"). With fewer than two lines both come back empty and
    the template renders the single-line case instead of a diff against itself.
    """
    lines = sorted(matrix.get("lines") or {})
    if len(lines) < 2:
        return "", ""
    return lines[0], lines[-1]


def render_page(product: str, hub_endpoint: str, rebuild_endpoint: str,
                page_endpoint: str):
    matrix = api_matrix.load(product) or {"product": product, "lines": {},
                                          "fleet_lines": [], "witnesses": [],
                                          "notes": [], "built_at": "",
                                          "sweepable": product in api_matrix.SWEPT_PRODUCTS}
    lines = sorted(matrix.get("lines") or {})
    d_base, d_target = _pick_lines(matrix)
    base = request.args.get("base") or d_base
    target = request.args.get("target") or d_target
    # A base/target that is not a known line is silently dropped rather than
    # rendered as an empty diff: an empty diff and "you asked about a firmware
    # nobody has ever measured" look identical and mean opposite things.
    if base not in lines:
        base = d_base
    if target not in lines:
        target = d_target

    delta = None
    if base and target and base != target:
        delta = api_matrix.diff(product, base, target, matrix=matrix)

    # CLI provenance is PER FIRMWARE LINE here, never per product. A dump
    # is captured from one box running one firmware, so answering "does
    # 8.0 have this in its CLI?" with a 7.6 capture would be the page's
    # only way to lie, and it would look like a confident answer.
    # ``cli_coverage.report`` owns that selection (``line=``); a line with
    # no capture comes back unmeasured and every badge for it is "—".
    line_prov = {ln: cli_coverage.provenance(product, line=ln) for ln in lines}
    base_prov = line_prov.get(base)
    target_prov = line_prov.get(target)

    # Until now the page printed only COUNTS of endpoints added/removed.
    # A provenance column needs the rows, so they are rendered — annotated
    # in the view rather than looked up in the template, so the lookup has
    # exactly one call site.
    if delta:
        for row in delta.get("endpoints_added") or []:
            row["cli_base"] = base_prov.for_name(row["endpoint"]) if base_prov else None
            row["cli_target"] = target_prov.for_name(row["endpoint"]) if target_prov else None
        for row in delta.get("endpoints_removed") or []:
            row["cli_base"] = base_prov.for_name(row["endpoint"]) if base_prov else None
            row["cli_target"] = target_prov.for_name(row["endpoint"]) if target_prov else None

    # The console and the ``show`` runner live on this product's API hub, and
    # the caller already told us which blueprint that is. Deriving the two route
    # names from ``hub_endpoint`` keeps this body product-agnostic without
    # introducing a second product->blueprint map to drift against the first.
    _hub_bp = (hub_endpoint or "").split(".")[0]
    from ..models import Appliance, visible_appliances
    probe_appliances = (visible_appliances().filter(Appliance.kind == product)
                        .order_by(Appliance.name).all()) if _hub_bp else []
    return render_template(
        "registry/versions.html", product=product, matrix=matrix, lines=lines,
        probe_appliances=probe_appliances,
        exec_endpoint=("%s.execute" % _hub_bp) if _hub_bp else "",
        live_endpoint=("%s.cli_coverage_live" % _hub_bp) if _hub_bp else "",
        base=base, target=target, delta=delta, hub_endpoint=hub_endpoint,
        rebuild_endpoint=rebuild_endpoint, page_endpoint=page_endpoint,
        line_prov=line_prov, base_prov=base_prov, target_prov=target_prov,
    )


def rebuild_page(product: str, page_endpoint: str):
    try:
        matrix = api_matrix.rebuild(product)
    except Exception as exc:  # noqa: BLE001 — a rebuild failure must be visible
        flash("Rebuild failed: %s: %s" % (type(exc).__name__, exc), "danger")
        return redirect(url_for(page_endpoint))
    counts = matrix.get("lines") or {}
    flash("Matrix rebuilt from evidence on disk — %d firmware line(s): %s."
          % (len(counts), ", ".join(sorted(counts)) or "none"), "success")
    # Every skipped witness is surfaced. A device dropped for being unhealthy
    # is the single most useful thing on this page and the easiest to lose in
    # a success banner.
    for note in matrix.get("notes") or []:
        flash("%s skipped — %s." % (note.get("device", "?"), note.get("skipped", "")),
              "warning")
    return redirect(url_for(page_endpoint))


__all__ = ["render_page", "rebuild_page"]
