"""Shared body of the registry-reconcile page.

Mounted TWICE — on the FortiWeb ``registry`` blueprint (``/web/registry``) and
on the FortiADC ``adc_api`` blueprint (``/adc/api``) — because the catalog is
two-dimensional (``product``, ``api_version``) and each product's API hub is
its own ADOM-scoped page. One implementation, two thin routes: a copy per
product is how the two halves drift until only one of them still has the guard.

The page is read-only; ``apply`` is a separate POST and the service re-derives
the proposal set from the evidence before touching a row.
"""
from __future__ import annotations

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user

from ..services import registry_reconcile


def render_page(product: str, apply_endpoint: str, hub_endpoint: str):
    report = registry_reconcile.reconcile(product)
    return render_template("registry/reconcile.html", report=report,
                           product=product, apply_endpoint=apply_endpoint,
                           hub_endpoint=hub_endpoint)


def apply_page(product: str, page_endpoint: str):
    names = request.form.getlist("endpoint")
    if not names:
        flash("Select at least one endpoint to disable.", "warning")
        return redirect(url_for(page_endpoint))

    actor = getattr(current_user, "username", "") or ""
    result = registry_reconcile.apply_disable(product, names, actor=actor)

    if result["applied"]:
        flash("Disabled %d endpoint(s): %s." % (
            len(result["applied"]),
            ", ".join(a["name"] for a in result["applied"])), "success")
    # A rejection is never silent: the operator may be acting on a page that
    # was rendered before a sweep changed the evidence, and "nothing happened"
    # with a success banner is how that becomes invisible.
    for item in result["rejected"]:
        flash('"%s" was not disabled — %s.' % (item["name"], item["reason"]), "danger")
    return redirect(url_for(page_endpoint))


__all__ = ["render_page", "apply_page"]
