"""Certificate Manager — the Automation inventory + lifecycle UI.

Lives under **Automation** (admin-only, USER_MANAGE). Three concerns:

* **Settings** (``/cert-manager/settings``) — the admin fills the ADCS connection
  and, per class (server / clientserver / client), the signing/revoke command
  templates + key/subject/SAN formats + renew window. Nothing is hardcoded.
* **Inventory** (``/cert-manager/``) — every managed certificate with its device,
  class, SANs, expiry / days-left (colour-coded), status and bindings, plus row
  actions: renew now, swap (immediate), revoke, view timeline.
* **New** (``/cert-manager/new``) — generate → sign → deploy a fresh certificate.

Box-affecting steps go through the service layer
(:mod:`app.services.cert_manager`), which snapshots/audits and never raises.
"""
from __future__ import annotations

from flask import (Blueprint, flash, redirect, render_template, request,
                   url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import (Appliance, ManagedCertificate, ManagedCertificateEvent,
                      Permission, db)
from ..services import cert_manager as cm
from ..services import settings_store as store
from ..services.audit import log_action

bp = Blueprint("cert_manager", __name__, url_prefix="/cert-manager")


def _fortiweb_appliances():
    return (Appliance.query.filter_by(kind="fortiweb")
            .order_by(Appliance.name).all())


# --------------------------------------------------------------------------- #
#  Inventory                                                                     #
# --------------------------------------------------------------------------- #
@bp.route("/")
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    certs = (ManagedCertificate.query
             .order_by(ManagedCertificate.expires_at.asc().nullslast(),
                       ManagedCertificate.name.asc())
             .all())
    appliance_list = _fortiweb_appliances()
    appliances = {a.id: a for a in appliance_list}
    rows = []
    for c in certs:
        d = c.days_left
        tone = "muted"
        if d is not None:
            tone = "danger" if d < 0 else "warning" if d <= 14 else (
                "warning" if d <= 30 else "success")
        rows.append({
            "c": c,
            "device": appliances.get(c.appliance_id).name if c.appliance_id in appliances else "—",
            "days_left": d,
            "tone": tone,
            "class_label": store.CERT_CLASS_LABELS.get(c.cert_class, c.cert_class),
        })
    # On-device certificates: a live read-only sweep so the operator can see the
    # certs already on each FortiWeb even when ADCS signing isn't configured.
    # Consolidated to ONE row per unique cert (same cert on N boxes = 1 line, not N).
    device_certs = cm.list_device_certificates(appliance_list)
    device = cm.consolidate_device_certificates(device_certs)
    return render_template(
        "cert_manager/index.html",
        rows=rows,
        configured=store.cert_manager_configured(),
        class_labels=store.CERT_CLASS_LABELS,
        device_rows=device["rows"],
        device_offline=device["offline"],
        device_unique=device["unique"],
        device_deployments=device["deployments"],
    )


@bp.route("/device-cert")
@login_required
@require_permission(Permission.USER_MANAGE)
def device_cert():
    """Read-only detail for one on-device certificate: which FortiWebs carry it and,
    live, which server policies bind it on each. No ADCS, no writes."""
    store_label = (request.args.get("store") or "").strip()
    name = (request.args.get("name") or "").strip()
    appliance_list = _fortiweb_appliances()
    device = cm.consolidate_device_certificates(
        cm.list_device_certificates(appliance_list))
    row = next((r for r in device["rows"]
                if r["store"] == store_label and r["name"] == name), None)
    if row is None:
        flash(f"Certificate {name!r} was not found on any device (it may have been "
              "removed, or the box is unreachable).", "warning")
        return redirect(url_for("cert_manager.index"))
    on_ids = {d["id"] for d in row["devices"]}
    per_device = []
    for a in appliance_list:
        if a.id not in on_ids:
            continue
        per_device.append({"appliance": a, "bindings": cm.read_bindings(a, name)})
    return render_template("cert_manager/device_cert.html",
                           row=row, per_device=per_device)


# --------------------------------------------------------------------------- #
#  Settings                                                                      #
# --------------------------------------------------------------------------- #
@bp.route("/settings")
@login_required
@require_permission(Permission.USER_MANAGE)
def settings():
    """Settings moved into the admin console (Settings → Certificate Manager).
    This stub keeps old links / bookmarks working."""
    return redirect(url_for("settings.index") + "#tab-certmgr")


# --------------------------------------------------------------------------- #
#  New certificate                                                               #
# --------------------------------------------------------------------------- #
@bp.route("/new", methods=["GET", "POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def new():
    if request.method == "POST":
        appliance = db.session.get(Appliance, _int(request.form.get("appliance_id")))
        cn = (request.form.get("cn") or "").strip()
        cert_class = (request.form.get("cert_class") or "server").strip()
        extra = [s.strip() for s in (request.form.get("extra_sans") or "").replace("\n", ",").split(",") if s.strip()]
        deploy = bool(request.form.get("deploy"))
        if appliance is None:
            flash("Select a target FortiWeb.", "danger")
            return redirect(url_for("cert_manager.new"))
        res = cm.create_certificate(appliance, cn, cert_class, extra_sans=extra,
                                    deploy=deploy, actor=current_user.username)
        if res.get("ok"):
            flash(f"Certificate {res.get('name')} created"
                  + (" and deployed." if deploy else " (not deployed)."), "success")
            return redirect(url_for("cert_manager.detail", id=res["cert_id"]))
        # Partial failure still leaves a row we can inspect.
        flash(f"Certificate creation failed: {res.get('error')}", "danger")
        if res.get("cert_id"):
            return redirect(url_for("cert_manager.detail", id=res["cert_id"]))
        return redirect(url_for("cert_manager.new"))

    return render_template(
        "cert_manager/new.html",
        appliances=_fortiweb_appliances(),
        classes=[(c, store.CERT_CLASS_LABELS[c]) for c in store.CERT_CLASSES],
        configured=store.cert_manager_configured(),
    )


# --------------------------------------------------------------------------- #
#  Detail / timeline                                                            #
# --------------------------------------------------------------------------- #
@bp.route("/<int:id>")
@login_required
@require_permission(Permission.USER_MANAGE)
def detail(id):
    cert = ManagedCertificate.query.get_or_404(id)
    appliance = db.session.get(Appliance, cert.appliance_id) if cert.appliance_id else None
    # Live bindings (best-effort) so swap targets are real.
    live_bindings = cm.read_bindings_for(cert) if appliance else []
    policies = []
    if appliance:
        try:
            resp = appliance.build_client().api_call("GET", cm.SERVER_POLICY_EP)
            body = resp.json() if resp is not None else {}
            rows = body.get("results") if isinstance(body, dict) else []
            policies = sorted(str(p.get("name", "")) for p in rows
                              if isinstance(p, dict) and p.get("name"))
        except Exception:  # noqa: BLE001 — offline box → no swap targets, page still works
            policies = []
    events = (ManagedCertificateEvent.query
              .filter_by(cert_id=cert.id)
              .order_by(ManagedCertificateEvent.ts.desc())
              .all())
    return render_template(
        "cert_manager/detail.html",
        cert=cert, appliance=appliance, events=events,
        live_bindings=live_bindings, policies=policies,
        class_label=store.CERT_CLASS_LABELS.get(cert.cert_class, cert.cert_class),
    )


@bp.route("/<int:id>/renew", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def renew(id):
    cert = ManagedCertificate.query.get_or_404(id)
    res = cm.renew_certificate(cert, deploy=True, actor=current_user.username)
    if res.get("ok"):
        flash(f"Renewed → {res.get('name')} (ready for a maintenance-window swap).", "success")
        return redirect(url_for("cert_manager.detail", id=res["cert_id"]))
    flash(f"Renew failed: {res.get('error')}", "danger")
    return redirect(url_for("cert_manager.detail", id=id))


@bp.route("/<int:id>/swap", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def swap(id):
    cert = ManagedCertificate.query.get_or_404(id)
    policy = (request.form.get("policy") or "").strip()
    if not policy:
        flash("Choose a server policy to swap.", "danger")
        return redirect(url_for("cert_manager.detail", id=id))
    res = cm.confirm_swap(cert, policy, actor=current_user.username)
    if res.get("ok"):
        flash(f"Policy {policy} now uses {cert.name}.", "success")
    else:
        flash(f"Swap failed: {res.get('error')}", "danger")
    return redirect(url_for("cert_manager.detail", id=id))


@bp.route("/<int:id>/revoke", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def revoke(id):
    cert = ManagedCertificate.query.get_or_404(id)
    delete_from_box = bool(request.form.get("delete_from_box"))
    res = cm.revoke_certificate(cert, delete_from_box=delete_from_box,
                                actor=current_user.username)
    if res.get("bindings"):
        flash("Revoked at the CA, but NOT deleted from the device — still bound to: "
              + ", ".join(res["bindings"]), "warning")
    elif res.get("ok"):
        flash(f"Certificate {cert.name} revoked"
              + (" and removed from the device." if delete_from_box else "."), "success")
    else:
        flash(f"Revoke reported an issue: {res.get('error')}", "warning")
    return redirect(url_for("cert_manager.detail", id=id))


@bp.route("/<int:id>/delete", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def delete(id):
    cert = ManagedCertificate.query.get_or_404(id)
    name = cert.name
    ManagedCertificateEvent.query.filter_by(cert_id=cert.id).delete()
    db.session.delete(cert)
    db.session.commit()
    log_action("certmgr.delete", target=name)
    flash(f"Removed certificate record {name} (the device copy, if any, is untouched).",
          "success")
    return redirect(url_for("cert_manager.index"))


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None
