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
                      Permission, db, visible_appliances,
                      visible_appliance_or_404)
from ..services import cert_manager as cm
from ..services import cert_probe
from ..services import settings_store as store
from ..services.audit import log_action

bp = Blueprint("cert_manager", __name__, url_prefix="/cert-manager")


def _product_kind() -> str:
    """Appliance kind for the ACTIVE product (session['product']). The
    Certificate Manager is reachable from BOTH products; each must show only
    its OWN devices/certs (FortiADC Global -> FortiADC, FortiWeb -> FortiWeb)."""
    from flask import session
    return "fortiadc" if session.get("product") == "fortiadc" else "fortiweb"


def _fortiweb_appliances():
    """Every appliance the device-cert inventory covers — FortiWeb AND FortiADC
    (the scan/list service dispatches per kind; ADC reads are pure REST).
    Name kept for history; it has been both-kinds since the ADC scan landed."""
    return (visible_appliances()
            .filter(Appliance.kind == _product_kind())
            .order_by(Appliance.name).all())


def _deploy_targets():
    """Deploy targets for a NEW certificate — FortiWeb (SSH import) AND FortiADC
    (REST upload; ``cert_adc``)."""
    return (visible_appliances()
            .filter(Appliance.kind == _product_kind())
            .order_by(Appliance.name).all())


# --------------------------------------------------------------------------- #
#  Inventory                                                                     #
# --------------------------------------------------------------------------- #
@bp.route("/")
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    appliance_list = _fortiweb_appliances()
    appliances = {a.id: a for a in appliance_list}
    _prod_ids = set(appliances)
    # Managed certs scoped to the active product: certs on THIS product's
    # appliances (unassigned certs - no appliance yet - show in either).
    certs = [c for c in (ManagedCertificate.query
                         .order_by(ManagedCertificate.expires_at.asc().nullslast(),
                                   ManagedCertificate.name.asc())
                         .all())
             if c.appliance_id in _prod_ids or c.appliance_id is None]
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
    # On-device certificates: read the CACHED inventory from the DB (populated by
    # the "Scan devices" button or the daily cert_scan scheduled action), so the
    # table shows expiry / days-left / SANs / bindings WITHOUT a slow fleet sweep
    # on every page load. Consolidated to ONE row per unique cert.
    device = cm.stored_device_certificates(appliance_list)
    device_cached = True
    device_offline = []
    if not device["rows"] and device["last_scanned"] is None:
        # Never scanned: fall back to a one-off live sweep so the table isn't blank,
        # and let the operator know a scan will enrich it with expiry/SANs.
        device_cached = False
        swept = cm.consolidate_device_certificates(
            cm.list_device_certificates(appliance_list))
        for r in swept["rows"]:
            r.setdefault("sans", []); r.setdefault("expires_at", None)
            r.setdefault("days_left", None); r.setdefault("bindings", [])
        device = {"rows": swept["rows"], "unique": swept["unique"],
                  "deployments": swept["deployments"], "last_scanned": None}
        device_offline = swept["offline"]
    _lifecycle = cm.lifecycle_candidates()
    for _k in ("revoke_due", "delete_due", "blocked"):
        _lifecycle[_k] = [it for it in _lifecycle.get(_k, [])
                          if it["cert"].appliance_id in _prod_ids
                          or it["cert"].appliance_id is None]
    return render_template(
        "cert_manager/index.html",
        rows=rows,
        lifecycle=_lifecycle,
        configured=store.cert_manager_configured(),
        class_labels=store.CERT_CLASS_LABELS,
        device_rows=device["rows"],
        device_offline=device_offline,
        device_unique=device["unique"],
        device_deployments=device["deployments"],
        device_last_scanned=device["last_scanned"],
        device_cached=device_cached,
    )


@bp.route("/lifecycle/run", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def lifecycle_run():
    """Apply the lifecycle policy NOW (manual sweep): revoke due superseded
    certs at the CA and delete due unbound material off the devices. Every
    destructive step re-verifies bindings live and fail-closed."""
    res = cm.run_lifecycle_sweep(dry_run=False, actor=current_user.username)
    done = res["revoked"] + res["deleted"]
    if done:
        flash("Lifecycle sweep: " + "; ".join(done), "success")
    else:
        flash("Lifecycle sweep: nothing applied.", "info")
    if res["skipped"]:
        flash("Skipped: " + "; ".join(res["skipped"]), "warning")
    return redirect(url_for("cert_manager.index"))


@bp.route("/scan", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def scan_devices():
    """Manual fleet-wide certificate scan → refresh the on-device DB cache."""
    appliance_list = _fortiweb_appliances()
    res = cm.scan_fleet_certificates(appliance_list)
    log_action("certmgr.scan_devices",
               detail=f"scanned={res['scanned']} detailed={res['detailed']} "
                      f"online={res['online']}")
    msg = (f"Scanned {res['online']} device(s): cached {res['scanned']} "
           f"certificate(s), {res['detailed']} with full X.509 detail.")
    if res["offline"]:
        msg += " Unreachable: " + ", ".join(o["name"] for o in res["offline"]) + "."
    flash(msg, "success" if res["online"] else "warning")
    return redirect(url_for("cert_manager.index"))


@bp.route("/device-cert")
@login_required
@require_permission(Permission.USER_MANAGE)
def device_cert():
    """Detail for one on-device certificate: which FortiWebs carry it, its typed
    bindings (server-policy / SNI / GUI), a live-probed X.509 detail panel, and
    swap/remove actions."""
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
    devices = [a for a in appliance_list if a.id in on_ids]

    detail = None
    mc = ManagedCertificate.query.filter_by(name=name).first()
    if mc and mc.cert_pem:
        detail = cert_probe.detail_from_pem(mc.cert_pem)
    per_device = []
    swap_options = []
    for a in devices:
        usage = cm.cert_usage(a, name)
        per_device.append({"appliance": a, "usage": usage})
        if detail is None:
            for u in usage:
                if u.get("probe") and u["probe"].get("host"):
                    pem, err = cert_probe.probe_leaf_pem(
                        u["probe"]["host"], u["probe"].get("port") or 443,
                        server_name=(_detail_hint(u) or name))
                    if pem:
                        detail = cert_probe.detail_from_pem(pem)
                        break
        swap_options.append({"appliance": a, "targets": _swap_targets(a)})

    # Fallback: a cert that is on the box but bound nowhere (no server policy / SNI /
    # GUI) is served on no live endpoint, so the TLS probe above finds nothing. Read
    # its decoded X.509 detail straight from the FortiWeb CLI over SSH instead.
    if detail is None:
        for a in devices:
            detail = cm.device_cert_detail_via_ssh(a, store_label, name)
            if detail is not None:
                break

    return render_template("cert_manager/device_cert.html",
                           row=row, per_device=per_device, detail=detail,
                           swap_options=swap_options, cert_name=name,
                           store_label=store_label)


def _detail_hint(usage_row):
    """SNI/host hint for the TLS SNI field when probing (a domain if we have one)."""
    lbl = usage_row.get("label", "")
    return lbl.split("—")[-1].strip() if "—" in lbl else None


def _swap_targets(appliance):
    """Every place a cert could be swapped ON this box: server policies, SNI members,
    GUI. Read-only, best-effort."""
    try:
        client = appliance.build_client(timeout=6.0)
    except Exception:  # noqa: BLE001
        return {"policies": [], "sni": [], "gui": False}
    pols = cm._get_results(client, cm.SERVER_POLICY_EP) or []
    policies = sorted(str(p.get("name", "")) for p in pols
                      if isinstance(p, dict) and p.get("name"))
    sni_rows = cm._get_results(client, cm.SNI_EP) or []
    sni = []
    for s in sni_rows:
        if isinstance(s, dict):
            for m in (s.get("members") or []):
                if isinstance(m, dict):
                    sni.append({"sni": str(s.get("name", "")), "id": str(m.get("id", "")),
                                "domain": str(m.get("domain", ""))})
    return {"policies": policies, "sni": sni, "gui": True}


@bp.route("/device-cert/swap", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def device_cert_swap():
    a = db.session.get(Appliance, _int(request.form.get("appliance_id")))
    cert_name = (request.form.get("cert_name") or "").strip()
    kind = (request.form.get("kind") or "").strip()
    store_label = (request.form.get("store") or "").strip()
    if a is None or not cert_name:
        flash("Missing appliance or certificate.", "danger")
        return redirect(url_for("cert_manager.index"))
    if kind == "server-policy":
        res = cm.swap_server_policy_cert(a, (request.form.get("policy") or "").strip(),
                                         "certificate", cert_name, dry_run=False)
    elif kind == "sni":
        sni = (request.form.get("sni") or "").strip()
        member_id = (request.form.get("member_id") or "").strip()
        if not sni or not member_id:
            flash("Select an SNI member to swap.", "danger")
            return redirect(url_for("cert_manager.device_cert", store=store_label, name=cert_name))
        res = cm.swap_sni_member(a, sni, member_id, cert_name, dry_run=False)
    elif kind == "gui":
        res = cm.swap_gui_cert(a, cert_name, dry_run=False)
    else:
        flash(f"Unknown swap target {kind!r}.", "danger")
        return redirect(url_for("cert_manager.device_cert", store=store_label, name=cert_name))
    flash((f"Swapped {kind} onto {cert_name} on {a.name}." if res.get("ok")
           else f"Swap failed: {res.get('error')}"),
          "success" if res.get("ok") else "danger")
    return redirect(url_for("cert_manager.device_cert", store=store_label, name=cert_name))


@bp.route("/device-cert/remove", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def device_cert_remove():
    a = db.session.get(Appliance, _int(request.form.get("appliance_id")))
    cert_name = (request.form.get("cert_name") or "").strip()
    store_label = (request.form.get("store") or "").strip()
    if a is None or not cert_name:
        flash("Missing appliance or certificate.", "danger")
        return redirect(url_for("cert_manager.index"))
    res = cm.remove_device_certificate(a, store_label, cert_name, dry_run=False,
                                       actor=current_user.username)
    if res.get("removed"):
        flash(f"Removed {cert_name} from {a.name}.", "success")
    else:
        flash(f"Not removed: {res.get('error')}", "warning")
    return redirect(url_for("cert_manager.device_cert", store=store_label, name=cert_name))


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
        appliances=_deploy_targets(),
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
    cert_detail = cert_probe.detail_from_pem(cert.cert_pem) if cert.cert_pem else None
    return render_template(
        "cert_manager/detail.html",
        cert=cert, appliance=appliance, events=events,
        live_bindings=live_bindings, policies=policies,
        class_label=store.CERT_CLASS_LABELS.get(cert.cert_class, cert.cert_class),
        cert_detail=cert_detail, cert_pem=cert.cert_pem or "",
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
