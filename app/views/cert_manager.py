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

from flask import (Blueprint, Response, flash, jsonify, redirect, render_template,
                   request, url_for)
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
    """Appliance kind for the ACTIVE product (the request's effective ADOM —
    per-tab, see services.product_scope). A concrete ADOM shows only its OWN
    devices/certs; the Global ADOM shows every product (returns '' = no kind
    filter).

    The product list is DERIVED, not enumerated here: a hardcoded pair meant
    every ADOM added after this function was written fell through to '' and
    got the unfiltered inventory."""
    from ..services.product_scope import session_product, concrete_products
    prod = session_product()
    return prod if prod in concrete_products() else ""  # '' = global/unset


def _kind_scoped(query):
    """Apply the active ADOM's kind filter, then keep only the kinds SATOM
    manages certificates on (``cm.CERT_KINDS``). Global used to pass every
    kind, so Scan devices aimed FortiWeb calls at FortiGate, FortiAnalyzer and
    FortiAuthenticator and listed them as unreachable."""
    kind = _product_kind()
    if kind:
        query = query.filter(Appliance.kind == kind)
    return query.filter(db.or_(Appliance.kind.in_(cm.CERT_KINDS),
                               Appliance.kind.is_(None)))


def _fortiweb_appliances():
    """Every appliance the device-cert inventory covers — FortiWeb AND FortiADC
    (the scan/list service dispatches per kind; ADC reads are pure REST).
    Name kept for history; it has been both-kinds since the ADC scan landed."""
    return _kind_scoped(visible_appliances()).order_by(Appliance.name).all()


def _deploy_targets():
    """Deploy targets for a NEW certificate — FortiWeb (SSH import) AND FortiADC
    (REST upload; ``cert_adc``)."""
    return _kind_scoped(visible_appliances()).order_by(Appliance.name).all()


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
    all_certs = [c for c in (ManagedCertificate.query
                             .order_by(ManagedCertificate.expires_at.asc().nullslast(),
                                       ManagedCertificate.name.asc())
                             .all())
                 if c.appliance_id in _prod_ids or c.appliance_id is None]
    certs = [c for c in all_certs if not c.archived_at]
    archived = [c for c in all_certs if c.archived_at]
    rows = [_row(c, appliances) for c in certs]
    from ..models import CertRevocation
    _ids = {c.id for c in all_certs}
    revocations = [r for r in (CertRevocation.query
                               .order_by(CertRevocation.requested_at.desc())
                               .limit(200).all())
                   if r.cert_id is None or r.cert_id in _ids]
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
        archived=archived,
        revocations=revocations,
        revocations_pending=sum(1 for r in revocations if r.result == "manual_pending"),
        lifecycle=_lifecycle,
        configured=store.cert_manager_configured(),
        protocol=store.cert_manager_protocol(),
        class_labels=store.CERT_CLASS_LABELS,
        device_rows=device["rows"],
        device_offline=device_offline,
        device_unique=device["unique"],
        device_deployments=device["deployments"],
        device_last_scanned=device["last_scanned"],
        device_cached=device_cached,
    )


STATUS_TONES = {"active": "success", "staged": "info", "pending": "info",
                "awaiting_signature": "warning", "superseded": "secondary",
                "revoked": "danger"}
ORIGIN_LABELS = {"signer": "Configured CA", "external": "CSR for another CA",
                 "imported": "Imported (key from outside)"}


def is_deployed(cert) -> bool:
    """Did a deploy of *cert* succeed (its timeline says so)?"""
    return any(e.kind == "deploy" and e.ok for e in cert.events)


def _row(c, appliances) -> dict:
    d = c.days_left
    tone = "muted"
    if d is not None:
        tone = "danger" if d < 0 else "warning" if d <= 30 else "success"
    return {
        "c": c,
        "device": appliances.get(c.appliance_id).name if c.appliance_id in appliances else "—",
        "days_left": d,
        "tone": tone,
        "class_label": store.CERT_CLASS_LABELS.get(c.cert_class, c.cert_class),
        "next": cm.next_step(c),
        "acts": actions_for(c),
    }


def actions_for(c) -> dict:
    """Which row/detail buttons apply to *c* — one rule for both pages."""
    live = not c.archived_at
    succ = cm.successor_of(c) if live else None
    return {
        "renew": live and c.origin == "signer" and c.status in ("active", "pending")
                 and succ is None,
        "new_csr": live and c.origin == "external"
                   and c.status in ("active", "pending") and succ is None,
        "replace": live and c.status in ("active", "pending") and succ is None,
        "csr": live and bool(c.csr_pem) and c.status == "awaiting_signature",
        "import_signed": live and c.status == "awaiting_signature",
        "deploy": live and c.status == "pending" and bool(c.cert_pem)
                  and bool(c.appliance_id) and not is_deployed(c),
        "swap": live and c.status in ("staged", "pending") and bool(c.supersedes_id)
                and is_deployed(c),
        "rollback": live and cm.can_rollback(c) == "",
        "revoke": live and c.status not in ("revoked", "awaiting_signature"),
        "delete": True,
    }


@bp.route("/lifecycle/run", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def lifecycle_run():
    """Apply the lifecycle policy NOW (manual sweep): revoke due superseded
    certs at the CA and delete due unbound material off the devices. Every
    destructive step re-verifies bindings live and fail-closed."""
    res = cm.run_lifecycle_sweep(dry_run=False, actor=current_user.username)
    done = (res["renewed"] + res["swapped"] + res["revoked"] + res["deleted"]
            + res["archived"])
    if done:
        flash("Lifecycle sweep: " + "; ".join(done), "success")
    else:
        flash("Lifecycle sweep: nothing applied.", "info")
    if res["notices"]:
        flash("Needs attention: " + "; ".join(res["notices"]), "warning")
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
    flash((f"Swapped {kind} onto {cert_name} on {a.name}.{_verdict_note(res)}" if res.get("ok")
           else f"Swap failed: {res.get('error')}"),
          "success" if res.get("ok") else "danger")
    return redirect(url_for("cert_manager.device_cert", store=store_label, name=cert_name))


def _verdict_note(res: dict) -> str:
    """`` (Verified on the device)`` / `` (Not verified: …)`` after a success
    message, when the write was re-read (the FortiADC REST paths); nothing
    otherwise. A mismatch never gets here: it is reported as the failure."""
    v = (res or {}).get("verify")
    return " (%s)" % v["label"] if isinstance(v, dict) and v.get("label") else ""


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
        flash(f"Removed {cert_name} from {a.name}.{_verdict_note(res)}", "success")
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
    """One form, three origins: signed by the configured CA, a CSR for another
    CA, or a certificate + key imported from outside."""
    if request.method == "POST":
        mode = (request.form.get("mode") or "signer").strip()
        appliance = db.session.get(Appliance, _int(request.form.get("appliance_id")))
        cert_class = (request.form.get("cert_class") or "server").strip()
        deploy = bool(request.form.get("deploy"))
        if appliance is None or not cm.supports_kind(appliance) or \
                appliance not in _deploy_targets():
            flash("Select a target FortiWeb or FortiADC.", "danger")
            return redirect(url_for("cert_manager.new", mode=mode))
        if mode == "import":
            data = _upload_bytes("bundle_file", "bundle_pem")
            if not data:
                flash("Paste the PEM certificate or upload a PEM / PKCS#12 file.", "danger")
                return redirect(url_for("cert_manager.new", mode=mode))
            res = cm.import_certificate(
                appliance, cert_class, data,
                key_pem=request.form.get("key_pem") or "",
                password=request.form.get("bundle_password") or "",
                deploy=deploy, actor=current_user.username)
            verb = "imported"
        else:
            cn = (request.form.get("cn") or "").strip()
            extra = [x.strip() for x in (request.form.get("extra_sans") or "")
                     .replace("\n", ",").split(",") if x.strip()]
            if mode == "external":
                res = cm.create_external_csr(appliance, cn, cert_class,
                                             extra_sans=extra,
                                             actor=current_user.username)
                verb = "CSR generated — download it, have it signed, then import the certificate"
            else:
                res = cm.create_certificate(appliance, cn, cert_class, extra_sans=extra,
                                            deploy=deploy, actor=current_user.username)
                verb = "created" + (" and deployed" if deploy else " (not deployed)")
        row = db.session.get(ManagedCertificate, res["cert_id"]) if res.get("cert_id") else None
        if row is not None:
            err = cm.apply_windows(row, _window_form())
            if err:
                flash(f"Rotation windows not saved: {err}", "warning")
            else:
                db.session.commit()
        if res.get("ok"):
            flash(f"Certificate {res.get('name')}: {verb}.", "success")
            return redirect(url_for("cert_manager.detail", id=res["cert_id"]))
        flash(f"Certificate not created: {res.get('error')}", "danger")
        if res.get("cert_id"):
            return redirect(url_for("cert_manager.detail", id=res["cert_id"]))
        return redirect(url_for("cert_manager.new", mode=mode))

    mode = request.args.get("mode") or "signer"
    return render_template(
        "cert_manager/new.html",
        mode=mode if mode in ("signer", "external", "import") else "signer",
        appliances=_deploy_targets(),
        classes=[(c, store.CERT_CLASS_LABELS[c]) for c in store.CERT_CLASSES],
        configured=store.cert_manager_configured(),
        protocol=store.cert_manager_protocol(),
        defaults={c: cm.default_policy(c) for c in store.CERT_CLASSES},
    )


def _window_form() -> dict:
    f = request.form
    out = {k: f.get(k, "") for k in cm.WINDOW_FIELDS}
    out["revoke_superseded"] = f.get("revoke_superseded", "")
    out["auto_renew"] = "1" if f.get("auto_renew") else "0"
    return out


def _upload_bytes(file_field: str, text_field: str) -> bytes:
    """A pasted PEM wins over nothing; an uploaded file wins over a paste."""
    fs = request.files.get(file_field)
    if fs is not None and fs.filename:
        data = fs.read(256 * 1024 + 1)
        if len(data) > 256 * 1024:
            return b""
        return data
    return (request.form.get(text_field) or "").encode()


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
    live_bindings = []
    policies = []
    if appliance and not cert.archived_at and cert.status != "awaiting_signature":
        live_bindings = cm.read_bindings_for(cert)
        if getattr(appliance, "kind", "fortiweb") != "fortiadc":
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
    from ..models import CertRevocation
    cert_detail = cert_probe.detail_from_pem(cert.cert_pem) if cert.cert_pem else None
    route, route_why = cm.revoke_route(cert)
    return render_template(
        "cert_manager/detail.html",
        cert=cert, appliance=appliance, events=events,
        live_bindings=live_bindings, policies=policies,
        class_label=store.CERT_CLASS_LABELS.get(cert.cert_class, cert.cert_class),
        origin_label=ORIGIN_LABELS.get(cert.origin, cert.origin),
        cert_detail=cert_detail, cert_pem=cert.cert_pem or "",
        policy=cm.cert_policy(cert), defaults=cm.default_policy(cert.cert_class),
        next=cm.next_step(cert), acts=actions_for(cert),
        predecessor=cm.predecessor_of(cert), successor=cm.successor_of(cert),
        rollback_why=cm.can_rollback(cert),
        revoke_route=route, revoke_route_why=route_why,
        reasons=CertRevocation.REASONS,
        revocations=(CertRevocation.query.filter_by(cert_id=cert.id)
                     .order_by(CertRevocation.requested_at.desc()).all()),
        tones=STATUS_TONES,
    )


@bp.route("/<int:id>/csr.pem")
@login_required
@require_permission(Permission.USER_MANAGE)
def csr_download(id):
    cert = ManagedCertificate.query.get_or_404(id)
    if not cert.csr_pem:
        flash("This certificate has no CSR stored.", "warning")
        return redirect(url_for("cert_manager.detail", id=id))
    log_action("certmgr.csr_download", target=cert.name)
    return Response(cert.csr_pem, mimetype="application/pkcs10",
                    headers={"Content-Disposition":
                             f'attachment; filename="{cert.name}.csr"'})


@bp.route("/<int:id>/import-signed", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def import_signed(id):
    cert = ManagedCertificate.query.get_or_404(id)
    data = _upload_bytes("signed_file", "signed_pem")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        flash("Import refused: only a PEM certificate is accepted here. The key of "
              "this request was generated in SATOM — a PKCS#12 would replace it.",
              "danger")
        return redirect(url_for("cert_manager.detail", id=id))
    res = cm.import_signed(cert, text, deploy=bool(request.form.get("deploy")),
                           actor=current_user.username)
    flash(f"Signed certificate imported into {cert.name}." if res.get("ok")
          else f"Import refused: {res.get('error')}",
          "success" if res.get("ok") else "danger")
    return redirect(url_for("cert_manager.detail", id=id))


@bp.route("/<int:id>/replace", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def replace(id):
    """Import a certificate + key made outside SATOM as the replacement of
    *id* (same staged swap as a renewal)."""
    cert = ManagedCertificate.query.get_or_404(id)
    data = _upload_bytes("bundle_file", "bundle_pem")
    if not data:
        flash("Paste the PEM certificate or upload a PEM / PKCS#12 file.", "danger")
        return redirect(url_for("cert_manager.detail", id=id))
    res = cm.import_certificate(
        db.session.get(Appliance, cert.appliance_id) if cert.appliance_id else None,
        cert.cert_class, data, key_pem=request.form.get("key_pem") or "",
        password=request.form.get("bundle_password") or "", supersedes=cert.id,
        deploy=True, actor=current_user.username)
    if res.get("ok"):
        flash(f"Replacement {res.get('name')} imported — it takes over on its swap date.",
              "success")
        return redirect(url_for("cert_manager.detail", id=res["cert_id"]))
    flash(f"Import refused: {res.get('error')}", "danger")
    return redirect(url_for("cert_manager.detail", id=id))


@bp.route("/<int:id>/renew", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def renew(id):
    cert = ManagedCertificate.query.get_or_404(id)
    res = cm.renew_certificate(cert, deploy=True, actor=current_user.username)
    if res.get("ok"):
        new = db.session.get(ManagedCertificate, res["cert_id"])
        if new is not None and new.status == "awaiting_signature":
            flash(f"New CSR {res.get('name')} generated — download it, have it signed "
                  "and import the certificate.", "success")
        elif new is not None and new.status == "staged":
            flash(f"Renewed → {res.get('name')}; it takes over the bindings of "
                  f"{cert.name} on {new.swap_due_at:%Y-%m-%d %H:%M} UTC.", "success")
        else:
            flash(f"Renewed → {res.get('name')}.", "success")
        return redirect(url_for("cert_manager.detail", id=res["cert_id"]))
    flash(f"Renew failed: {res.get('error')}", "danger")
    return redirect(url_for("cert_manager.detail", id=res.get("cert_id") or id))


@bp.route("/<int:id>/deploy", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def deploy(id):
    cert = ManagedCertificate.query.get_or_404(id)
    if not actions_for(cert)["deploy"]:
        flash("Nothing to deploy for this certificate.", "warning")
        return redirect(url_for("cert_manager.detail", id=id))
    err = cm._deploy(cert, cm._appliance_of(cert), actor=current_user.username)
    if not err:
        cm._schedule_swap(cert, cm.predecessor_of(cert))
    flash(err or f"{cert.name} deployed.", "danger" if err else "success")
    return redirect(url_for("cert_manager.detail", id=id))


@bp.route("/<int:id>/swap-now", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def swap_now(id):
    """Swap a renewal in NOW instead of on its date: every binding of the
    certificate it replaces moves onto it."""
    cert = ManagedCertificate.query.get_or_404(id)
    if not actions_for(cert)["swap"]:
        flash("This certificate has no deployed predecessor to take over from.", "warning")
        return redirect(url_for("cert_manager.detail", id=id))
    res = cm.perform_swap(cert, actor=current_user.username)
    if res.get("ok"):
        flash(f"{cert.name} took over: " + (", ".join(res.get("done") or [])
                                            or res.get("note") or "nothing was bound"),
              "success")
    else:
        flash(f"Swap not completed: {res.get('error')}", "danger")
    return redirect(url_for("cert_manager.detail", id=id))


@bp.route("/<int:id>/rollback", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def rollback(id):
    cert = ManagedCertificate.query.get_or_404(id)
    res = cm.rollback(cert, actor=current_user.username)
    flash((f"Rolled back: {cm.predecessor_of(cert).name} serves "
           + ", ".join(res.get("done") or []) + " again.") if res.get("ok")
          else f"Rollback not completed: {res.get('error')}",
          "success" if res.get("ok") else "danger")
    return redirect(url_for("cert_manager.detail", id=id))


@bp.route("/<int:id>/windows", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def windows(id):
    cert = ManagedCertificate.query.get_or_404(id)
    err = cm.apply_windows(cert, _window_form())
    if err:
        db.session.rollback()
        flash(f"Not saved: {err}", "danger")
    else:
        db.session.commit()
        log_action("certmgr.windows", target=cert.name,
                   detail=" ".join(f"{k}={getattr(cert, k)}" for k in
                                   cm.WINDOW_FIELDS + ("revoke_superseded", "auto_renew")))
        flash("Rotation settings saved.", "success")
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
    res = cm.revoke_certificate(cert, reason=(request.form.get("reason") or "unspecified"),
                                delete_from_box=delete_from_box,
                                allow_bound=bool(request.form.get("allow_bound")),
                                actor=current_user.username)
    if res.get("in_use"):
        flash(f"Not revoked — {res.get('error')}. To revoke a certificate in use "
              "(e.g. a compromised key), tick \u201crevoke even though it is in use\u201d "
              "on its page.", "warning")
        return redirect(url_for("cert_manager.detail", id=id))
    if not res.get("revoked"):
        flash(f"Not revoked: {res.get('error')}", "danger")
    elif res.get("error"):
        flash(f"Revoked, but NOT removed from the device: {res['error']}", "warning")
    elif res.get("manual"):
        flash(f"{cert.name} marked revoked — {res.get('manual_reason')}. It is in the "
              "revocation register as pending until you confirm it.", "warning")
    else:
        flash(f"Certificate {cert.name} revoked at the CA"
              + (" and removed from the device." if delete_from_box else "."), "success")
    return redirect(url_for("cert_manager.detail", id=id))


@bp.route("/<int:id>/delete", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def delete(id):
    cert = ManagedCertificate.query.get_or_404(id)
    res = cm.delete_record(cert, revoke_first=bool(request.form.get("revoke_first")),
                           reason=(request.form.get("reason") or "cessationOfOperation"),
                           remove_from_box=bool(request.form.get("remove_from_box")),
                           actor=current_user.username)
    if not res.get("ok"):
        flash(f"Not deleted: {res.get('error')}", "danger")
        return redirect(url_for("cert_manager.detail", id=id))
    flash(f"Removed certificate record {res['name']}"
          + (" (the device copy is untouched)." if res.get("left_on_device") else "."),
          "success")
    return redirect(url_for("cert_manager.index"))


@bp.route("/revocations/<int:rid>/confirm", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def revocation_confirm(rid):
    from ..models import CertRevocation
    rev = CertRevocation.query.get_or_404(rid)
    res = cm.confirm_manual_revocation(rev, actor=current_user.username)
    flash(f"Revocation of {rev.cert_name} confirmed at the CA." if res.get("ok")
          else res.get("error"), "success" if res.get("ok") else "warning")
    nxt = request.form.get("next") or ""
    if nxt.startswith("/") and not nxt.startswith("//"):
        return redirect(nxt)
    return redirect(url_for("cert_manager.index") + "#revocations")


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Renewals — why a renewal did (or did not) happen, with the error text
# ---------------------------------------------------------------------------
@bp.route("/renewals")
@login_required
@require_permission(Permission.USER_MANAGE)
def renewals():
    """The renewal journal for BOTH nodes plus the appliance-certificate
    failures, so an operator never has to read journalctl to find out why a
    certificate was not renewed. Complements the alert e-mail: the mail says
    'something is wrong', this page says WHAT and shows the exact error."""
    from ..services import cert_renew_log as jrn

    # Durability pass. The journal is node-local by design, so the PRIMARY pulls
    # the peer's copy into data/ (which it owns — the datasync propagates the
    # primary's data/ to the standby, it does not delete it). Throttled and
    # inert on a standby; a failure here must never 500 the page it explains.
    try:
        refresh = jrn.archive_refresh()
    except Exception as exc:  # noqa: BLE001
        refresh = {"role": "unknown", "skipped": "error",
                   "error": "%s: %s" % (type(exc).__name__, exc), "results": []}

    nodes = jrn.fleet_view(limit=150)
    archive_alerts = jrn.durability_alerts(nodes, role=refresh.get("role") or "")

    # Appliance / ACME certificates: the failed lifecycle events (sign, deploy,
    # renew, revoke). Same question, different pipeline — one page for both.
    dev_failures = []
    try:
        rows = (db.session.query(ManagedCertificateEvent, ManagedCertificate)
                .join(ManagedCertificate,
                      ManagedCertificate.id == ManagedCertificateEvent.cert_id)
                .filter(ManagedCertificateEvent.ok.is_(False))
                .order_by(ManagedCertificateEvent.ts.desc())
                .limit(100).all())
        for ev, cert in rows:
            dev_failures.append({"ts": ev.ts, "kind": ev.kind, "by": ev.by,
                                 "detail": ev.detail or "", "cert_id": cert.id,
                                 "cert_name": cert.name, "cn": cert.subject or ""})
    except Exception as exc:  # noqa: BLE001 — a broken query must not 500 the page
        db.session.rollback()
        dev_failures = []
        flash("Could not read appliance certificate events: %s" % exc, "warning")

    return render_template("cert_manager/renewals.html",
                           nodes=nodes, dev_failures=dev_failures,
                           archive_alerts=archive_alerts,
                           archive_retention=jrn.retention_policy())


@bp.route("/renewals/durability.json")
@login_required
@require_permission(Permission.USER_MANAGE)
def renewals_durability():
    """Per-node durability of the renewal journal, as JSON.

    Answers the three questions the live journal cannot: how much archived
    history survives this node's disk, when the archive was last refreshed from
    each node, and — when it could not be — since when. ``?force=1`` bypasses the
    pull throttle so an operator can prove the channel works right now.
    """
    from ..services import cert_renew_log as jrn
    force = (request.args.get("force") or "").strip() in ("1", "true", "yes")
    try:
        refresh = jrn.archive_refresh(force=force)
    except Exception as exc:  # noqa: BLE001
        refresh = {"role": "unknown", "skipped": "error",
                   "error": "%s: %s" % (type(exc).__name__, exc), "results": []}
    nodes = []
    for n in jrn.fleet_view(limit=150):
        nodes.append({"name": n.get("name"), "host": n.get("host"),
                      "is_self": n.get("is_self"), "reachable": n.get("reachable"),
                      "live_runs": len(n.get("runs") or []),
                      "archived_runs": len(n.get("archived") or []),
                      "archive": n.get("archive") or {}})
    return jsonify({"ok": True, "role": refresh.get("role"),
                    "refresh": refresh, "nodes": nodes,
                    "retention": jrn.retention_policy(),
                    "alerts": jrn.durability_alerts(
                        [{"name": n["name"], "archive": n["archive"]} for n in nodes],
                        role=refresh.get("role") or "")})


@bp.route("/renewals/run", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def renewals_run():
    """Run the same pass the nightly timer runs, on THIS node, now. Exists so an
    operator can prove the pipeline works instead of waiting for 03:30 — and so a
    misconfiguration shows up as a journal row immediately."""
    from ..services import cert_service as cs
    from ..services import cert_renew_log as jrn
    who = getattr(current_user, "username", "") or "operator"
    try:
        res = cs.renew_if_needed(by="manual:%s" % who)
        msg = "renew: %s" % (res.get("reason") or ("renewed, %s d left" % res.get("days_left")))
    except Exception as exc:  # noqa: BLE001 — already journaled by the service
        msg = "renew failed: %s" % exc
    try:
        if cs.renew_mode() == "autopull":
            r2 = cs.autopull(by="manual:%s" % who)
            msg += " | autopull: %s" % (r2.get("reason") or "pulled + installed")
    except Exception as exc:  # noqa: BLE001
        jrn.record(jrn.CH_TIMER, jrn.OK_ERROR, "manual renewal pass aborted",
                   error="%s: %s" % (type(exc).__name__, exc), by=who)
        msg += " | autopull failed: %s" % exc
    log_action("certmgr.renewals.run", target=msg[:190])
    flash("Renewal pass finished — %s" % msg, "info")
    return redirect(url_for("cert_manager.renewals"))
