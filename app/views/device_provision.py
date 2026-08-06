"""Device provisioning — build an appliance machine from nothing.

Distinct from ``app/views/provisioning.py``, which is the *configuration*
provisioner (SystemProfile -> registry endpoints, with dry-run, canary and
approval). That module is the LAST step of this pipeline; this one gets a
machine to the point where that module has something to talk to.

**Scoping.** A run is stamped with the ADOM it was created in and every query
filters on it, on the QUERY rather than in the template: a row hidden by a
template is still a row the page fetched, and the JSON feeds would return it.
The product also decides what kind of appliance gets registered at the end, so
a run that could re-label its own ADOM would let a FortiADC session build a
FortiWeb and file it under FortiWeb.

**Availability.** With no hypervisor registered the machine-creation modes are
not offered at all — not offered as buttons that fail. The address / DNS /
certificate / profile half still works against a machine built by hand
(``config_only``), so the page stays useful either way.
"""
from __future__ import annotations

from flask import (Blueprint, abort, flash, g, jsonify, redirect,
                   render_template, request, url_for)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Permission, db
from ..services import product_scope
from ..services.audit import log_action

# NOT mounted under /provisioning: the legacy-URL shim in create_app
# rewrites every path beginning with /provisioning onto /web/... for the
# 2026-07-07 ADOM split, so a route there would be redirected to a URL
# that does not exist. The prefix is deliberately its own.
bp = Blueprint("device_provision", __name__,
               url_prefix="/device-provisioning")


def _runs_query():
    from ..models_provision import ProvisionRun
    q = ProvisionRun.query
    return product_scope.scope_query(q, ProvisionRun.product)


def _run_or_404(run_id: int):
    """Fetch a run, refusing one that belongs to a different ADOM.

    404 rather than 403 on purpose: from this ADOM the run does not exist.
    Answering 403 would confirm that a run with that id exists elsewhere.
    """
    from ..models_provision import ProvisionRun
    row = ProvisionRun.query.get(run_id)
    if row is None or not product_scope.visible_product(row.product):
        abort(404)
    return row


def _available_targets():
    from ..services.hypervisors import configured_targets
    try:
        return configured_targets()
    except Exception:  # noqa: BLE001 — table missing on a very old node
        return []


@bp.route("/")
@login_required
def index():
    from ..models_provision import MODES, ProvisionRun
    from ..services.provision_runner import MODE_STEPS, MODE_STOP_REASON
    targets = _available_targets()
    runs = _runs_query().order_by(ProvisionRun.created_at.desc()).limit(50).all()

    # With no hypervisor, the modes that build a machine are not offered. The
    # operator sees why, and the one mode that still works stays available.
    if targets:
        modes = MODES
    else:
        modes = {"config_only": MODES["config_only"]}

    fw = []
    try:
        from ..models_firmware import FirmwareImage
        fq = FirmwareImage.query.filter(FirmwareImage.image_kind == "install")
        adom = getattr(g, "product", None)
        if adom and adom in product_scope.concrete_products():
            fq = fq.filter(FirmwareImage.product == adom)
        fw = fq.order_by(FirmwareImage.uploaded_at.desc()).limit(50).all()
    except Exception:  # noqa: BLE001 — firmware split may predate this node
        fw = []

    return render_template(
        "provisioning/device_index.html",
        runs=runs, targets=targets, modes=modes, mode_steps=MODE_STEPS,
        mode_stop=MODE_STOP_REASON, install_images=fw,
        has_hypervisor=bool(targets),
        adom=getattr(g, "product", "") or "global",
        kind_options=product_scope.device_products(),
    )


@bp.route("/data")
@login_required
def data():
    from ..models_provision import ProvisionRun
    runs = _runs_query().order_by(ProvisionRun.created_at.desc()).limit(50).all()
    return jsonify({
        "scope": getattr(g, "product", "") or "global",
        "runs": [r.public() for r in runs],
        "has_hypervisor": bool(_available_targets()),
    })


@bp.route("/new", methods=["POST"])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def create():
    from ..models_provision import MODES, ProvisionRun
    f = request.form
    name = (f.get("name") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "a machine name is required"}), 400
    mode = (f.get("mode") or "semi").strip()
    if mode not in MODES:
        return jsonify({"ok": False, "error": "unknown mode %r" % mode}), 400

    product = product_scope.stamp()
    if not product:
        # Global has no single answer for "what kind of appliance is this?".
        product = (f.get("product") or "").strip().lower()
        if product not in product_scope.concrete_products():
            return jsonify({
                "ok": False,
                "error": "pick the product this appliance will be",
                "detail": "A run started from the Global ADOM has to say which "
                          "product it is building, because that decides what "
                          "kind of appliance gets registered at the end."}), 400

    targets = {t.id for t in _available_targets()}
    tid = f.get("target_id") or ""
    target_id = int(tid) if tid.isdigit() and int(tid) in targets else None
    if mode != "config_only" and target_id is None:
        return jsonify({
            "ok": False,
            "error": "that mode needs a hypervisor",
            "detail": "Register one in Settings > Hypervisors, or use "
                      "'Config only' against a machine that already exists."}), 400

    run = ProvisionRun(
        product=product, name=name, mode=mode, target_id=target_id,
        created_by=getattr(current_user, "username", "") or "")
    run.hostname = (f.get("hostname") or "").strip()
    run.mgmt_ip = (f.get("mgmt_ip") or "").strip()
    run.netmask = (f.get("netmask") or "").strip()
    run.gateway = (f.get("gateway") or "").strip()
    run.node = (f.get("node") or "").strip()
    run.datastore = (f.get("datastore") or "").strip()
    run.network = (f.get("network") or "").strip()
    run.admin_user = (f.get("admin_user") or "admin").strip()
    if f.get("admin_password"):
        run.admin_password = f.get("admin_password")
    for attr, key, default in (("cpus", "cpus", 4),
                               ("memory_mb", "memory_mb", 4096),
                               ("disk_gb", "disk_gb", 0)):
        try:
            setattr(run, attr, int(f.get(key) or default))
        except ValueError:
            setattr(run, attr, default)
    for attr, key in (("firmware_id", "firmware_id"),
                      ("profile_id", "profile_id")):
        v = f.get(key) or ""
        setattr(run, attr, int(v) if str(v).isdigit() else None)
    # IPAM is opt-in per run: only then is the address ours to release on
    # rollback. A hand-typed address belongs to whoever typed it.
    run.ip_from_ipam = (f.get("use_ipam") or "").lower() in ("1", "on", "true")
    db.session.add(run)
    db.session.commit()
    log_action("provision.device.create",
               detail="name=%s mode=%s product=%s" % (name, mode, product))
    return jsonify({"ok": True, "run": run.public()})


@bp.route("/<int:run_id>/preflight", methods=["POST"])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def preflight(run_id: int):
    """Inspect only. Changes nothing — safe to press at any time."""
    from ..services.provision_runner import preflight as _pf
    run = _run_or_404(run_id)
    return jsonify({"ok": True, "preflight": _pf(run), "run": run.public()})


@bp.route("/<int:run_id>/advance", methods=["POST"])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def advance(run_id: int):
    """Run the pipeline. Refuses to start when preflight says it cannot finish.

    Checking first is the whole point: a run that dies at machine creation
    after reserving an address and writing a DNS row leaves three systems to
    clean up by hand.
    """
    from ..services.provision_runner import advance as _adv, preflight as _pf
    run = _run_or_404(run_id)
    if run.status in ("done", "aborted"):
        return jsonify({"ok": False,
                        "error": "this run is finished"}), 409
    pf = _pf(run)
    if not pf["ok"]:
        return jsonify({"ok": False,
                        "error": "preflight refused this run",
                        "blockers": pf["blockers"]}), 409
    _adv(run)
    log_action("provision.device.advance",
               detail="run=%s step=%s status=%s" % (run.id, run.step, run.status))
    return jsonify({"ok": True, "run": run.public()})


@bp.route("/<int:run_id>/rollback", methods=["POST"])
@login_required
@require_permission(Permission.CONFIG_WRITE)
def rollback(run_id: int):
    from ..services.provision_runner import rollback as _rb
    run = _run_or_404(run_id)
    _rb(run)
    log_action("provision.device.rollback",
               detail="run=%s error=%s" % (run.id, run.error))
    return jsonify({"ok": True, "run": run.public()})


@bp.route("/<int:run_id>")
@login_required
def detail(run_id: int):
    from ..services.provision_runner import MODE_STEPS
    run = _run_or_404(run_id)
    from ..models_provision import STEPS
    return render_template("provisioning/device_detail.html", run=run,
                           steps=STEPS,
                           plan=MODE_STEPS.get(run.mode, ()),
                           adom=getattr(g, "product", "") or "global")
