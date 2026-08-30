"""ADOM → Administration → *Stored Assets*: what this ADOM HOLDS.

Deliberately separate from Settings. The knobs — how much SoT payload stays
local, how many bundles stay on the node, where the backup server is — are one
console-wide configuration and live in the admin console. What each ADOM
*holds* is per-ADOM data an operator reads while working inside that ADOM, and
putting the two on the same page is how a retention field ends up being edited
by somebody who came to check a backup date.

Read-mostly. The one destructive action is deleting a single config backup off
the server, and it is deliberately narrow: an exact filename, an explicit
confirmation, an audit entry naming the device and the size. There is no
"delete everything older than" button — the appliances author those files, and
a bulk delete of somebody else's artefacts is not a thing this page should be
able to do by accident.
"""
from __future__ import annotations

from flask import (Blueprint, flash, redirect, render_template, request,
                   url_for, jsonify)
from flask_login import login_required

from ..auth.decorators import require_permission
from ..models import Permission
from ..services import adom_assets as assets_svc
from ..services.audit import log_action

bp = Blueprint("adom_assets", __name__, url_prefix="/adom-assets")


def _scope() -> str:
    """The ADOM this request is about.

    ``global`` is the console scope, not a device family, so it means "every
    ADOM" — which is also the only view where the unclaimed folders and the
    unassigned SoT devices can be shown, because they belong to no family by
    definition.
    """
    from ..branding import get_product
    key = (get_product(None) or {}).get("key") or ""
    return "" if key in ("", "global") else key


@bp.route("/")
@login_required
@require_permission(Permission.USER_MANAGE)
def index():
    product = _scope()
    data = assets_svc.collect(product)
    return render_template("adom_assets/index.html", data=data,
                           product_key=product)


@bp.route("/refresh-identity", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def refresh_identity():
    """Make sure every appliance and every remembered device has an identity
    row, and stamp the ADOM onto SoT versions recorded before the column
    existed. Idempotent — safe to press twice."""
    from ..services import device_identity, sot_store
    ident = device_identity.reconcile()
    stamped = sot_store.backfill_products()
    log_action("adom_assets.reconcile",
               detail=f"created={ident['created']} adopted={ident['adopted']} "
                      f"sot_stamped={stamped['stamped']} "
                      f"unresolved={stamped['unresolved']}")
    flash('Identity reconciled: %d new record(s), %d adopted from history. '
          'SoT: %d version(s) filed under an ADOM, %d device(s) still '
          'unidentified.'
          % (ident["created"], ident["adopted"], stamped["stamped"],
             stamped["unresolved"]), "success")
    return redirect(url_for("adom_assets.index"))


@bp.route("/files")
@login_required
@require_permission(Permission.USER_MANAGE)
def files():
    """Full listing of one device's folder (the table shows a summary)."""
    from ..services import backup_server
    return jsonify(backup_server.device_files(request.args.get("device", "")))


@bp.route("/delete-backup", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def delete_backup():
    from ..services import backup_server
    device = (request.form.get("device") or "").strip()
    filename = (request.form.get("filename") or "").strip()
    if request.form.get("confirm") != "DELETE":
        flash("Not confirmed — type DELETE to remove a backup from the server.",
              "warning")
        return redirect(url_for("adom_assets.index"))
    res = backup_server.delete_device_file(device, filename)
    # Audited on failure too: an attempt to destroy an appliance's artefact is
    # worth a line whether or not it succeeded.
    log_action("adom_assets.delete_backup",
               detail=f"device={device!r} file={filename!r} "
                      f"ok={res.get('ok')} {str(res.get('detail',''))[:160]}")
    flash(res.get("detail", ""), "success" if res.get("ok") else "danger")
    return redirect(url_for("adom_assets.index"))
