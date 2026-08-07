"""Monitoring → Collection — the fleet metrics collection control panel.

This page answers the operator's cadence question directly: every scrape
target (device x collector) with its OWN editable interval, plus the health
of the local VictoriaMetrics store. It exists because a probe row's declared
interval already lied once (the 5-under-3 cadence lesson): collection policy
must be visible and editable in one place, not implied by code.

Reads are DB + loopback VM only — a page load never touches an appliance.
``/peer/*`` is the only exception and is deliberately NOT reached from a render:
``/stores`` does cross-node I/O and is fetched after the page, the same contract
the infra-health card keeps.

The two ``/peer`` routes are the RECEIVING half of the metrics dual-write. They
carry no session: the caller is the other HA node, identified by the shared
``X-FM-Node-Key``. They fail CLOSED when no identity key is configured — the
store behind them has no authentication of its own, so an un-keyed node
accepting writes would be a fleet-wide open write port, which is exactly what
the loopback bind exists to prevent.
"""
from __future__ import annotations

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import login_required

from ..auth.decorators import require_permission
from ..extensions import csrf
from ..models import db, visible_appliances

bp = Blueprint("metrics_admin", __name__, url_prefix="/monitoring/collection")


def _visible_targets():
    from ..models_metrics import ScrapeTarget
    visible = {a.id for a in visible_appliances().all()}
    rows = ScrapeTarget.query.all()
    return [t for t in rows if t.appliance_id in visible]


@bp.route("/")
@login_required
def index():
    from ..services import metrics_collect as mc
    from ..services import vm_store
    targets = sorted(_visible_targets(),
                     key=lambda t: ((t.appliance.name if t.appliance else ""),
                                    t.collector))
    return render_template(
        "monitoring/collection.html",
        targets=[t.to_dict() for t in targets],
        collectors=mc.COLLECTORS,
        gaps=mc.coverage_gaps(visible_appliances().all()),
        vm=vm_store.health(),
        # Local journal read only — no peer I/O on a render. The cross-node
        # picture is /stores, fetched after the page.
        peer=mc.peer_health(),
    )


@bp.route("/data")
@login_required
def data():
    from ..services import metrics_collect as mc
    from ..services import vm_store
    targets = sorted(_visible_targets(),
                     key=lambda t: ((t.appliance.name if t.appliance else ""),
                                    t.collector))
    return jsonify({"targets": [t.to_dict() for t in targets],
                    "gaps": mc.coverage_gaps(visible_appliances().all()),
                    "vm": vm_store.health(),
                    "peer": mc.peer_health()})


@bp.route("/target/<int:tid>", methods=["POST"])
@login_required
@require_permission("config_write")
def update_target(tid):
    from ..models_metrics import ScrapeTarget
    from ..services import audit
    t = ScrapeTarget.query.get_or_404(tid)
    if t.appliance_id not in {a.id for a in visible_appliances().all()}:
        return jsonify({"ok": False, "error": "not visible in this ADOM"}), 404
    changed = []
    if "interval_min" in request.form:
        try:
            iv = max(1, min(1440, int(request.form["interval_min"])))
        except ValueError:
            return jsonify({"ok": False, "error": "bad interval"}), 400
        if iv != t.interval_min:
            t.interval_min = iv
            changed.append("interval=%d" % iv)
    if "enabled" in request.form:
        en = request.form["enabled"] in ("1", "true", "on")
        if en != bool(t.enabled):
            t.enabled = en
            changed.append("enabled" if en else "disabled")
    if "top_n" in request.form:
        try:
            n = max(1, min(200, int(request.form["top_n"])))
        except ValueError:
            return jsonify({"ok": False, "error": "bad top_n"}), 400
        p = t.params
        if p.get("top_n") != n:
            p["top_n"] = n
            t.params = p
            changed.append("top_n=%d" % n)
    db.session.commit()
    if changed:
        audit.log_action("metrics_target_update",
                         "%s/%s" % (t.appliance.name if t.appliance else t.appliance_id,
                                    t.collector),
                         {"changes": changed})
    if request.form.get("_redirect"):
        flash("Target %s/%s: %s" % (t.appliance.name if t.appliance else "?",
                                    t.collector,
                                    ", ".join(changed) or "no change"),
              "success")
        return redirect(url_for("metrics_admin.index"))
    return jsonify({"ok": True, "target": t.to_dict(), "changed": changed})


@bp.route("/run", methods=["POST"])
@login_required
@require_permission("config_write")
def run_now():
    """Run the sweep in the foreground of this request — the operator asked
    for it and expects the outcome in the flash, same as probe discovery."""
    from ..services import metrics_collect as mc
    res = mc.sweep()
    flash("Scrape sweep: %(ok)d/%(targets)d ok, %(errors)d error(s), "
          "%(series)d series in %(ms)d ms" % res,
          "success" if not res["errors"] else "warning")
    # A half-written sweep must not read as a clean one: the local store having
    # the samples says nothing about whether the peer does.
    peer = res.get("peer") or {}
    if peer.get("alarm"):
        flash("Peer dual-write %s — %d consecutive failure(s), last success %s"
              % (peer.get("state"), peer.get("consecutive_failures") or 0,
                 peer.get("last_success_at") or "never"), "warning")
    return redirect(url_for("metrics_admin.index"))


# ── cross-node view (network I/O — never called from a render) ───────────────

@bp.route("/stores")
@login_required
def stores():
    """Per-node store state: reachable? how many series? last write? This is
    what tells the operator whether the pair is ACTUALLY redundant or only
    claims to be — 'no peer configured' and 'peer unreachable' come back as
    different states on purpose."""
    from ..services import metrics_collect as mc
    return jsonify({"nodes": mc.stores_report(), "peer": mc.peer_health()})


# ── receiving half of the dual-write (peer → this node) ──────────────────────

def _peer_gate():
    """None when the caller is the trusted peer, else a ready-made response.

    Fails CLOSED on an unconfigured identity key: 503, not 200. The alternative
    is a node that accepts anonymous writes into an unauthenticated TSDB.
    """
    from ..services import node_security as nsec
    verdict = nsec.verify_request(request.headers)
    if verdict is None:
        return jsonify({"ok": False,
                        "error": "node identity key not configured"}), 503
    if not verdict:
        return jsonify({"ok": False, "error": "bad node key"}), 403
    return None


#: Guard rail on the receiving side. A peer scrape is a few hundred lines; a
#: multi-megabyte body is not a scrape.
MAX_INGEST_BYTES = 4 * 1024 * 1024


@bp.route("/peer/ingest", methods=["POST"])
@csrf.exempt
def peer_ingest():
    """Accept the peer node's mirrored samples into THIS node's store.

    This is the whole point of the dual-write: both nodes independently hold a
    complete series, so a promote inherits history instead of an empty store —
    without rsyncing a live TSDB and without an 8 GB backup bundle.
    """
    denied = _peer_gate()
    if denied is not None:
        return denied
    from ..services import vm_store
    raw = request.get_data(cache=False)
    if len(raw) > MAX_INGEST_BYTES:
        return jsonify({"ok": False, "error": "body too large"}), 413
    lines = [l for l in raw.decode("utf-8", "replace").splitlines() if l.strip()]
    if not lines:
        return jsonify({"ok": True, "count": 0}), 200
    res = vm_store.ingest(lines)
    if not res["ok"]:
        # Answer with the failure, do not absorb it: the writer's whole
        # failure counter depends on this status being honest.
        return jsonify({"ok": False, "error": res["detail"]}), 502
    return jsonify({"ok": True, "count": res["count"]}), 200


@bp.route("/peer/store")
@csrf.exempt
def peer_store():
    """Publish THIS node's store state so the peer can render both halves of
    the pair — the same peer-probe pattern as /healthz/backups."""
    denied = _peer_gate()
    if denied is not None:
        return denied
    from ..services import metrics_collect as mc
    return jsonify({"ok": True, "store": mc.local_store_report()}), 200


# ── consistent hot snapshot of the local store ───────────────────────────────

@bp.route("/snapshot", methods=["POST"])
@login_required
@require_permission("config_write")
def snapshot():
    """Take a hot snapshot (hardlink tree — instant, near-free) of the local
    store. Nothing expires these: the unit carries no ``-snapshotsMaxAge``, so
    the list is shown next to the trigger and deletion is explicit."""
    from ..services import audit
    from ..services import metrics_collect as mc
    if request.form.get("delete"):
        res = mc.snapshot_delete(request.form["delete"])
        flash("Snapshot deleted" if res["ok"] else
              "Snapshot delete failed: %s" % res["detail"],
              "success" if res["ok"] else "danger")
    else:
        res = mc.snapshot_create()
        audit.log_action("metrics_snapshot", res.get("snapshot") or "-",
                         {"ok": res["ok"], "detail": res.get("detail", "")})
        flash("Snapshot %s" % res["snapshot"] if res["ok"] else
              "Snapshot failed: %s" % res["detail"],
              "success" if res["ok"] else "danger")
    return redirect(url_for("metrics_admin.index"))


@bp.route("/snapshots")
@login_required
def snapshots():
    from ..services import metrics_collect as mc
    return jsonify(mc.snapshot_list())
