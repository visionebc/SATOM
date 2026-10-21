"""/api/v1/system — CPU, memory and disk of the SATOM nodes themselves.

* ``GET /api/v1/system/nodes``          — every node now: graded readings
* ``GET /api/v1/system/nodes/history``  — the same readings over time
  (``?range=1h|6h|24h|7d|30d|90d``, ``?node=<name>``, ``?metrics=cpu,mem,...``)

The same data as SATOM health (Global ADOM) -> node tiles and Resource
history, for an outside monitoring system. Three gates:

* the ``read`` scope (nothing here writes);
* a token bound to the **global** ADOM: the page is Global-only because node
  names describe the installation, and a FortiWeb-bound token must not reach
  what a FortiWeb-ADOM session cannot;
* a token restricted to named capabilities must hold ``monitoring``. An empty
  list keeps the permissive read default every other ``GET`` here has.

Node addresses are not in the answer: an inventory feed has no use for the
management IPs of the manager, and leaking them is what Global-only exists to
prevent.
"""
from __future__ import annotations

from flask import g, jsonify, request

from ..extensions import limiter
from . import bp
from .auth import _err, token_required


def _gate():
    tok = g.api_token
    if (tok.product or "global") != "global":
        return _err(403, "wrong_product",
                    "Node resources describe the SATOM installation; they need "
                    "a token bound to the 'global' ADOM.")
    caps = tok.capability_list
    if caps and "monitoring" not in caps:
        return _err(403, "capability_denied",
                    "This token is restricted to named capabilities and does "
                    "not hold 'monitoring'.")
    return None


@bp.route("/system/nodes", methods=["GET"])
@limiter.limit("60 per minute")
@token_required("read")
def system_nodes():
    denied = _gate()
    if denied is not None:
        return denied
    from ..services import node_metrics
    return jsonify(node_metrics.snapshot())


@bp.route("/system/nodes/history", methods=["GET"])
@limiter.limit("60 per minute")
@token_required("read")
def system_nodes_history():
    denied = _gate()
    if denied is not None:
        return denied
    from ..services import node_metrics
    try:
        out = node_metrics.history(request.args.get("range"),
                                   node=request.args.get("node"),
                                   metrics=request.args.get("metrics"))
    except ValueError as exc:
        return _err(400, "bad_request", str(exc))
    if not out["ok"]:
        # The store did not answer: say so with a 502, never a 200 with empty
        # series that a poller would record as "no load".
        resp = jsonify(dict(out, error="store_unavailable"))
        resp.status_code = 502
        return resp
    return jsonify(out)
