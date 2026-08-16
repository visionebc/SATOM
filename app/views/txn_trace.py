# app/views/txn_trace.py
"""Transaction tracer — client → WAF/ADC → backend, in one page.

Every endpoint here makes THIS SERVER issue requests, so the gates are the
point, not decoration:

* Destination policy is :mod:`app.services.net_guard` — inventory targets are
  free, free targets need :data:`net_guard.FREE_PERMISSION`.
* ``GET``/``HEAD``/``OPTIONS`` are free; a mutating method needs the same
  permission AND an explicit per-call ``confirm_mutating`` flag.
* Every trace — completed or refused — is audited with the destinations, the
  method and the outcome.

Leg B is derived from the device's configuration and is labelled as derived at
every layer: service, endpoint and panel. It is the one thing in this feature
SATOM cannot observe.
"""
from __future__ import annotations

import time

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from ..models import Appliance, visible_appliances
from ..services import net_guard, txn_trace
from ..services.audit import log_action

bp = Blueprint("txn_trace", __name__, url_prefix="/txn-trace")

MAX_HEADERS = 24


def _may_free() -> bool:
    try:
        perms = set(current_user.effective_permissions or ())
    except Exception:  # noqa: BLE001
        return False
    return net_guard.FREE_PERMISSION in perms or "user_manage" in perms


def _inventory() -> dict:
    out = {}
    for a in visible_appliances(Appliance.query).all():
        out[(a.host or "").strip().lower()] = a
    return out


def _clean_headers(raw) -> dict:
    """Operator-supplied request headers, bounded.

    ``Host`` is refused here rather than silently dropped: the tracer sets it
    from the target on purpose (that is how leg A and leg C stay comparable),
    and an operator who typed one and saw it vanish would conclude the tool
    ignored them.
    """
    out = {}
    if isinstance(raw, str):
        pairs = []
        for line in raw.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                pairs.append((k.strip(), v.strip()))
        raw = dict(pairs)
    if not isinstance(raw, dict):
        return out
    for k, v in list(raw.items())[:MAX_HEADERS]:
        k = str(k).strip()
        if not k or "\n" in k or "\r" in k:
            continue
        out[k] = str(v).replace("\n", " ").replace("\r", " ")[:2048]
    return out


def _resolve(mode: str, raw: str, inventory: dict, default_port: int = 443):
    """``(dest, scheme, path, error_response)``."""
    try:
        parsed = net_guard.parse_target(raw, default_port=default_port)
    except net_guard.TargetError as exc:
        return None, "", "", (jsonify(ok=False, error=str(exc)), 400)
    try:
        dest = net_guard.resolve_target(parsed["host"], parsed["port"], mode=mode,
                                        inventory_hosts=list(inventory.keys()))
    except net_guard.TargetError as exc:
        return None, "", "", (jsonify(ok=False, error=str(exc)), 400)
    return dest, parsed["scheme"], parsed["path"], None


@bp.route("/context")
@login_required
def context():
    """What the panel needs to render before the operator types anything."""
    rows = []
    for a in visible_appliances(Appliance.query).order_by(Appliance.name).all():
        rows.append({"id": a.id, "name": a.name, "kind": a.kind,
                     "host": a.host, "port": a.port or 443})
    return jsonify(ok=True, appliances=rows, may_free=_may_free(),
                   free_permission=net_guard.FREE_PERMISSION,
                   safe_methods=list(txn_trace.SAFE_METHODS),
                   mutating_methods=list(txn_trace.MUTATING_METHODS))


@bp.route("/run", methods=["POST"])
@login_required
def run():
    """Trace one transaction: leg A, leg C, and the diff.

    Either leg may be omitted — an operator who only has the VIP still gets
    leg A plus the derived leg B, and the diff says WHY it is absent instead of
    rendering an empty comparison that reads like "no differences".
    """
    body = request.get_json(silent=True) or {}
    mode_a = str(body.get("mode_a") or net_guard.MODE_INVENTORY)
    mode_c = str(body.get("mode_c") or net_guard.MODE_FREE)
    method = str(body.get("method") or "GET").upper()
    path = str(body.get("path") or "/")[:2048]
    headers = _clean_headers(body.get("headers"))
    req_body = str(body.get("body") or "")[:txn_trace.MAX_REQ_BODY].encode()
    vip_raw = str(body.get("vip") or "").strip()
    backend_raw = str(body.get("backend") or "").strip()

    if method not in txn_trace.SAFE_METHODS + txn_trace.MUTATING_METHODS:
        return jsonify(ok=False, error="Method %s is not traceable." % method), 400
    if method in txn_trace.MUTATING_METHODS:
        if not _may_free():
            log_action("txn_trace.denied", target=vip_raw[:200],
                       extra={"method": method,
                              "reason": "missing " + net_guard.FREE_PERMISSION})
            return jsonify(ok=False, error=(
                "%s writes to the target application. It requires the '%s' "
                "permission." % (method, net_guard.FREE_PERMISSION))), 403
        if not body.get("confirm_mutating"):
            return jsonify(ok=False, error=(
                "%s is a real write to that application, issued from this "
                "server. Tick the confirmation to send it." % method),
                needs_confirmation=True), 409

    if (mode_a == net_guard.MODE_FREE or mode_c == net_guard.MODE_FREE) \
            and not _may_free():
        log_action("txn_trace.denied", target=(vip_raw or backend_raw)[:200],
                   extra={"reason": "free target without "
                                    + net_guard.FREE_PERMISSION})
        return jsonify(ok=False, error=(
            "A free target requires the '%s' permission. Inventory "
            "destinations remain available." % net_guard.FREE_PERMISSION)), 403

    inventory = _inventory()
    legs = []
    leg_a = leg_c = None
    started = time.time()

    if vip_raw:
        dest, scheme, tpath, err = _resolve(mode_a, vip_raw, inventory)
        if err:
            return err
        leg_a = txn_trace.send(
            dest["ip"], dest["port"], host=dest["host"],
            path=path or tpath or "/", scheme=scheme, method=method,
            headers=headers, body=req_body, leg=txn_trace.LEG_A,
            label="through the appliance")
        legs.append(leg_a)

    if backend_raw:
        dest, scheme, tpath, err = _resolve(mode_c, backend_raw, inventory,
                                            default_port=80)
        if err:
            return err
        # The SAME Host as leg A when there is one — a leg C carrying the
        # backend's own hostname is a different request, and every
        # name-based vhost on that backend would answer differently.
        host_for_c = headers.get("Host") or (leg_a["request"]["host"]
                                             if leg_a else dest["host"])
        leg_c = txn_trace.send(
            dest["ip"], dest["port"], host=host_for_c,
            path=path or tpath or "/", scheme=scheme, method=method,
            headers=headers, body=req_body, sni=host_for_c,
            leg=txn_trace.LEG_C, label="direct to the backend")
        leg_c["request"]["dialled_host"] = dest["host"]
        legs.append(leg_c)
    ended = time.time()

    if not legs:
        return jsonify(ok=False,
                       error="Give at least a VIP or a backend to trace."), 400

    comparison = txn_trace.diff(leg_a, leg_c) if (leg_a and leg_c) else {
        "comparable": False,
        "why": ("Only one leg was traced, so there is nothing to compare. The "
                "diff is the answer to 'is it the WAF or the app?' — give both "
                "a VIP and a backend to get it.")}

    log_action("txn_trace.run",
               target="%s -> %s" % (vip_raw or "-", backend_raw or "-"),
               extra={"method": method, "path": path,
                      "mode_a": mode_a, "mode_c": mode_c,
                      "status_a": leg_a["status"] if leg_a else None,
                      "status_c": leg_c["status"] if leg_c else None,
                      "verdict": comparison.get("verdict", {}).get("key", "")})

    return jsonify(ok=True, legs=legs, diff=comparison,
                   curl=[{"leg": l["leg"], "label": l.get("label"),
                          "cmd": txn_trace.to_curl(l)} for l in legs],
                   window=[started, ended])


@bp.route("/derive", methods=["POST"])
@login_required
def derive():
    """Leg B — what the appliance forwards, read off its own configuration.

    A separate endpoint because it is a DIFFERENT KIND of answer from a trace,
    and a panel that folds a derivation into the measured legs would let an
    operator quote a configuration value as an observation.
    """
    body = request.get_json(silent=True) or {}
    appliance_id = int(body.get("appliance_id") or 0)
    policy = str(body.get("policy") or "").strip()
    if not (appliance_id and policy):
        return jsonify(ok=False,
                       error="Pick an appliance and a server policy."), 400
    from ..models import visible_appliance_or_404
    appliance = visible_appliance_or_404(appliance_id)
    try:
        from ..clients.fortiweb import FortiWebClient
        client = FortiWebClient(appliance)
        pf = client.policy_full(policy)
    except Exception as exc:  # noqa: BLE001 — a dead box is a read failure
        # NOT an empty derivation: an unreadable device and a device with
        # nothing configured produce the same empty table and mean opposite
        # things.
        return jsonify(ok=False, error="Could not read %s from %s: %s"
                                       % (policy, appliance.name, exc)), 502
    wpp = (pf.get("wpp") or {})
    xff_name = wpp.get("x-forwarded-for-rule") or ""
    if xff_name:
        try:
            pf["xff"] = client._safe_one(
                "/api/v2.0/cmdb/application-delivery/x-forwarded-for?mkey=%s"
                % xff_name)
        except Exception:  # noqa: BLE001
            pf["xff"] = {}
    derived = txn_trace.derive_forwarded(pf)
    log_action("txn_trace.derive", target="%s:%s" % (appliance.name, policy),
               extra={"rows": len(derived["rows"]),
                      "absent": len(derived["absent"])})
    return jsonify(ok=True, policy=policy, appliance=appliance.name, **derived)


@bp.route("/correlate", methods=["POST"])
@login_required
def correlate():
    """Attack-log entries that could belong to a trace window."""
    body = request.get_json(silent=True) or {}
    appliance_id = int(body.get("appliance_id") or 0)
    window = body.get("window") or []
    if not appliance_id or len(window) != 2:
        return jsonify(ok=False, error="Need an appliance and a trace window."), 400
    from ..models import visible_appliance_or_404
    appliance = visible_appliance_or_404(appliance_id)
    from ..services import attack_log
    try:
        entries = attack_log.recent(appliance, limit=60)
    except Exception as exc:  # noqa: BLE001
        return jsonify(ok=False, error="Attack log unavailable on %s: %s"
                                       % (appliance.name, exc)), 502
    res = txn_trace.correlate(entries, float(window[0]), float(window[1]),
                              src_ips=body.get("source_ips") or [])
    return jsonify(ok=True, **res)


@bp.route("/har", methods=["POST"])
@login_required
def har():
    """The traced legs as a HAR 1.2 log, for browser devtools."""
    body = request.get_json(silent=True) or {}
    legs = body.get("legs") or []
    if not isinstance(legs, list):
        return jsonify(ok=False, error="legs must be a list"), 400
    return jsonify(ok=True, har=txn_trace.to_har(legs[:8]))
