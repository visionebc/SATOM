# app/views/cert_inspect.py
"""Certificate & chain inspector — helper endpoints for the header Tools menu.

Two ways in, and they are not the same kind of operation:

* ``/paste`` is pure computation on text the operator supplied. No socket, no
  device, no DB write. It needs nothing beyond being logged in.
* ``/probe`` opens a TLS connection FROM THIS SERVER. That is an outbound
  request the operator's browser could not have made, so it is gated
  (:data:`net_guard.FREE_PERMISSION` for a free target), bounded by
  :mod:`app.services.net_guard`, and written to the audit trail every time —
  including the refusals, because "SATOM was pointed at X" is the fact an
  incident review needs and a refused attempt is the interesting half.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from ..models import Appliance, visible_appliances
from ..services import cert_inspect, net_guard
from ..services.audit import log_action

bp = Blueprint("cert_inspect", __name__, url_prefix="/cert-inspect")

#: Hard ceiling on pasted text. A fullchain is a few kB; anything past this is
#: a trust store or a mistake, and parsing it to say so is wasted work.
MAX_PASTE = 256 * 1024


def _may_free() -> bool:
    """Free-target probing needs its own permission — but an admin has it by
    definition, and the granular catalog is composed by admins, so a deployment
    that has not adopted the new key must not lock its admins out of a tool the
    release notes just announced."""
    try:
        perms = set(current_user.effective_permissions or ())
    except Exception:  # noqa: BLE001
        return False
    return net_guard.FREE_PERMISSION in perms or "user_manage" in perms


@bp.route("/targets")
@login_required
def targets():
    """The inventory destinations this user may point the inspector at.

    Built from ``visible_appliances`` so a device in maintenance stays hidden
    from the operators it is hidden from everywhere else — a tool that leaks the
    hostname of a parked appliance has undone that gate.
    """
    rows = []
    for a in visible_appliances(Appliance.query).order_by(Appliance.name).all():
        rows.append({"id": a.id, "name": a.name, "kind": a.kind,
                     "host": a.host, "port": a.port or 443})
    return jsonify(ok=True, targets=rows, may_free=_may_free(),
                   free_permission=net_guard.FREE_PERMISSION,
                   openssl=cert_inspect.openssl_available())


@bp.route("/paste", methods=["POST"])
@login_required
def paste():
    """Analyse pasted PEM material. Nothing leaves this process."""
    body = request.get_json(silent=True) or {}
    pem = str(body.get("pem") or "")[:MAX_PASTE]
    key = str(body.get("key") or "")[:MAX_PASTE]
    hostname = str(body.get("hostname") or "").strip()[:253]
    passphrase = str(body.get("passphrase") or "")[:256]
    pems = cert_inspect.split_pem(pem)
    if not pems:
        return jsonify(ok=False,
                       error="No PEM certificate block found. Paste the text "
                             "between -----BEGIN CERTIFICATE----- and "
                             "-----END CERTIFICATE----- (a fullchain may hold "
                             "several)."), 400
    res = cert_inspect.analyse(pems, hostname=hostname, source="paste",
                               key_pem=key, key_passphrase=passphrase)
    return jsonify(ok=True, **res)


@bp.route("/probe", methods=["POST"])
@login_required
def probe():
    """Open a TLS connection and analyse what the server presents."""
    body = request.get_json(silent=True) or {}
    mode = str(body.get("mode") or net_guard.MODE_INVENTORY)
    raw = str(body.get("target") or "").strip()
    sni_override = str(body.get("sni") or "").strip()

    inventory = {}
    for a in visible_appliances(Appliance.query).all():
        inventory[a.host.strip().lower()] = a

    if mode == net_guard.MODE_INVENTORY:
        appliance = inventory.get(raw.split(":")[0].strip().lower())
        if appliance is None:
            try:
                appliance = next(
                    a for a in inventory.values() if a.name == raw)
            except StopIteration:
                appliance = None
        if appliance is None:
            return jsonify(ok=False, error="Not an inventory destination."), 400
        host, port = appliance.host, int(appliance.port or 443)
        path = ""
    else:
        if not _may_free():
            log_action("cert_inspect.probe_denied", target=raw[:200],
                       extra={"reason": "missing " + net_guard.FREE_PERMISSION})
            return jsonify(
                ok=False,
                error="Free-target probing requires the '%s' permission. "
                      "Inventory destinations remain available."
                      % net_guard.FREE_PERMISSION), 403
        try:
            parsed = net_guard.parse_target(raw)
        except net_guard.TargetError as exc:
            return jsonify(ok=False, error=str(exc)), 400
        host, port, path = parsed["host"], parsed["port"], parsed["path"]

    try:
        dest = net_guard.resolve_target(
            host, port, mode=mode, inventory_hosts=list(inventory.keys()))
    except net_guard.TargetError as exc:
        log_action("cert_inspect.probe_denied", target="%s:%s" % (host, port),
                   extra={"mode": mode, "reason": str(exc)})
        return jsonify(ok=False, error=str(exc)), 400

    sni = sni_override or dest["host"]
    fetched = cert_inspect.fetch_chain(dest["ip"], dest["port"], server_name=sni)
    log_action("cert_inspect.probe", target="%s:%d" % (dest["host"], dest["port"]),
               extra={"mode": mode, "ip": dest["ip"], "sni": sni,
                      "source": fetched.get("source"),
                      "error": fetched.get("error")})
    if not fetched["pems"]:
        return jsonify(ok=False,
                       error="Could not read a certificate from %s:%d (%s) — %s"
                             % (dest["host"], dest["port"], dest["ip"],
                                fetched["error"] or "no certificate presented"),
                       resolved=dest["ip"]), 502

    res = cert_inspect.analyse(fetched["pems"], hostname=sni,
                               source=fetched["source"],
                               verify_line=fetched.get("verify_line", ""))
    return jsonify(ok=True, resolved=dest["ip"], addresses=dest["addresses"],
                   sni=sni, port=dest["port"], host=dest["host"], path=path,
                   protocol=fetched.get("protocol", ""),
                   cipher=fetched.get("cipher", ""), **res)
