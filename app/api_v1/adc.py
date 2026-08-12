"""/api/v1/adc — third-party authoring of FortiADC carve-outs.

The FortiWeb half of this surface (``api_v1.waf``) writes DESIRED STATE first:
a carve-out becomes a ``WppException`` row that carries its author, and the
appliance write is a second, separately-authorised step. FortiADC has no such
store — the ADC area of SATOM is live-only (there is no ADC object cache). Two
consequences, both stated here rather than papered over:

* **Dry-run is built locally.** FortiADC applies immediately and offers no
  server-side preview, so ``apply: false`` returns the exact request that WOULD
  be sent (identical contract to the ADC UI writes) without opening a session.
* **There is no DELETE.** Without a store there is no recorded author, so
  "delete only what you created" is UNPROVABLE — and a delete endpoint that
  cannot tell an external team's object from an operator's is a way to remove
  someone else's protection. Withdrawal is an operator action until the ADC side
  grows a desired-state store. Advertised in ``GET /adc/rule-types`` so an
  integrator learns it from the API, not from a support ticket.

Same two-audience model as the WAF surface, same reason: the privilege is the
capability on the token (``adc_rule_draft`` / ``adc_rule_apply``), never a flag
the caller sets.
"""
from __future__ import annotations

from flask import g, jsonify, request

from ..clients.fortiadc import FortiADCClient, FortiADCError
from ..extensions import limiter
from ..models import visible_appliance_or_404
from ..services import adc_objform
from ..services.audit import log_action
from . import bp
from .auth import audit_extra, token_required

# ---------------------------------------------------------------------------
# The allow-list. Short BY DESIGN and extended in code, not in configuration:
# the FortiADC REST surface reaches ``system_*``, ``router_*`` and the admin
# objects through the same shape as these, so "whatever logical you send" is an
# appliance-takeover API. Both entries below are carve-out objects — the ADC
# analogue of what the FortiWeb surface allows — and both are verified present
# in the ADC registry.
# ---------------------------------------------------------------------------
ADC_RULE_LOGICALS: dict[str, str] = {
    "security_waf_exception":
        "WAF exception — exempts matching traffic from WAF checks.",
    "security_dos_exception":
        "DoS protection exception — exempts matching sources from DoS limits.",
}


def _owner():
    return getattr(g, "api_token_owner", None)


def _err(status: int, code: str, message: str, **extra):
    body = {"error": code, "message": message}
    body.update(extra)
    return jsonify(body), status


def _fortiadc_or_error(appliance_id):
    if not appliance_id:
        return None, _err(400, "bad_request", "'appliance_id' is required.")
    appliance = visible_appliance_or_404(int(appliance_id), user=_owner())
    if appliance.kind != "fortiadc":
        return None, _err(404, "not_found", "No such FortiADC appliance.")
    return appliance, None


def _logical_or_error(logical: str):
    logical = (logical or "").strip()
    if logical not in ADC_RULE_LOGICALS:
        return None, _err(400, "type_not_allowed",
                          f"'{logical}' is not an API-authorable FortiADC rule "
                          "type. GET /api/v1/adc/rule-types for the allow-list.",
                          allowed=sorted(ADC_RULE_LOGICALS))
    # Belt and braces: the curated list must also be a registry logical, so a
    # registry rename surfaces as an error here instead of a blind POST to a
    # path that no longer means what the allow-list thinks it means.
    if not adc_objform.is_known(logical):
        return None, _err(500, "registry_mismatch",
                          f"'{logical}' is allow-listed but missing from the "
                          "FortiADC registry — refusing to guess its endpoint.")
    return logical, None


def _appid_gate(tok):
    """An AppID-scoped token cannot use this surface — and that is fail-closed.

    AppID bindings resolve to ``(appliance, server_policy)`` pairs, a FortiWeb
    concept. A FortiADC exception object is not bound to a virtual server in its
    own payload, so the scope is UNRESOLVABLE here. Allowing the write anyway
    would silently promote a narrowly-scoped token to appliance-wide reach on a
    second product — the exact failure ``not_appid_scopable`` already prevents
    for catalog actions.
    """
    if tok.is_appid_scoped:
        return _err(403, "not_appid_scopable",
                    "This token is AppID-scoped. AppID scope resolves to "
                    "FortiWeb server policies and cannot be proven for a "
                    "FortiADC rule, so the write is refused. Use a token "
                    "scoped to the fortiadc ADOM without an AppID allow-list.")
    return None


# --------------------------------------------------------------------------- #
#  Catalog                                                                      #
# --------------------------------------------------------------------------- #
@bp.route("/adc/rule-types", methods=["GET"])
@token_required("read")
def adc_rule_types():
    out = []
    for logical, description in sorted(ADC_RULE_LOGICALS.items()):
        out.append({
            "logical": logical,
            "description": description,
            "required": sorted(adc_objform.required_fields(logical)),
            "hint": adc_objform.create_hint(logical),
            "known": adc_objform.is_known(logical),
        })
    return jsonify({
        "types": out,
        "delete_supported": False,
        "note": ("FortiADC rules are written straight to the appliance (no "
                 "desired-state store), so SATOM cannot record who authored "
                 "one. Withdrawal is therefore an operator action."),
    })


# --------------------------------------------------------------------------- #
#  Read                                                                         #
# --------------------------------------------------------------------------- #
@bp.route("/adc/rules", methods=["GET"])
@token_required("read")
def adc_list_rules():
    appliance, err = _fortiadc_or_error(request.args.get("appliance_id", type=int))
    if err:
        return err
    logical, err = _logical_or_error(request.args.get("logical", ""))
    if err:
        return err
    try:
        rows, device_error = FortiADCClient(appliance).list_with_error(logical)
    except (FortiADCError, Exception) as exc:  # noqa: BLE001
        return _err(502, "device_unreachable", str(exc))
    if device_error:
        return _err(502, "device_error", device_error)
    return jsonify({"logical": logical, "appliance_id": appliance.id,
                    "rules": rows or []})


# --------------------------------------------------------------------------- #
#  Create                                                                       #
# --------------------------------------------------------------------------- #
@bp.route("/adc/rules", methods=["POST"])
@limiter.limit("30 per minute")
@token_required("write")
def adc_create_rule():
    tok = g.api_token
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return _err(400, "bad_request", "Body must be a JSON object.")

    ok, code, msg = tok.authorize_object("adc_rule_draft")
    if not ok:
        log_action("api.adc_rule.denied", extra=audit_extra(reason=code))
        return _err(403, code, msg)
    want_apply = bool(body.get("apply"))
    if want_apply:
        ok, code, msg = tok.authorize_object("adc_rule_apply")
        if not ok:
            log_action("api.adc_rule.denied",
                       extra=audit_extra(reason=code, wanted="apply"))
            return _err(403, code, msg)

    err = _appid_gate(tok)
    if err:
        return err

    appliance, err = _fortiadc_or_error(body.get("appliance_id"))
    if err:
        return err
    logical, err = _logical_or_error(body.get("logical", ""))
    if err:
        return err

    mkey = str(body.get("mkey") or "").strip()
    if not mkey:
        return _err(400, "bad_request", "'mkey' (the object name) is required.")
    fields = body.get("fields")
    if not isinstance(fields, dict):
        return _err(400, "bad_request", "'fields' must be a JSON object.")

    missing = [k for k in adc_objform.required_fields(logical)
               if not str(fields.get(k, "")).strip()]
    if missing:
        return _err(400, "invalid_payload",
                    "Missing required field(s): " + ", ".join(sorted(missing)),
                    errors=sorted(missing))

    payload = {k: v for k, v in fields.items() if v not in (None, "", [])}
    payload["mkey"] = mkey
    client = FortiADCClient(appliance)

    if not want_apply:
        return jsonify({
            "ok": True, "applied": False, "dry_run": True,
            "request": {"method": "POST", "path": client._resolve(logical),
                        "body": payload},
            "note": ("Preview only — nothing was sent to the appliance. "
                     "Re-send with \"apply\": true using a token holding "
                     "'adc_rule_apply'."),
        })

    # A create must never CLOBBER. FortiADC's POST-on-existing-mkey behaviour is
    # not something to find out in production on someone else's object, so the
    # name is checked first and a collision is refused here.
    try:
        existing = client.get_object(logical, mkey)
    except (FortiADCError, Exception):  # noqa: BLE001 — absent or unreadable
        existing = None
    if existing:
        return _err(409, "already_exists",
                    f"'{mkey}' already exists on this FortiADC. Creating would "
                    "risk overwriting an object this token does not own; pick "
                    "another name or ask an operator to edit the existing one.")

    try:
        client.create(logical, payload)
    except (FortiADCError, Exception) as exc:  # noqa: BLE001
        log_action("api.adc_rule.create_failed", target=f"{logical}/{mkey}",
                   extra=audit_extra(appliance_id=appliance.id, error=str(exc)))
        return _err(502, "device_error", str(exc))

    log_action("api.adc_rule.create", target=f"{logical}/{mkey}",
               extra=audit_extra(appliance_id=appliance.id, logical=logical,
                                 fields=sorted(payload)))
    return jsonify({"ok": True, "applied": True, "dry_run": False,
                    "logical": logical, "mkey": mkey,
                    "appliance_id": appliance.id}), 201
