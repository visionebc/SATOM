"""/api/v1/adc — third-party authoring of FortiADC carve-outs.

The FortiWeb half of this surface (``api_v1.waf``) writes DESIRED STATE first:
a carve-out becomes a ``WppException`` row that carries its author, and the
appliance write is a second, separately-authorised step. FortiADC rules are
written straight to the appliance (there is no ADC desired-state store), so:

* **Dry-run is built locally.** FortiADC applies immediately and offers no
  server-side preview, so ``apply: false`` returns the exact request that WOULD
  be sent (identical contract to the ADC UI writes) without opening a session.
* **Reads come from SATOM's device cache** (the hourly sweep, kept current by
  write-through after every API write): ``source``/``as_of``/``stale`` say how
  old the answer is. ``?live=1`` reads the device, through the per-appliance
  session cap (``services.device_gate``) and shared with identical callers for
  a few seconds -- a hundred pollers must not become a hundred sessions.
* **DELETE only what this token created.** The create records its author and
  what it sent (``ApiObjectAuthor``). A delete is refused for anything else --
  an operator's object, another token's -- and when the object on the device
  no longer matches what was sent (an operator edited or re-created it under
  the same name). Before the author record, "delete only what you created" was
  unprovable and the surface had no DELETE at all.

Same two-audience model as the WAF surface, same reason: the privilege is the
capability on the token (``adc_rule_draft`` / ``adc_rule_apply``), never a flag
the caller sets.
"""
from __future__ import annotations

from datetime import datetime

from flask import g, jsonify, request

from ..clients.fortiadc import FortiADCClient, FortiADCError
from ..extensions import db, limiter
from ..models import visible_appliance_or_404
from ..services import adc_objform, cache_reads, device_gate, device_verify
from ..services import api_object_rules as guard
from ..services.audit import log_action
from . import bp
from .auth import audit_extra, rate_key, token_required

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
    """The allow-list of FortiADC rule types a token may author."""
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
        "delete_supported": True,
        "delete_scope": "own",
        "note": ("A token may delete only a rule it created through this API, "
                 "and only while the rule on the appliance still matches what "
                 "it sent. Anything else is an operator action."),
        "reads": ("GET /adc/rules answers from SATOM's device cache (source, "
                  "as_of, stale); add live=1 to read the appliance."),
    })


def _busy(exc: device_gate.Busy):
    resp, status = _err(429, "device_busy", str(exc), retry_after=exc.retry_after,
                        concurrency_limit=exc.limit)
    resp.headers["Retry-After"] = str(exc.retry_after)
    return resp, status


def _live_rows(appliance, logical: str):
    rows, device_error = FortiADCClient(appliance).list_with_error(logical)
    if device_error:
        raise FortiADCError(device_error)
    return rows or []


# --------------------------------------------------------------------------- #
#  Read                                                                         #
# --------------------------------------------------------------------------- #
def _wants_live() -> bool:
    return str(request.args.get("live", "")).lower() in ("1", "true", "yes")


@bp.route("/adc/rules", methods=["GET"])
@limiter.limit("20 per minute", key_func=rate_key, exempt_when=lambda: not _wants_live())
@token_required("read")
def adc_list_rules():
    """FortiADC rules of one type: from SATOM's device cache, or ``live=1``."""
    appliance, err = _fortiadc_or_error(request.args.get("appliance_id", type=int))
    if err:
        return err
    logical, err = _logical_or_error(request.args.get("logical", ""))
    if err:
        return err
    base = {"logical": logical, "appliance_id": appliance.id}

    if not _wants_live():
        got = cache_reads.read_table(appliance, logical)
        meta = {"source": "cache", "as_of": got["as_of"], "stale": got["stale"],
                "stale_reason": got["reason"] if got["stale"] else "",
                "sync_failing_since": got["sync_failing_since"]}
        if got["status"] == "ok":
            return jsonify({**base, **meta, "rules": got["rows"]})
        if got["status"] == "failed":
            return _err(503, "not_cached",
                        "The last sweep of this appliance could not read this "
                        f"table ({got['error']}). Retry with live=1 to ask the "
                        "appliance, or see Monitoring for the device's state.",
                        **base, **meta)
        # Never swept: answer from the device once, through the same gate.

    try:
        rows, shared = device_gate.coalesce(
            appliance.id, f"adc_rules:{logical}", lambda: _live_rows(appliance, logical))
    except device_gate.Busy as exc:
        return _busy(exc)
    except FortiADCError as exc:
        return _err(502, "device_error", str(exc))
    except Exception as exc:  # noqa: BLE001 — transport
        return _err(502, "device_unreachable", str(exc))
    return jsonify({**base, "source": "live", "shared": shared,
                    "as_of": datetime.utcnow().isoformat() + "Z", "stale": False,
                    "rules": rows})


# --------------------------------------------------------------------------- #
#  Create                                                                       #
# --------------------------------------------------------------------------- #
@bp.route("/adc/rules", methods=["POST"])
@limiter.limit("30 per minute")
@token_required("write")
def adc_create_rule():
    """Create a FortiADC rule: a preview, or the write with ``apply`` and the capability."""
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

    try:
        with device_gate.slot(appliance.id):
            # A create must never CLOBBER. FortiADC's POST-on-existing-mkey
            # behaviour is not something to find out in production on someone
            # else's object, so the name is checked first and a collision is
            # refused here.
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

            # The create is re-read: "applied" means the device HOLDS the object
            # with the fields that were sent, not only that it accepted the POST.
            v = device_verify.adc_after_write(appliance, client, "create",
                                              logical=logical, mkey=mkey, sent=payload)
    except device_gate.Busy as exc:
        return _busy(exc)
    if device_verify.failed(v):
        log_action("api.adc_rule.create_failed", target=f"{logical}/{mkey}",
                   extra=audit_extra(appliance_id=appliance.id,
                                     error=device_verify.label(v)))
        return _err(502, "not_applied", device_verify.label(v), verify=v)

    _record_author(appliance, logical, mkey, tok, payload)
    log_action("api.adc_rule.create", target=f"{logical}/{mkey}",
               extra=audit_extra(appliance_id=appliance.id, logical=logical,
                                 fields=sorted(payload), verify=v["verdict"]))
    return jsonify({"ok": True, "applied": True, "dry_run": False,
                    "logical": logical, "mkey": mkey,
                    "appliance_id": appliance.id, "verify": v}), 201


# --------------------------------------------------------------------------- #
#  Authorship                                                                   #
# --------------------------------------------------------------------------- #
def _record_author(appliance, logical: str, mkey: str, tok, sent: dict) -> None:
    """Remember that *tok* created ``logical/mkey`` with *sent*. Best effort: a
    failure only means the token cannot delete it later (fails closed)."""
    from ..models_cache import ApiObjectAuthor
    try:
        row = (ApiObjectAuthor.query
               .filter_by(appliance_id=appliance.id, logical=logical, mkey=mkey).first())
        if row is None:
            row = ApiObjectAuthor(appliance_id=appliance.id, logical=logical, mkey=mkey)
        row.product = "fortiadc"
        row.author = guard.author_ref(tok)
        row.sent = dict(sent)
        row.created_at = datetime.utcnow()
        db.session.add(row)
        db.session.commit()
    except Exception:  # noqa: BLE001
        db.session.rollback()


def _still_as_sent(current: dict, sent: dict) -> list[str]:
    """Fields of *sent* the device now holds with another value."""
    changed = []
    for k, v in (sent or {}).items():
        if k == "mkey":
            continue
        have = current.get(k)
        if str(have if have is not None else "").strip() != str(v).strip():
            changed.append(k)
    return sorted(changed)


# --------------------------------------------------------------------------- #
#  Delete                                                                       #
# --------------------------------------------------------------------------- #
@bp.route("/adc/rules", methods=["DELETE"])
@limiter.limit("30 per minute", key_func=rate_key)
@token_required("write")
def adc_delete_rule():
    """Delete a FortiADC rule THIS token created through the API (capability
    ``adc_rule_apply``). ``appliance_id``, ``logical`` and ``mkey`` come in the
    query string or a JSON body."""
    from ..models_cache import ApiObjectAuthor
    tok = g.api_token
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        body = {}

    def arg(name):
        return request.args.get(name) or body.get(name)

    ok, code, msg = tok.authorize_object("adc_rule_apply")
    if not ok:
        log_action("api.adc_rule.denied", extra=audit_extra(reason=code, wanted="delete"))
        return _err(403, code, msg)
    err = _appid_gate(tok)
    if err:
        return err
    appliance, err = _fortiadc_or_error(arg("appliance_id"))
    if err:
        return err
    logical, err = _logical_or_error(arg("logical") or "")
    if err:
        return err
    mkey = str(arg("mkey") or "").strip()
    if not mkey:
        return _err(400, "bad_request", "'mkey' (the object name) is required.")

    rec = (ApiObjectAuthor.query
           .filter_by(appliance_id=appliance.id, logical=logical, mkey=mkey).first())
    if rec is None or rec.author != guard.author_ref(tok):
        log_action("api.adc_rule.delete_denied", target=f"{logical}/{mkey}",
                   extra=audit_extra(appliance_id=appliance.id,
                                     reason="not_owner" if rec else "not_api_created"))
        return _err(403, "not_owner",
                    f"'{mkey}' was not created through this API by this token, so "
                    "it cannot delete it. Withdrawing it is an operator action.")

    client = FortiADCClient(appliance)
    try:
        with device_gate.slot(appliance.id):
            # The whole table, not ``get_object``: a single-object read that
            # fails cannot tell "gone" from "unreachable", and reading "gone"
            # into an unreachable box would drop the author record.
            try:
                rows, read_err = client.list_with_error(logical)
            except Exception as exc:  # noqa: BLE001 — transport
                rows, read_err = [], f"{type(exc).__name__}: {exc}"
            if read_err:
                return _err(502, "device_error", read_err)
            current = next((r for r in rows if isinstance(r, dict)
                            and str(r.get("mkey", "")) == mkey), None)
            if current is None:
                db.session.delete(rec)
                db.session.commit()
                log_action("api.adc_rule.delete", target=f"{logical}/{mkey}",
                           extra=audit_extra(appliance_id=appliance.id, verify="already_absent"))
                return jsonify({"ok": True, "deleted": False, "already_absent": True,
                                "logical": logical, "mkey": mkey,
                                "appliance_id": appliance.id})
            changed = _still_as_sent(current if isinstance(current, dict) else {},
                                     rec.sent or {})
            if changed:
                log_action("api.adc_rule.delete_denied", target=f"{logical}/{mkey}",
                           extra=audit_extra(appliance_id=appliance.id,
                                             reason="modified", fields=changed))
                return _err(409, "modified_since_created",
                            f"'{mkey}' on the appliance no longer matches what this "
                            "token created (changed: " + ", ".join(changed) + "). "
                            "Someone else edited it; withdrawing it is an operator "
                            "action.", changed=changed)
            try:
                client.delete(logical, mkey)
            except (FortiADCError, Exception) as exc:  # noqa: BLE001
                log_action("api.adc_rule.delete_failed", target=f"{logical}/{mkey}",
                           extra=audit_extra(appliance_id=appliance.id, error=str(exc)))
                return _err(502, "device_error", str(exc))
            v = device_verify.adc_after_write(appliance, client, "delete",
                                              logical=logical, mkey=mkey)
    except device_gate.Busy as exc:
        return _busy(exc)
    if device_verify.failed(v):
        log_action("api.adc_rule.delete_failed", target=f"{logical}/{mkey}",
                   extra=audit_extra(appliance_id=appliance.id,
                                     error=device_verify.label(v)))
        return _err(502, "not_applied", device_verify.label(v), verify=v)
    db.session.delete(rec)
    db.session.commit()
    log_action("api.adc_rule.delete", target=f"{logical}/{mkey}",
               extra=audit_extra(appliance_id=appliance.id, verify=v["verdict"]))
    return jsonify({"ok": True, "deleted": True, "logical": logical, "mkey": mkey,
                    "appliance_id": appliance.id, "verify": v})
