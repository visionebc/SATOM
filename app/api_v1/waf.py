"""/api/v1/waf — third-party authoring of FortiWeb WAF carve-outs.

The ask this answers: an external technical team must be able to file (and, when
trusted, apply) an exception on the WAF that protects ITS application, without a
SATOM operator retyping it.

What this is NOT, deliberately: a passthrough to the FortiWeb cmdb. The FortiWeb
cmdb does not distinguish "a WAF carve-out" from ``system/admin``,
``system/interface`` or ``router/static``, so an endpoint that accepts whatever
object type it is handed is not a rules API — it is an appliance-takeover API.
The type must be in :data:`app.services.wpp_exceptions.CATALOG`, and in v1 only
the ``exception`` half of it:

* ``CAT_EXCEPTION`` — a carve-out scoped to a host/URL/IP/cookie/file. In.
* ``CAT_SIGNATURE`` — edits a signature SET, which every policy binding that set
  inherits, and which is capped at 128 rows the whole fleet competes for. Out of
  the external surface; it stays UI + operator.

The two-audience split the operator asked for ("some file a request the operator
approves, others write directly") is NOT a flag in the request body — a caller
must never pick its own privilege. It is which capability the token holds:

* ``waf_exception_draft``  → writes the desired-state record + returns the exact
  device plan. **Never touches an appliance.**
* ``waf_exception_apply``  → may additionally push it (``apply: true``).

Both are EXPLICIT-only grants (see ``models_api_token.EXPLICIT_ONLY_CAPABILITIES``):
tokens minted before this surface existed gain nothing.
"""
from __future__ import annotations

from flask import g, jsonify, request

from ..extensions import limiter
from ..models import Appliance, visible_appliance_or_404
from ..services import api_object_rules as guard
from ..services import exception_inject
from ..services import wpp_exceptions as store
from ..services.audit import log_action
from . import bp
from .auth import audit_extra, token_required

#: v1 external surface = WAF exceptions only (see module docstring).
ALLOWED_CATEGORY = store.CAT_EXCEPTION


def _owner():
    return getattr(g, "api_token_owner", None)


def _err(status: int, code: str, message: str, **extra):
    body = {"error": code, "message": message}
    body.update(extra)
    return jsonify(body), status


def _fortiweb_or_error(appliance_id: int):
    """Resolve a visible FortiWeb appliance, or an error response tuple."""
    if not appliance_id:
        return None, _err(400, "bad_request", "'appliance_id' is required.")
    appliance = visible_appliance_or_404(int(appliance_id), user=_owner())
    if appliance.kind != "fortiweb":
        # 404, not 403: do not confirm what a device the token cannot use is.
        return None, _err(404, "not_found", "No such FortiWeb appliance.")
    return appliance, None


def _exception_json(exc, *, appliance: Appliance | None = None) -> dict:
    return {
        "id": exc.id,
        "appliance_id": exc.appliance_id,
        "appliance": appliance.name if appliance is not None else None,
        "wpp_mkey": exc.wpp_mkey,
        "exc_type": exc.exc_type,
        "label": (store.type_for(exc.exc_type) or {}).get("label", exc.exc_type),
        "category": exc.category,
        "name": exc.name or "",
        "payload": exc.payload_dict,
        "policies": exc.policy_names,
        "reason": exc.reason or "",
        "enabled": bool(exc.enabled),
        "stale": bool(exc.stale),
        "stale_reason": exc.stale_reason or "",
        "author": exc.author or "",
        "created_at": exc.created_at.isoformat() if exc.created_at else None,
        "updated_at": exc.updated_at.isoformat() if exc.updated_at else None,
    }


def _plan_json(plan: dict) -> dict:
    return {k: plan.get(k) for k in
            ("status", "method", "endpoint", "collection", "target", "inline",
             "error")}


# --------------------------------------------------------------------------- #
#  Catalog — the allow-list, published so a caller can build a valid request    #
# --------------------------------------------------------------------------- #
@bp.route("/waf/exception-types", methods=["GET"])
@token_required("read")
def waf_exception_types():
    out = []
    for t in store.catalog(ALLOWED_CATEGORY):
        key = t["key"]
        out.append({
            "key": key,
            "label": t["label"],
            "group": t["group"],
            "required": store.REQUIRED_FIELDS.get(key, []),
            "fields": [
                {"key": f.get("key"), "label": f.get("label"),
                 "widget": f.get("widget", "text"),
                 "options": f.get("options") or [],
                 "required": bool(f.get("required"))}
                for f in store.fields_for(key)
            ],
            "help": store.help_for(key),
            "auto_bind": exception_inject.supports_auto_bind(key),
        })
    return jsonify({"types": out, "category": ALLOWED_CATEGORY})


# --------------------------------------------------------------------------- #
#  Read                                                                         #
# --------------------------------------------------------------------------- #
@bp.route("/waf/exceptions", methods=["GET"])
@token_required("read")
def waf_list_exceptions():
    """Carve-outs this token authored. ``?all=1`` (admin scope) widens to every
    carve-out on the appliance — an external team sees ITS OWN by default, which
    is also what stops it from enumerating another tenant's config."""
    tok = g.api_token
    appliance_id = request.args.get("appliance_id", type=int)
    appliance, err = _fortiweb_or_error(appliance_id)
    if err:
        return err

    want_all = request.args.get("all") in ("1", "true", "yes")
    if want_all and not tok.has_scope("admin"):
        return _err(403, "insufficient_scope",
                    "Listing every carve-out requires the 'admin' scope.")

    rows = store.list_exceptions(appliance.id, ALLOWED_CATEGORY)
    if not want_all:
        mine = guard.author_ref(tok)
        rows = [r for r in rows if (r.author or "") == mine]
    policy = (request.args.get("policy") or "").strip()
    if policy:
        rows = [r for r in rows if policy in r.policy_names]
    return jsonify({"exceptions": [_exception_json(r, appliance=appliance)
                                   for r in rows],
                    "scope": "all" if want_all else "own"})


@bp.route("/waf/exceptions/<int:exc_id>", methods=["GET"])
@token_required("read")
def waf_get_exception(exc_id):
    tok = g.api_token
    exc = store.get(exc_id)
    if exc is None or exc.category != ALLOWED_CATEGORY:
        return _err(404, "not_found", "No such carve-out.")
    appliance, err = _fortiweb_or_error(exc.appliance_id)
    if err:
        return err
    if not guard.owned_by(exc, tok) and not tok.has_scope("admin"):
        return _err(404, "not_found", "No such carve-out.")
    return jsonify(_exception_json(exc, appliance=appliance))


# --------------------------------------------------------------------------- #
#  Create (draft by default, apply only with the capability AND apply=true)     #
# --------------------------------------------------------------------------- #
@bp.route("/waf/exceptions", methods=["POST"])
@limiter.limit("30 per minute")
@token_required("write")
def waf_create_exception():
    tok = g.api_token
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return _err(400, "bad_request", "Body must be a JSON object.")

    # ---- authorization: the "what". Drafting is the floor for every caller. --
    ok, code, msg = tok.authorize_object("waf_exception_draft")
    if not ok:
        log_action("api.wpp_exception.denied", extra=audit_extra(reason=code))
        return _err(403, code, msg)

    # ``apply`` asks to touch the device. It is honoured only for a token that
    # holds the apply capability — a caller never elects its own privilege, and
    # a draft-only token asking to apply is told so rather than silently
    # downgraded (a silent downgrade reads as "applied" to an automation).
    want_apply = bool(body.get("apply"))
    if want_apply:
        ok, code, msg = tok.authorize_object("waf_exception_apply")
        if not ok:
            log_action("api.wpp_exception.denied",
                       extra=audit_extra(reason=code, wanted="apply"))
            return _err(403, code, msg)

    # ---- shape ----------------------------------------------------------
    appliance, err = _fortiweb_or_error(body.get("appliance_id"))
    if err:
        return err

    exc_type = str(body.get("exc_type") or "").strip()
    spec = store.type_for(exc_type)
    if spec is None or spec["category"] != ALLOWED_CATEGORY:
        return _err(400, "type_not_allowed",
                    f"'{exc_type}' is not an API-authorable carve-out type. "
                    "GET /api/v1/waf/exception-types for the allow-list.",
                    allowed=[t["key"] for t in store.catalog(ALLOWED_CATEGORY)])

    wpp_mkey = str(body.get("wpp_mkey") or "").strip()
    if not wpp_mkey:
        return _err(400, "bad_request",
                    "'wpp_mkey' (the Web Protection Profile this carve-out "
                    "belongs to) is required.")

    payload = guard.normalize_payload(body.get("payload"))
    policies = guard.normalize_policies(body.get("policies"))

    # ---- team rule 2: a template-managed profile stays clean ---------------
    lock = store.template_lock_error(wpp_mkey)
    if lock:
        return _err(409, "template_locked", lock)

    # ---- FortiWeb-base validation -----------------------------------------
    errors = store.validate_payload(exc_type, payload)
    if errors:
        return _err(400, "invalid_payload",
                    "The carve-out payload is not valid for this type.",
                    errors=errors)

    # ---- authorization: the "where" ---------------------------------------
    ok, code, msg = guard.appid_gate(tok, appliance_id=appliance.id,
                                     wpp_mkey=wpp_mkey, policies=policies)
    if not ok:
        log_action("api.wpp_exception.denied", target=f"appliance:{appliance.id}",
                   extra=audit_extra(reason=code, wpp=wpp_mkey))
        return _err(403, code, msg)

    # ---- idempotency by content -------------------------------------------
    author = guard.author_ref(tok)
    exc = guard.find_equivalent(appliance_id=appliance.id, wpp_mkey=wpp_mkey,
                                exc_type=exc_type, payload=payload,
                                policies=policies, author=author)
    created = exc is None
    if created:
        exc = store.add(appliance.id, wpp_mkey=wpp_mkey, exc_type=exc_type,
                        payload=payload, name=str(body.get("name") or "")[:128],
                        reason=str(body.get("reason") or ""), author=author,
                        policies=policies, category=ALLOWED_CATEGORY)
        log_action("api.wpp_exception.create", target=f"wpp_exception:{exc.id}",
                   extra=audit_extra(appliance_id=appliance.id, wpp=wpp_mkey,
                                     exc_type=exc_type, policies=policies))

    # ---- the device plan is ALWAYS returned, applied or not ----------------
    target = str(body.get("target") or "").strip()
    plan = exception_inject.plan_injection(exc_type, payload, target)

    out = {
        "ok": True,
        "created": created,
        "idempotent": not created,
        "exception": _exception_json(exc, appliance=appliance),
        "plan": _plan_json(plan),
        "applied": False,
    }
    if not want_apply:
        out["note"] = ("Recorded as desired state. It is NOT on the appliance "
                       "yet — an operator applies it, or use a token holding "
                       "'waf_exception_apply' with \"apply\": true.")
        return jsonify(out), (201 if created else 200)

    # ---- apply -------------------------------------------------------------
    if not target:
        out["ok"] = False
        out["error"] = "target_required"
        out["message"] = ("Applying needs 'target' — the device object the row "
                          "goes in. The record was still saved as desired state.")
        return jsonify(out), 400

    from ..services.fortiweb_ops import FortiWebOps
    res = exception_inject.apply_injection(
        FortiWebOps(appliance), exc_type=exc_type, payload=payload,
        target=target, dry_run=False,
        create_container=bool(body.get("create_container")))
    out.update(applied=True, ok=bool(res["ok"]), steps=res["steps"],
               already_present=bool(res["already_present"]),
               plan=_plan_json(res["plan"]))
    log_action("api.wpp_exception.apply", target=f"wpp_exception:{exc.id}",
               extra=audit_extra(appliance_id=appliance.id, wpp=wpp_mkey,
                                 exc_type=exc_type, device_target=target,
                                 ok=bool(res["ok"]),
                                 already_present=bool(res["already_present"])))
    return jsonify(out), (200 if res["ok"] else 502)


# --------------------------------------------------------------------------- #
#  Delete (own records only)                                                    #
# --------------------------------------------------------------------------- #
@bp.route("/waf/exceptions/<int:exc_id>", methods=["DELETE"])
@limiter.limit("30 per minute")
@token_required("write")
def waf_delete_exception(exc_id):
    """Withdraw a carve-out this token authored from desired state.

    It does NOT retract the row from the appliance. Saying otherwise would be
    the worse lie of the two: an operator reading "deleted" would believe the
    hole is closed. Removing it from the box is an operator action (the
    Exceptions page), and the response says so.
    """
    tok = g.api_token
    ok, code, msg = tok.authorize_object("waf_exception_draft")
    if not ok:
        return _err(403, code, msg)

    exc = store.get(exc_id)
    if exc is None or exc.category != ALLOWED_CATEGORY:
        return _err(404, "not_found", "No such carve-out.")
    if not guard.owned_by(exc, tok):
        # Same 404 an unknown id gets: whether an operator-authored carve-out
        # exists is not this token's business.
        return _err(404, "not_found", "No such carve-out.")
    appliance, err = _fortiweb_or_error(exc.appliance_id)
    if err:
        return err

    snapshot = _exception_json(exc, appliance=appliance)
    store.delete(exc_id)
    log_action("api.wpp_exception.delete", target=f"wpp_exception:{exc_id}",
               extra=audit_extra(appliance_id=appliance.id,
                                 wpp=snapshot["wpp_mkey"],
                                 exc_type=snapshot["exc_type"]))
    return jsonify({
        "ok": True,
        "deleted": snapshot,
        "note": ("Removed from desired state only. If it was already applied, "
                 "the entry is STILL on the appliance — an operator must "
                 "remove it there."),
    })
