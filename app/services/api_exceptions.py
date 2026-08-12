"""The third-party carve-out surface — authorization, identity and idempotency.

``/api/v1/waf/*`` and ``/api/v1/adc/*`` let an EXTERNAL team author a WAF
carve-out without ever being handed the cmdb. Everything that decides *may this
token do this* lives here, device-free and HTTP-free, so it is testable on its
own and so the request handlers cannot grow a second copy of a rule.

Three things shape the design:

**1. The catalog IS the allow-list.** The type a caller may author comes from
``wpp_exceptions.CATALOG`` (FortiWeb) or :data:`ADC_CATALOG` (FortiADC), and the
device path is derived from that entry — never from a request field. A surface
that accepts the collection name is not a carve-out API, it is a cmdb proxy, and
``system/admin`` is one POST away.

**2. v1 offers the EXCEPTION half only.** A signature customisation edits a
shared signature SET: it has a hard 128-row cap and it applies to every policy
that binds the set. That blast radius stays operator-only.

**3. The capability is EXPLICIT-GRANT.** For the scheduled-action catalog an
empty ``capabilities`` list means "unrestricted" — a backwards-compat affordance
for tokens minted before capabilities existed. Reusing that default here would
silently hand every one of those tokens the power to author a WAF bypass, so
this surface inverts it: empty grants NOTHING.
"""
from __future__ import annotations

import hashlib
import json

# --------------------------------------------------------------------------- #
#  Capabilities (declared in models_api_token.CAPABILITIES)                    #
# --------------------------------------------------------------------------- #
WAF_DRAFT = "waf_exception_draft"
WAF_APPLY = "waf_exception_apply"
ADC_DRAFT = "adc_exception_draft"
ADC_APPLY = "adc_exception_apply"

#: Every capability on this surface. Explicit-grant only — see module docstring.
EXPLICIT_CAPS = (WAF_DRAFT, WAF_APPLY, ADC_DRAFT, ADC_APPLY)


def authorize(tok, cap: str) -> tuple[bool, str, str]:
    """Explicit-grant gate. Returns ``(ok, error_code, message)``.

    Deliberately NOT ``ApiToken.authorize_capability``: that one treats an empty
    allow-list as "unrestricted". Here an empty list means the token was never
    granted this surface at all.
    """
    if cap in (tok.capability_list or []):
        return True, "", ""
    return (False, "capability_denied",
            f"This token was not granted '{cap}'. The carve-out API is "
            "opt-in: ask an administrator to add the capability to the token.")


# --------------------------------------------------------------------------- #
#  Catalogs                                                                    #
# --------------------------------------------------------------------------- #
def waf_types() -> list[dict]:
    """The FortiWeb carve-out types a third party may author (exceptions only)."""
    from . import wpp_exceptions as store
    out = []
    for t in store.catalog(store.CAT_EXCEPTION):
        out.append({
            "key": t["key"], "label": t["label"], "group": t["group"],
            "product": "fortiweb",
            "required": list(store.REQUIRED_FIELDS.get(t["key"], [])),
            "fields": store.fields_for(t["key"]),
            "help": store.help_for(t["key"]),
        })
    return out


def waf_type_allowed(exc_type: str) -> bool:
    """Is *exc_type* an authorable EXCEPTION (never a signature customisation)?"""
    from . import wpp_exceptions as store
    t = store.type_for(exc_type)
    return bool(t) and t["category"] == store.CAT_EXCEPTION


# -- FortiADC ---------------------------------------------------------------
# FortiADC has no Web-Protection-Profile: a WAF Profile names ONE exception
# object through its ``exception_name`` field (verified live on fortiadc02
# 8.0.x — the profile rows carry it, and ``security_waf_exception`` resolves in
# the ADC registry). Identity on FortiADC is ``mkey``, not ``name``.
ADC_CATALOG: list[dict] = [
    {"key": "adc_waf_exception", "label": "WAF Exception",
     "group": "Web Application Firewall", "product": "fortiadc",
     "logical": "security_waf_exception"},
]
_ADC_BY_KEY = {t["key"]: t for t in ADC_CATALOG}

#: Only the field whose presence is PROVEN off the live device. The rest stays
#: free-form on purpose: inventing a required list that cannot be verified makes
#: legitimate payloads un-authorable, which is worse than accepting one the box
#: will reject with a readable error.
ADC_REQUIRED: dict[str, list[str]] = {"adc_waf_exception": ["mkey"]}


def adc_types() -> list[dict]:
    return [dict(t, required=list(ADC_REQUIRED.get(t["key"], [])),
                 fields=[{"key": "mkey", "label": "Name", "widget": "text"}],
                 help={"note": "Bind the object to a WAF Profile through its "
                               "'exception_name' field."})
            for t in ADC_CATALOG]


def adc_validate(exc_type: str, payload: dict) -> list[str]:
    errors = []
    for key in ADC_REQUIRED.get(exc_type, []):
        if (payload or {}).get(key) in (None, "", []):
            errors.append("'%s' is required for this carve-out type" % key)
    return errors


def adc_plan(exc_type: str, payload: dict) -> dict:
    """Resolve the single write that would create an ADC carve-out.

    Pure: the endpoint comes from the ADC registry, so a renamed/absent logical
    surfaces as ``no-endpoint`` instead of a blind POST — the same contract the
    FortiWeb planner already holds.
    """
    base = {"status": "no-endpoint", "method": "", "logical": "",
            "endpoint": "", "body": None, "error": ""}
    t = _ADC_BY_KEY.get(exc_type)
    if t is None:
        return dict(base, error=f"no inject mapping for {exc_type!r}")
    from ..registry import loader
    try:
        path = loader.load_adc_registry().get(t["logical"])
    except Exception as exc:  # noqa: BLE001 — an unreadable registry is not "ready"
        return dict(base, logical=t["logical"], error=str(exc))
    if not path:
        return dict(base, logical=t["logical"],
                    error=f"ADC registry has no endpoint {t['logical']!r}")
    return {"status": "ready", "method": "POST", "logical": t["logical"],
            "endpoint": path, "body": dict(payload or {}), "error": ""}


def adc_apply(client, exc_type: str, payload: dict, *, dry_run: bool = True) -> dict:
    """Push one ADC carve-out through a :class:`FortiADCClient`. Never raises.

    ``FortiADCClient.create`` RAISES on a device refusal (unlike ``FortiWebOps``,
    which returns a result), so the exception is caught and rendered as a failed
    step — a caller must never get a 500 for a box saying no.
    """
    plan = adc_plan(exc_type, payload)
    if plan["status"] != "ready":
        return {"ok": False, "plan": plan, "steps": [], "dry_run": dry_run}
    if dry_run:
        return {"ok": True, "plan": plan, "dry_run": True,
                "steps": [{"step": "entry", "ok": True, "note": "preview",
                           "request": {"method": "POST",
                                       "path": plan["endpoint"]},
                           "error": ""}]}
    try:
        client.create(plan["logical"], plan["body"])
    except Exception as exc:  # noqa: BLE001 — a device refusal is a result
        return {"ok": False, "plan": plan, "dry_run": False,
                "steps": [{"step": "entry", "ok": False, "note": "",
                           "request": {"method": "POST",
                                       "path": plan["endpoint"]},
                           "error": f"{type(exc).__name__}: {exc}"}]}
    return {"ok": True, "plan": plan, "dry_run": False,
            "steps": [{"step": "entry", "ok": True, "note": "",
                       "request": {"method": "POST", "path": plan["endpoint"]},
                       "error": ""}]}


# --------------------------------------------------------------------------- #
#  Identity + idempotency                                                      #
# --------------------------------------------------------------------------- #
def token_author(tok) -> str:
    """The ``author`` stamp a token writes on the rows it owns.

    Deliberately the TOKEN, not the human: ``author`` is 64 chars and a long
    username would truncate, and a truncated owner string turns the delete
    guard into a prefix match. The human is recorded in the audit receipt.
    """
    return f"api:{tok.public_id}"


def _canon(payload: dict) -> dict:
    """Values compared by CONTENT, not by JSON spelling.

    A retrying client that serialises ``1`` one time and ``"1"`` the next must
    not author the carve-out twice — the device cannot tell them apart either.
    """
    return {str(k): ("" if v is None else str(v))
            for k, v in sorted((payload or {}).items())}


def fingerprint(*, appliance_id, container: str, exc_type: str,
                payload: dict, policies) -> str:
    blob = json.dumps({
        "appliance": int(appliance_id or 0),
        "container": (container or "").strip(),
        "type": (exc_type or "").strip(),
        "payload": _canon(payload),
        "policies": sorted({(p or "").strip() for p in (policies or [])
                            if (p or "").strip()}),
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def find_duplicate(author: str, appliance_id: int, exc_type: str, fp: str):
    """An existing row of THIS author with the same fingerprint, or ``None``.

    Scoped per author on purpose: handing token B a row authored by token A
    would return an id B cannot delete — a 200 promising ownership it lacks.

    Recomputed over the author's rows for this (appliance, type) rather than
    stored in a column: a fingerprint column would need a migration, and the
    candidate set is a handful of rows.
    """
    from ..models import WppException
    rows = (WppException.query
            .filter_by(appliance_id=appliance_id, exc_type=exc_type,
                       author=author).all())
    for row in rows:
        if fingerprint(appliance_id=row.appliance_id, container=row.wpp_mkey,
                       exc_type=row.exc_type, payload=row.payload_dict,
                       policies=row.policy_names) == fp:
            return row
    return None


# --------------------------------------------------------------------------- #
#  AppID scope                                                                 #
# --------------------------------------------------------------------------- #
def appid_scope_check(tok, appliance_id: int, policies) -> tuple[bool, str, str]:
    """A token pinned to AppIDs may only author on those AppIDs' policies.

    Fails CLOSED twice over: a request that names NO policy has an unprovable
    location, and a policy outside the allow-list is refused by name.
    """
    if not tok.is_appid_scoped:
        return True, "", ""
    wanted = {(p or "").strip() for p in (policies or []) if (p or "").strip()}
    if not wanted:
        return (False, "appid_scope_unresolved",
                "This token is AppID-scoped, so a carve-out must name the "
                "server policies it is authored for.")
    from . import appids
    allowed = appids.token_scope_targets(tok.app_id_list, product=tok.product)
    outside = {p for p in wanted if (appliance_id, p) not in allowed}
    if outside:
        return (False, "appid_scope_denied",
                "These server policies are outside your AppID scope: "
                + ", ".join(sorted(outside)))
    return True, "", ""


def visible_rows(tok, rows):
    """Filter authored rows down to what this token is entitled to SEE.

    A row bound to one in-scope policy AND one out-of-scope policy is hidden:
    showing it would disclose the name of a policy the caller has no claim on.
    """
    if not tok.is_appid_scoped:
        return list(rows)
    from . import appids
    allowed = appids.token_scope_targets(tok.app_id_list, product=tok.product)
    out = []
    for r in rows:
        names = r.policy_names
        if names and all((r.appliance_id, n) in allowed for n in names):
            out.append(r)
    return out


__all__ = [
    "WAF_DRAFT", "WAF_APPLY", "ADC_DRAFT", "ADC_APPLY", "EXPLICIT_CAPS",
    "authorize", "waf_types", "waf_type_allowed",
    "ADC_CATALOG", "ADC_REQUIRED", "adc_types", "adc_validate", "adc_plan",
    "adc_apply", "token_author", "fingerprint", "find_duplicate",
    "appid_scope_check", "visible_rows",
]
