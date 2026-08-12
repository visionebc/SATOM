"""Shared guards for the /api/v1 OBJECT-write surface (WAF carve-outs, ADC rules).

``/api/v1`` used to be read-biased: the only mutation was triggering a catalog
action an operator had already created. This module backs the step that lets an
external team author a rule of its own, and it exists because that step needs
four guarantees the route layer should not re-implement per resource:

1. **Ownership.** Every API-authored record carries ``author = "api:<public_id>"``.
   A token may only edit/delete what IT created — otherwise an external team
   could retract a carve-out an operator put in place.
2. **Idempotency by CONTENT, not by header.** A SOAR/CI caller retries. The
   device is protected by FortiWeb's own duplicate errcode, but the desired-state
   TABLE is not: a retried POST would leave two identical rows and the alignment
   report would double-count. Dedupe is on the normalised (appliance, wpp, type,
   payload, policies) tuple, so it also collapses a retry that arrives after a
   restart or from a different process — which an in-memory Idempotency-Key
   cache would not.
3. **AppID scope.** An AppID-scoped token may only author carve-outs for its own
   server policies, and must NAME them. Fail closed.
4. **Blast radius of a SHARED profile.** This is the one that is easy to miss: a
   Web Protection Profile is usually bound to SEVERAL server policies, so an
   exception authored "for my app" silently applies to every other app on the
   same profile. Ownership of the policies you listed is NOT ownership of the
   profile. An AppID-scoped token is refused when the target WPP is bound to a
   policy outside its scope.

Pure-ish: no Flask, no device. The routes supply ids and payloads.
"""
from __future__ import annotations

import json
from typing import Any

from ..models import WppException

#: Prefix that marks a desired-state record as API-authored. The public id (not
#: the secret, never the secret) makes the author both stable and revocable-
#: traceable: revoking token ``fmk_ab12…`` tells you exactly which rows it owns.
AUTHOR_PREFIX = "api:"


def author_ref(tok) -> str:
    """The ``author`` string a record created by *tok* carries."""
    return f"{AUTHOR_PREFIX}{tok.public_id}"


def is_api_authored(exc) -> bool:
    return str(getattr(exc, "author", "") or "").startswith(AUTHOR_PREFIX)


def owned_by(exc, tok) -> bool:
    """May *tok* mutate *exc*? Only if the token authored it."""
    return str(getattr(exc, "author", "") or "") == author_ref(tok)


# --------------------------------------------------------------------------- #
#  Normalisation + content idempotency                                          #
# --------------------------------------------------------------------------- #
def normalize_payload(payload: Any) -> dict:
    """Canonical form of a carve-out payload for storage AND comparison.

    Values are stringified and trimmed, empties dropped. Both jobs must use the
    SAME function: normalising only on the way in would let a retry that sends
    ``"80 "`` instead of ``"80"`` create a second row that the device then
    rejects as a duplicate — a divergence between the store and the box that
    nothing else would surface.
    """
    if not isinstance(payload, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in payload.items():
        key = str(k).strip()
        if not key:
            continue
        if isinstance(v, bool):
            val = "enable" if v else "disable"
        elif isinstance(v, (list, tuple)):
            val = " ".join(str(x).strip() for x in v if str(x).strip())
        else:
            val = str(v if v is not None else "").strip()
        if val == "":
            continue
        out[key] = val
    return out


def normalize_policies(policies: Any) -> list[str]:
    if isinstance(policies, str):
        policies = [policies]
    if not isinstance(policies, (list, tuple)):
        return []
    return sorted({str(p).strip() for p in policies if str(p).strip()})


def content_key(*, appliance_id: int, wpp_mkey: str, exc_type: str,
                payload: dict, policies: list[str]) -> str:
    """Stable identity of a carve-out's CONTENT (the idempotency key)."""
    return json.dumps({
        "appliance_id": int(appliance_id),
        "wpp": (wpp_mkey or "").strip(),
        "type": (exc_type or "").strip(),
        "payload": normalize_payload(payload),
        "policies": normalize_policies(policies),
    }, sort_keys=True, separators=(",", ":"))


def exception_content_key(exc) -> str:
    return content_key(appliance_id=exc.appliance_id or 0, wpp_mkey=exc.wpp_mkey,
                       exc_type=exc.exc_type, payload=exc.payload_dict,
                       policies=exc.policy_names)


def find_equivalent(*, appliance_id: int, wpp_mkey: str, exc_type: str,
                    payload: dict, policies: list[str], author: str):
    """An existing record by the SAME author with identical content, or None.

    Scoped to the author on purpose: two teams may legitimately author the same
    carve-out for different reasons, and collapsing those would give team B a
    row it cannot delete (it is not the owner) and silently drop its ``reason``.
    """
    want = content_key(appliance_id=appliance_id, wpp_mkey=wpp_mkey,
                       exc_type=exc_type, payload=payload, policies=policies)
    rows = (WppException.query
            .filter_by(appliance_id=appliance_id, author=author,
                       exc_type=exc_type)
            .all())
    for row in rows:
        if exception_content_key(row) == want:
            return row
    return None


# --------------------------------------------------------------------------- #
#  AppID scope + shared-profile blast radius                                    #
# --------------------------------------------------------------------------- #
def wpp_blast_radius(appliance_id: int, wpp_mkey: str) -> set[str] | None:
    """Server policies on *appliance_id* bound to *wpp_mkey*.

    DB-first over the cached server policies (zero device calls). ``None`` means
    "could not tell" — an empty/absent cache. The caller must treat None as
    UNPROVABLE and fail closed for a scoped token, exactly like
    :func:`appids.policies_using_pool`: an unread cache is not evidence that the
    profile is unshared.
    """
    wpp_mkey = (wpp_mkey or "").strip()
    if not wpp_mkey:
        return set()
    from . import read_layer
    try:
        payloads, _meta = read_layer.read_objects(appliance_id, "server_policy")
    except Exception:  # noqa: BLE001 — unreadable cache ⇒ unprovable
        return None
    if not payloads:
        return None
    return {str(p["name"]) for p in payloads
            if isinstance(p, dict) and p.get("name")
            and str(p.get("web-protection-profile") or "").strip() == wpp_mkey}


def appid_gate(tok, *, appliance_id: int, wpp_mkey: str,
               policies: list[str]) -> tuple[bool, str, str]:
    """Enforce the token's AppID scope over an authored carve-out.

    Returns ``(ok, error_code, message)``. An unscoped token passes untouched —
    its reach is already bounded by product + owner RBAC.
    """
    from . import appids

    if not tok.is_appid_scoped:
        return (True, "", "")

    policies = normalize_policies(policies)
    if not policies:
        return (False, "appid_scope_unresolved",
                "This token is AppID-scoped, so a carve-out must name the "
                "server policies it is authored for (field 'policies').")

    allowed = appids.token_scope_targets(tok.app_id_list, product=tok.product)
    outside = {p for p in policies if (appliance_id, p) not in allowed}
    if outside:
        return (False, "appid_scope_denied",
                "Server polic(ies) outside your AppID scope: "
                + ", ".join(sorted(outside)))

    # The profile is the real blast radius — owning the policies you listed is
    # not owning the profile they share.
    bound = wpp_blast_radius(appliance_id, wpp_mkey)
    if bound is None:
        return (False, "wpp_scope_unprovable",
                f"Could not confirm which server policies bind the Web "
                f"Protection Profile '{wpp_mkey}' (device objects are not "
                "cached). A carve-out on a shared profile applies to every "
                "policy that binds it, so this is refused rather than guessed. "
                "Ask an operator to sync the appliance.")
    shared_outside = {p for p in bound if (appliance_id, p) not in allowed}
    if shared_outside:
        return (False, "wpp_shared_denied",
                f"'{wpp_mkey}' is also bound to server polic(ies) outside your "
                "AppID scope (" + ", ".join(sorted(shared_outside)) + "). An "
                "exception on a shared profile applies to all of them. Ask an "
                "operator for a dedicated profile (clone + rebind).")
    return (True, "", "")


__all__ = [
    "AUTHOR_PREFIX", "author_ref", "is_api_authored", "owned_by",
    "normalize_payload", "normalize_policies", "content_key",
    "exception_content_key", "find_equivalent", "wpp_blast_radius", "appid_gate",
]
