"""Desired-state WAF / signature carve-outs — catalog, field specs & store.

The web port of the desktop ``services.exceptions`` + the Exceptions page
catalog. It does three things, all device-free (the device stays source of
truth; pushing a carve-out onto a box is a separate, later step):

* **CATALOG** — the menu of carve-out TYPES the operator can author, grouped the
  FortiWeb way and split into WAF *exceptions* and *signature* customisations.
* **FIELD_SPECS** — the curated, FortiWeb-faithful field set per type (labels +
  widgets + enums, from the 7.6.4 admin guide / SDK), so the authoring form
  renders proper inputs instead of raw JSON. A type with no spec falls back to a
  free-form key/value editor — nothing is ever un-authorable.
* **store** — CRUD over ``WppException`` + the per-Server-Policy junction
  (``WppExceptionPolicy``), the alignment report, and the clean-migration purge.

Why it exists: a Web Protection Profile is usually SHARED, so an exception on it
applies to every policy that binds it and FortiWeb cannot say which policy a
carve-out was authored for. This records that intent. NEVER secrets.
"""
from __future__ import annotations

import json
from typing import Any

from ..models import WppException, WppExceptionPolicy, db

CAT_EXCEPTION = WppException.CAT_EXCEPTION
CAT_SIGNATURE = WppException.CAT_SIGNATURE

# FortiWeb hard cap: a signature set's ``filter_list`` (per-signature exception
# entries) holds at most 128 rows — verified live on fw1 7.6.8 and documented in
# the admin guide. Surfaced on the inject flow so the operator sees headroom.
SIG_FILTER_MAX = 128


def template_lock_error(wpp_mkey: str) -> str:
    """Team rule 2: a template-managed WPP stays CLEAN — no carve-outs on it.

    Returns a non-empty, human-readable reason when ``wpp_mkey`` names a Web
    Protection Profile governed by an APPROVED template (the same lock objedit
    enforces). Empty string = not locked."""
    if not wpp_mkey:
        return ""
    from .templates import managed_wpp_names
    if str(wpp_mkey) in managed_wpp_names():
        return ('"%s" is a template-managed Web Protection Profile — templates '
                'stay clean (no exceptions). Clone it for the Server Policy and '
                'author the carve-out on the clone.' % wpp_mkey)
    return ""


# --------------------------------------------------------------------------- #
#  Type catalog (GUI group · label · spec key · category)                       #
# --------------------------------------------------------------------------- #
def _t(key, label, group, category):
    return {"key": key, "label": label, "group": group, "category": category}


EXCEPTION_TYPES: list[dict] = [
    _t("http_constraint_exception_item", "HTTP Protocol Constraints", "Standard Protection", CAT_EXCEPTION),
    _t("allow_method_exception_item", "Allow Method", "Standard Protection", CAT_EXCEPTION),
    _t("geo_ip_exception_member_item", "Geo IP Block List", "Standard Protection", CAT_EXCEPTION),
    _t("syntax_exception_item", "Syntax-Based Detection", "Standard Protection", CAT_EXCEPTION),
    _t("bot_exception_element_item", "Bot Mitigation", "Standard Protection", CAT_EXCEPTION),
    _t("http_header_security_exception_item", "HTTP Header Security", "Client-Side Security", CAT_EXCEPTION),
    _t("cookie_security_exception_item", "Cookie Security", "Client-Side Security", CAT_EXCEPTION),
    _t("url_enc_exc_item", "URL Encryption", "Advanced Protection", CAT_EXCEPTION),
    _t("link_cloak_exc_item", "Link Cloaking", "Advanced Protection", CAT_EXCEPTION),
    _t("file_exception_item", "File Security", "Advanced Protection", CAT_EXCEPTION),
]

SIGNATURE_TYPES: list[dict] = [
    _t("signature_filter_item", "Signature Exception (per-id)", "Signature", CAT_SIGNATURE),
    _t("signature_disable_item", "Disabled Signature", "Signature", CAT_SIGNATURE),
    _t("signature_alert_only_item", "Alert-Only Signature", "Signature", CAT_SIGNATURE),
    _t("signature_subclass_disable_item", "Disabled Sub-Class", "Signature", CAT_SIGNATURE),
    _t("signature_class_action", "Class Action Override", "Signature", CAT_SIGNATURE),
    _t("signature_group_rule_condition", "Custom Rule Meet-Condition", "Signature", CAT_SIGNATURE),
]

CATALOG: list[dict] = EXCEPTION_TYPES + SIGNATURE_TYPES
_BY_KEY: dict[str, dict] = {t["key"]: t for t in CATALOG}


def catalog(category: str | None = None) -> list[dict]:
    if category is None:
        return list(CATALOG)
    return [t for t in CATALOG if t["category"] == category]


def type_for(key: str) -> dict | None:
    return _BY_KEY.get(key)


def category_for(key: str) -> str:
    t = _BY_KEY.get(key)
    return t["category"] if t else CAT_EXCEPTION


def groups(category: str) -> list[str]:
    """Ordered, de-duplicated GUI groups present for a category (for the picker)."""
    seen: list[str] = []
    for t in catalog(category):
        if t["group"] not in seen:
            seen.append(t["group"])
    return seen


# --------------------------------------------------------------------------- #
#  Field specs (FortiWeb 7.6.4 admin guide / SDK). widget ∈ text|enum|toggle.   #
# --------------------------------------------------------------------------- #
def _f(key, label, widget="text", options=None):
    return {"key": key, "label": label, "widget": widget, "options": options or []}


FIELD_SPECS: dict[str, list[dict]] = {
    "signature_filter_item": [
        _f("signature_id", "Signature ID"),
        _f("match-target", "Element Type", "enum",
           ["HTTP_METHOD", "CLIENT_IP", "HOST", "URI", "FULL_URL", "PARAMETER",
            "COOKIE", "HTTP_HEADER", "JSON_ELEMENTS"]),
        _f("operator", "Operation", "enum",
           ["STRING_MATCH", "REGEXP_MATCH", "EQ", "NE", "INCLUDE", "EXCLUDE"]),
        _f("http-method", "HTTP Method"),
        _f("ip", "Client IP"),
        _f("name", "Name"),
        _f("value-check", "Check Value", "toggle"),
        _f("value", "Value"),
        _f("concatenate-type", "Concatenate", "enum", ["AND", "OR"]),
    ],
    "http_constraint_exception_item": [
        _f("host-status", "Host Status", "toggle"), _f("host", "Host"),
        _f("source-ip-status", "Source IP Status", "toggle"), _f("source-ip", "Source IP"),
        _f("request-type", "Request Type", "enum", ["plain", "regular"]),
        _f("request-file", "URL Pattern"),
    ],
    "allow_method_exception_item": [
        _f("host-status", "Host Status", "toggle"), _f("host", "Host"),
        _f("request-type", "Type", "enum", ["plain", "regular"]),
        _f("request-file", "URL Pattern"),
        _f("allow-request", "Allow Method Exception (space-separated)"),
    ],
    "geo_ip_exception_member_item": [_f("ip", "IP / IP Range")],
    "syntax_exception_item": [
        _f("match-target", "Element Type", "enum",
           ["HOST", "URI", "FULL-URL", "PARAMETER", "COOKIE"]),
        _f("operator", "Operation", "enum", ["STRING_MATCH", "REGEXP_MATCH"]),
        _f("value-name", "Name"), _f("value-check", "Check Value", "toggle"),
        _f("value", "Value"), _f("attack-type", "Attack Type"),
        _f("concatenate-type", "Concatenate", "enum", ["AND", "OR"]),
    ],
    "bot_exception_element_item": [
        _f("match-target", "Element Type", "enum",
           ["Client IP", "Host", "URI", "Full URL", "Parameter", "Cookie"]),
        _f("operator", "Operation"), _f("ip-range", "Client IP"),
        _f("value-name", "Name"), _f("value-check", "Check Value", "toggle"),
        _f("value", "Value"), _f("concatenate-type", "Concatenate", "enum", ["and", "or"]),
    ],
    "http_header_security_exception_item": [
        _f("client-ip-status", "Client IP", "toggle"), _f("client-ip", "IPv4/IPv6/Range"),
        _f("request-url-type", "Request URL Type", "enum", ["plain", "regular"]),
        _f("request-url-pattern", "Request URL"),
    ],
    "cookie_security_exception_item": [
        _f("cookie-name", "Cookie Name"), _f("cookie-domain", "Cookie Domain"),
        _f("cookie-path", "Cookie Path"),
    ],
    "url_enc_exc_item": [
        _f("url-type", "Type", "enum", ["plain", "regular"]), _f("url-pattern", "Request URL"),
    ],
    "link_cloak_exc_item": [
        _f("url-type", "Type", "enum", ["plain", "regular"]), _f("url-pattern", "URL Pattern"),
    ],
    "file_exception_item": [
        _f("file-name", "File Name"), _f("md5", "MD5"), _f("comment", "Comment"),
    ],
    "signature_disable_item": [_f("signature_id", "Signature ID")],
    "signature_alert_only_item": [_f("signature_id", "Signature ID")],
    "signature_subclass_disable_item": [_f("sub_class_id", "Sub-Class ID")],
    "signature_class_action": [
        _f("main_class_id", "Main Class ID"),
        _f("action", "Action", "enum",
           ["alert", "block", "alert_deny", "deny_no_log", "period_block"]),
        _f("severity", "Severity", "enum", ["Informative", "Low", "Medium", "High"]),
    ],
    "signature_group_rule_condition": [
        _f("match-target", "Element Type"), _f("operator", "Operation"), _f("value", "Value"),
    ],
}


# exc_type → engine kind, where the names differ (the class-action override
# edits a row of the signature set's main_class_list).
_KIND_ALIAS = {"signature_class_action": "signature_class_item"}

# Required payload fields per type — the FortiWeb-base discipline: a carve-out
# missing its match key is garbage the box either rejects or (worse) applies
# too broadly. Enforced in the save endpoint + marked * in the form.
REQUIRED_FIELDS: dict[str, list[str]] = {
    "signature_filter_item": ["signature_id", "match-target"],
    "signature_disable_item": ["signature_id"],
    "signature_alert_only_item": ["signature_id"],
    "signature_subclass_disable_item": ["sub_class_id"],
    "signature_class_action": ["main_class_id", "action"],
    "http_constraint_exception_item": ["request-type", "request-file"],
    "allow_method_exception_item": ["request-type", "request-file"],
    "geo_ip_exception_member_item": ["ip"],
    "syntax_exception_item": ["match-target", "operator"],
    "bot_exception_element_item": ["match-target", "operator"],
    "http_header_security_exception_item": ["request-url-type", "request-url-pattern"],
    "cookie_security_exception_item": ["cookie-name"],
    "url_enc_exc_item": ["url-type", "url-pattern"],
    "link_cloak_exc_item": ["url-type", "url-pattern"],
    "file_exception_item": ["file-name"],
    "signature_group_rule_condition": ["match-target", "operator", "value"],
}

# Light format validators (key → (regex, message)). Only formats FortiWeb is
# strict about; anything else stays free so nothing becomes un-authorable.
_FORMAT_RULES: dict[str, tuple[str, str]] = {
    "signature_id": (r"^\d{9,10}$", "Signature ID is the 9-digit id (e.g. 010000001)"),
    "sub_class_id": (r"^\d{9,10}$", "Sub-Class ID is the 9-digit id"),
    "main_class_id": (r"^\d{9,10}$", "Main Class ID is the 9-digit id (e.g. 010000000)"),
    "request-file": (r"^/", "URL patterns must start with /"),
    "url-pattern": (r"^/", "URL patterns must start with /"),
    "request-url-pattern": (r"^/", "Request URL must start with /"),
}


def validate_payload(exc_type: str, payload: dict) -> list[str]:
    """FortiWeb-base validation: required fields present + strict formats OK.
    Returns a list of human-readable errors (empty = valid)."""
    import re as _re
    errors = []
    payload = payload or {}
    for key in REQUIRED_FIELDS.get(exc_type, []):
        if payload.get(key) in (None, "", []):
            errors.append("'%s' is required for this carve-out type" % key)
    for key, (rx, msg) in _FORMAT_RULES.items():
        val = payload.get(key)
        if val not in (None, "", []) and not _re.match(rx, str(val)):
            errors.append(msg)
    return errors


def fields_for(exc_type: str) -> list[dict]:
    """Field descriptors for a type — derived from the SAME curated WAF engine
    the object editor uses (labels, device enum tokens with GUI display labels,
    toggles, regex affordance, and the FortiWeb ``show_when`` gating that shows
    only the inputs relevant to the chosen Element Type — so the operator can't
    author contradictory garbage). Falls back to the static seed for any type
    the engine doesn't model."""
    from .fortiweb_field_schema import KIND_SPECS, descriptor, kind_keys

    kind = _KIND_ALIAS.get(exc_type, exc_type)
    required = set(REQUIRED_FIELDS.get(exc_type, ()))
    if kind in KIND_SPECS:
        out = []
        for key in kind_keys(kind):
            if key == "id":
                continue
            d = descriptor(kind, key, "", {})
            d["required"] = key in required
            out.append(d)
        if out:
            return out
    flat = []
    for f in FIELD_SPECS.get(exc_type, []):
        f = dict(f)
        f["required"] = f["key"] in required
        flat.append(f)
    return flat


# --------------------------------------------------------------------------- #
#  Per-type guidance: what it does + how the DEVICE reacts once injected.       #
#  Shown in the authoring form so the operator understands the blast radius.    #
# --------------------------------------------------------------------------- #
TYPE_HELP: dict[str, dict] = {
    "signature_filter_item": {
        "what": "Exempts ONE signature id from matching when the chosen request element matches your value — the FortiWeb 'Signature Details → Exception' tab.",
        "backend": "After inject, requests where the element matches skip that signature only; every other signature still applies. Max 128 exceptions per signature.",
        "base": "Use this instead of disabling a signature: the signature stays active for the rest of the site.",
    },
    "signature_disable_item": {
        "what": "Turns one signature id fully OFF in the signature set.",
        "backend": "The device stops evaluating that signature for EVERY policy that binds this set — traffic matching the attack pattern passes uninspected.",
        "base": "Prefer a per-element Signature Exception; disable only when the signature is a confirmed false positive everywhere.",
    },
    "signature_alert_only_item": {
        "what": "Keeps one signature detecting but downgrades its action to Alert.",
        "backend": "Matching requests are LOGGED but never blocked — the attack reaches the back-end.",
        "base": "Good as a staging step before re-enabling blocking.",
    },
    "signature_subclass_disable_item": {
        "what": "Disables a whole signature SUB-CLASS (hundreds of signatures).",
        "backend": "The device skips the entire sub-class for every bound policy — a wide hole.",
        "base": "Almost always too broad; prefer per-signature carve-outs.",
    },
    "signature_class_action": {
        "what": "Overrides the ACTION/severity of a signature main class (e.g. all SQL Injection).",
        "backend": "Every signature in the class fires with your action: Alert = log only, Alert & Deny = block + log, Period Block = block the client IP for the block period.",
        "base": "Pushed as an UPDATE to the existing class row on the signature set.",
    },
    "http_constraint_exception_item": {
        "what": "Exempts a host/URL from selected HTTP protocol constraint checks.",
        "backend": "Requests matching host+URL skip only the constraints you toggle on; the rest keep enforcing.",
        "base": "Pattern must start with /. With Type=Regular Expression, prove it in the regex calculator first.",
    },
    "allow_method_exception_item": {
        "what": "Allows extra HTTP methods on specific hosts/URLs beyond the policy's allow-list.",
        "backend": "Matching requests may use the extra methods; others still get the policy's method action (usually Alert & Deny).",
        "base": "Methods are space-separated device tokens: get post put delete …",
    },
    "geo_ip_exception_member_item": {
        "what": "Lets specific IPs/ranges through a Geo IP country block.",
        "backend": "Those sources bypass the geo block entirely for bound policies; everyone else in the blocked country is still denied (Alert & Deny / Period Block).",
        "base": "One IP or range per entry.",
    },
    "syntax_exception_item": {
        "what": "Exempts an element from SQL/XSS syntax-based detection for one attack type.",
        "backend": "The parser skips that attack-type evaluation when the element matches; other attack types keep firing.",
        "base": "Pick the NARROWEST attack type that false-positives — never blanket all of them.",
    },
    "bot_exception_element_item": {
        "what": "Excludes matching traffic from Bot Mitigation checks.",
        "backend": "Matching requests skip bot biometrics/thresholds/known-bot checks for bound policies.",
        "base": "Typical use: health checks, monitoring probes, internal automation IPs.",
    },
    "http_header_security_exception_item": {
        "what": "Skips HTTP header-security insertion for matching client IP / URL.",
        "backend": "Responses to matching requests are served WITHOUT the injected security headers.",
        "base": "URL must start with /; regex type available.",
    },
    "cookie_security_exception_item": {
        "what": "Exempts one cookie (by name/domain/path) from cookie security.",
        "backend": "That cookie is not signed/encrypted/enforced; all other cookies stay protected.",
        "base": "Needed for third-party cookies the back-end must read raw.",
    },
    "url_enc_exc_item": {
        "what": "Excludes URLs from URL Encryption.",
        "backend": "Matching URLs are served in clear (not encrypted) while the rest of the app keeps encrypted links.",
        "base": "Required for URLs consumed by external systems / deep links.",
    },
    "link_cloak_exc_item": {
        "what": "Excludes URLs from Link Cloaking.",
        "backend": "Matching links are not rewritten/cloaked in responses.",
        "base": "Same pattern rules as URL Encryption.",
    },
    "file_exception_item": {
        "what": "Allows a specific file (name + MD5) past File Security / AV scanning.",
        "backend": "Uploads matching name+hash bypass file-type and AV checks; anything else is still scanned.",
        "base": "Always pin the MD5 — a name-only exception is a hole.",
    },
    "signature_group_rule_condition": {
        "what": "A meet-condition row of a CUSTOM signature rule.",
        "backend": "The custom rule fires only when its conditions match (per the rule's logic); its action then applies.",
        "base": "Operators: RE (regex), GT/LT (numeric), EQ/NE.",
    },
}


def help_for(exc_type: str) -> dict:
    return TYPE_HELP.get(exc_type, {})


# --------------------------------------------------------------------------- #
#  Store (CRUD + junction + alignment + purge)                                  #
# --------------------------------------------------------------------------- #
def list_exceptions(appliance_id: int, category: str | None = None) -> list[WppException]:
    q = WppException.query.filter_by(appliance_id=appliance_id)
    if category:
        q = q.filter_by(category=category)
    return q.order_by(WppException.wpp_mkey, WppException.id).all()


def get(exc_id: int) -> WppException | None:
    return WppException.query.get(exc_id)


def _set_policies(exc: WppException, policies: list[str]) -> None:
    """Reconcile the policy bindings INCREMENTALLY (add/remove the delta).

    Replacing the whole collection would make SQLAlchemy insert the new rows
    before deleting the old ones — and with the (exception_id, server_policy)
    UNIQUE constraint that fails when a name is kept across the change. Diffing
    keeps unchanged rows untouched, so only true adds/removes hit the DB.
    """
    wanted = {p.strip() for p in (policies or []) if p and p.strip()}
    existing = {p.server_policy: p for p in list(exc.policies)}
    for name, row in existing.items():
        if name not in wanted:
            exc.policies.remove(row)          # delete-orphan → DELETE on flush
    for name in sorted(wanted):
        if name not in existing:
            exc.policies.append(WppExceptionPolicy(server_policy=name))


def add(appliance_id: int, *, wpp_mkey: str, exc_type: str, payload: dict,
        name: str = "", reason: str = "", author: str = "",
        policies: list[str] | None = None, category: str | None = None) -> WppException:
    exc = WppException(
        appliance_id=appliance_id, wpp_mkey=wpp_mkey or "",
        exc_type=exc_type, category=category or category_for(exc_type),
        name=name or "", payload=json.dumps(payload or {}),
        reason=reason or "", author=author or "",
    )
    _set_policies(exc, policies or [])
    db.session.add(exc)
    db.session.commit()
    return exc


def update(exc_id: int, *, wpp_mkey: str | None = None, payload: dict | None = None,
           name: str | None = None, reason: str | None = None,
           enabled: bool | None = None, policies: list[str] | None = None) -> WppException | None:
    exc = get(exc_id)
    if exc is None:
        return None
    if wpp_mkey is not None:
        exc.wpp_mkey = wpp_mkey
        # Re-pointing the carve-out at a profile resolves a lifecycle-stale flag
        # (the operator has made a decision — the record is current again).
        if getattr(exc, "stale", False):
            exc.stale = False
            exc.stale_reason = ""
    if payload is not None:
        exc.payload = json.dumps(payload or {})
    if name is not None:
        exc.name = name
    if reason is not None:
        exc.reason = reason
    if enabled is not None:
        exc.enabled = bool(enabled)
    if policies is not None:
        _set_policies(exc, policies)
    db.session.commit()
    return exc


def delete(exc_id: int) -> bool:
    exc = get(exc_id)
    if exc is None:
        return False
    db.session.delete(exc)
    db.session.commit()
    return True


def delete_for_policy(appliance_id: int, server_policy: str,
                      category: str | None = None) -> int:
    """Clean-migration purge: unbind *server_policy* from every carve-out and
    delete any carve-out left with no policies. Returns the deleted count."""
    deleted = 0
    for exc in list_exceptions(appliance_id, category):
        names = set(exc.policy_names)
        if server_policy not in names:
            continue
        names.discard(server_policy)
        if names:
            _set_policies(exc, sorted(names))
        else:
            db.session.delete(exc)
            deleted += 1
    db.session.commit()
    return deleted


def mark_stale_for_policy(appliance_id: int, server_policy: str,
                          new_wpp: str = "", reason: str = "") -> int:
    """Lifecycle hook (rule 1): the device-side WPP of *server_policy* changed.

    Flags every carve-out bound to that policy whose recorded ``wpp_mkey`` no
    longer matches the policy's new profile. Nothing is deleted — the operator
    decides on the Exceptions page whether each record migrates to the new
    profile or dies. Returns the number of records flagged."""
    n = 0
    for exc in list_exceptions(appliance_id):
        if server_policy not in exc.policy_names:
            continue
        if exc.wpp_mkey and new_wpp and exc.wpp_mkey == new_wpp:
            continue                       # already points at the new profile
        if getattr(exc, "stale", False):
            continue
        exc.stale = True
        exc.stale_reason = reason or (
            'Server Policy "%s" was re-bound to WPP "%s" — this carve-out still '
            'points at "%s".' % (server_policy, new_wpp or "?", exc.wpp_mkey or "?"))
        n += 1
    if n:
        db.session.commit()
    return n


def retarget_for_policy(appliance_id: int, server_policy: str,
                        old_wpp: str, new_wpp: str) -> int:
    """Move every carve-out bound to *server_policy* from *old_wpp* to
    *new_wpp* (the guided clone+rebind flow) and clear any stale flag.
    Returns the number of records moved."""
    n = 0
    for exc in list_exceptions(appliance_id):
        if server_policy not in exc.policy_names:
            continue
        if old_wpp and exc.wpp_mkey and exc.wpp_mkey != old_wpp:
            continue
        if exc.wpp_mkey == new_wpp and not getattr(exc, "stale", False):
            continue
        exc.wpp_mkey = new_wpp
        exc.stale = False
        exc.stale_reason = ""
        n += 1
    if n:
        db.session.commit()
    return n


def alignment(appliance_id: int, bindings: dict[str, str]) -> dict[str, Any]:
    """Join authored carve-outs with the device's live ``policy → wpp`` bindings.

    Returns ``{per_policy: {policy: [exc, …]}, stale: [exc, …]}`` — *stale* =
    carve-outs whose (policy, wpp) no longer matches a live binding (policy
    renamed/removed, or its bound WPP swapped)."""
    per_policy: dict[str, list] = {p: [] for p in bindings}
    stale: list = []
    for exc in list_exceptions(appliance_id):
        matched = False
        for pol in exc.policy_names:
            live_wpp = bindings.get(pol)
            if live_wpp is not None and (not exc.wpp_mkey or live_wpp == exc.wpp_mkey):
                per_policy.setdefault(pol, []).append(exc)
                matched = True
        if not matched:
            stale.append(exc)
    return {"per_policy": per_policy, "stale": stale}


__all__ = [
    "CAT_EXCEPTION", "CAT_SIGNATURE", "SIG_FILTER_MAX",
    "EXCEPTION_TYPES", "SIGNATURE_TYPES",
    "CATALOG", "catalog", "type_for", "category_for", "groups", "fields_for",
    "validate_payload", "help_for", "TYPE_HELP", "template_lock_error",
    "FIELD_SPECS", "list_exceptions", "get", "add", "update", "delete",
    "delete_for_policy", "mark_stale_for_policy", "retarget_for_policy",
    "alignment",
]
