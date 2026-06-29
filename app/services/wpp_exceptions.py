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


def fields_for(exc_type: str) -> list[dict]:
    """Curated fields for a type, else ``[]`` (the form offers a key/value editor)."""
    return list(FIELD_SPECS.get(exc_type, []))


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
    "CAT_EXCEPTION", "CAT_SIGNATURE", "EXCEPTION_TYPES", "SIGNATURE_TYPES",
    "CATALOG", "catalog", "type_for", "category_for", "groups", "fields_for",
    "FIELD_SPECS", "list_exceptions", "get", "add", "update", "delete",
    "delete_for_policy", "alignment",
]
