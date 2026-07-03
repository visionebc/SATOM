"""Curated WAF / Web-Protection-Profile edit specs — the web port of the
desktop's ``wpp_specs.py`` (165 ObjectSpecs, FortiWeb 7.6/8.0 SDK + admin-guide
validated).

The catalog itself is DATA (``app/registry/data/waf_specs.json``, generated from
the desktop repo — regenerate there, never hand-edit) plus an optional help
overlay (``app/registry/data/waf_help.json``, distilled from the FortiWeb 7.6.4
admin guide via Firecrawl: per-section "what is this / how does the backend
react", the action semantics, and regex examples).

At import :func:`register` merges everything into the existing engine:

* ``fortiweb_field_schema.KIND_SPECS`` gains one entry per WAF object kind
  (enums with device tokens, refs resolved to cmdb collections, toggles,
  numbers, per-kind field/group ORDER, ``show_when`` visibility gating and
  display ``value_labels``) — so :func:`fortiweb_field_schema.descriptor`
  renders every WAF object like the FortiWeb GUI instead of raw text inputs.
* ``objform._KIND_BY_COLL`` maps each WAF cmdb collection to its kind, and
  sub-table labels pick up the FortiWeb GUI titles ("Rule List", "Signature
  Exceptions" …).

Pure data + registration — no Flask, no device.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                         "registry", "data")


def _load(name: str) -> dict:
    try:
        with open(os.path.join(_DATA_DIR, name), "r", encoding="utf-8") as fh:
            return json.load(fh) or {}
    except Exception:  # noqa: BLE001 — a missing overlay must never break boot
        return {}


@lru_cache(maxsize=1)
def catalog() -> dict:
    """The generated spec catalog (kinds / kind_by_coll / value_labels / …)."""
    return _load("waf_specs.json")


@lru_cache(maxsize=1)
def help_data() -> dict:
    """The admin-guide help overlay (sections / actions / regex guide)."""
    return _load("waf_help.json")


# --------------------------------------------------------------------------- #
#  Accessors                                                                    #
# --------------------------------------------------------------------------- #
def kinds() -> dict:
    return catalog().get("kinds", {})


def kind_by_coll() -> dict:
    return catalog().get("kind_by_coll", {})


def value_labels() -> dict:
    return catalog().get("value_labels", {})


def subtable_titles() -> dict:
    return catalog().get("subtable_titles", {})


def wpp_sections() -> list:
    """The 36 WPP sub-policy dropdowns in FortiWeb menu order
    (section / label / wire field / target collection)."""
    return catalog().get("wpp_sections", [])


def action_explanations() -> dict:
    """``action token → what FortiWeb does when it fires`` (admin guide)."""
    return help_data().get("actions", {})


def section_help(kind: str) -> dict:
    """Per-kind help: what the section does + how the backend reacts."""
    helps = help_data().get("sections", {})
    key = _HELP_KEY_BY_KIND.get(kind, kind)
    return helps.get(key, {})


def regex_guide() -> dict:
    return help_data().get("regex_guide", {})


# kind (spec key) → waf_help.json section key, for the kinds whose names differ.
_HELP_KEY_BY_KIND = {
    "signature": "signatures",
    "http_constraint": "http_constraints",
    "http_constraint_exception": "http_constraints",
    "allow_method_policy": "allow_method",
    "allow_method_exception": "allow_method",
    "ip_list": "ip_list",
    "geo_ip": "geo_ip",
    "geo_ip_exception": "geo_ip",
    "url_access_policy": "url_access",
    "url_access_rule": "url_access",
    "custom_policy": "custom_access",
    "custom_rule": "custom_access",
    "ddos_policy": "dos_protection",
    "bot_mitigation_policy": "bot_mitigation",
    "bot_known_bots": "bot_mitigation",
    "bot_deception": "bot_mitigation",
    "bot_biometric_based_detection": "bot_mitigation",
    "bot_threshold_based_detection": "bot_mitigation",
    "bot_exception_policy": "bot_mitigation",
    "syntax_based_detection": "syntax_detection",
    "http_header_security": "http_header_security",
    "http_header_security_exception": "http_header_security",
    "cors_protection_policy": "cors",
    "cors_protection_rule": "cors",
    "cookie_security": "cookie_security",
    "websocket_security_policy": "websocket",
    "mitb_policy": "mitb",
    "csrf_protection": "csrf",
    "padding_oracle": "padding_oracle",
    "url_encryption_policy": "url_encryption",
    "url_encryption_rule": "url_encryption",
    "link_cloaking_policy": "link_cloaking",
    "link_cloaking_rule": "link_cloaking",
    "hidden_fields_rule": "hidden_fields",
    "parameter_validation_rule": "parameter_validation",
    "file_upload_policy": "file_security",
    "file_upload_rule": "file_security",
    "fiel_exception_policy": "file_security",
    "webshell_detection_policy": "webshell",
    "xml_protection_policy": "xml_validation",
    "xml_protection_rule": "xml_validation",
    "json_protection_policy": "json_validation",
    "json_protection_rule": "json_validation",
    "openapi_validation_policy": "openapi",
    "api_policy": "api_gateway",
    "api_rule": "api_gateway",
    "mobile_api_protection_policy": "mobile_api",
    "grpc_policy": "grpc",
    "url_rewrite_policy": "url_rewriting",
    "url_rewrite_rule": "url_rewriting",
    "http_authen_policy": "http_authentication",
    "compression_policy": "compression",
    "user_tracking_policy": "user_tracking",
    "threat_score_profile": "threat_scoring",
    "wpp": "wpp",
}

# Field keys that accept a REGULAR EXPRESSION on FortiWeb (per the admin guide:
# usually gated by a companion "type = regular" / operator = REGEXP_MATCH field).
# The regex-lab "🧮" affordance is offered on these; harmless elsewhere.
REGEX_KEYS = frozenset({
    "request-file", "request-url-pattern", "url-pattern", "match-expression",
    "reg-exp", "regex", "url", "request-url", "value", "match-condition-value",
    "pattern", "host", "path", "expression", "url-expr", "plain-url", "prefix",
    "signature-pattern", "match-content", "replace-url", "header-value",
})


# --------------------------------------------------------------------------- #
#  Registration into the engine                                                 #
# --------------------------------------------------------------------------- #
_registered = False


def register(kind_specs: dict, kind_by_coll_map: dict) -> None:
    """Merge the WAF catalog into ``fortiweb_field_schema.KIND_SPECS`` and
    ``objform._KIND_BY_COLL``. Idempotent; called at import by ``objform``."""
    global _registered
    if _registered:
        return
    cat = catalog()
    for key, k in cat.get("kinds", {}).items():
        entry = {
            "enums": {fk: list(v) for fk, v in (k.get("enums") or {}).items()},
            "refs": dict(k.get("refs") or {}),
            "toggles": set(k.get("toggles") or ()),
            "numbers": set(k.get("numbers") or ()),
            "labels": dict(k.get("labels") or {}),
            "groups": dict(k.get("groups") or {}),
            "show_when": {fk: (v[0], list(v[1]))
                          for fk, v in (k.get("show_when") or {}).items()},
            "order": list(k.get("field_order") or ()),
            "group_order": list(k.get("group_order") or ()),
            "kind_label": k.get("label") or key,
            "help_kind": key,
        }
        kind_specs.setdefault(key, entry)
    for coll, key in cat.get("kind_by_coll", {}).items():
        kind_by_coll_map.setdefault(coll, key)
    _registered = True


__all__ = [
    "catalog", "help_data", "kinds", "kind_by_coll", "value_labels",
    "subtable_titles", "wpp_sections", "action_explanations", "section_help",
    "regex_guide", "register", "REGEX_KEYS",
]
