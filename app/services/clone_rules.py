"""Clone / Migrate policy for Server-Policy copies — admin-configurable.

One AppSetting key (``clone.rules``) holds the fleet-wide policy the clone and
migrate dialogs start from:

* **ip_rules** — ordered dummy-IP transformation rules applied to a policy's
  VIP address when a copy must NOT take real traffic (every BULK clone/migrate,
  and the suggestion prefilled in the single-policy dialog). A rule replaces the
  LEADING octets of the source IP and keeps the rest, e.g. ``10 -> 240`` turns
  ``192.0.2.1`` into ``240.1.10.1``; ``162 -> 241`` turns ``162.5.0.9`` into
  ``241.5.0.9``. Match/replace must have the same octet count so the remainder
  always survives verbatim.
* **fallback_ip** — the dummy used when NO rule matches (default TEST-NET-3
  ``203.0.113.9``, the same placeholder the desktop clone uses).
* **copy_wpp_default** — whether a clone/migrate carries the Web Protection
  Profile subtree by default. The dialog shows this admin value read-only; the
  operator can override it only after ticking "Override admin defaults".

Editable in Settings → Clone / Migrate (USER_MANAGE). Pure helpers are
side-effect free so ``tests/test_clone_rules.py`` drives them without Flask.
"""
from __future__ import annotations

import ipaddress
from typing import Any

SETTING_KEY = "clone.rules"

DEFAULT_RULES = [
    {"match": "10", "replace": "240"},
    {"match": "162", "replace": "241"},
]
DEFAULT_FALLBACK_IP = "203.0.113.9"


# --------------------------------------------------------------------------- #
#  Config (AppSetting-backed)                                                   #
# --------------------------------------------------------------------------- #
def _defaults() -> dict[str, Any]:
    return {
        "ip_rules": [dict(r) for r in DEFAULT_RULES],
        "fallback_ip": DEFAULT_FALLBACK_IP,
        "copy_wpp_default": True,
    }


def config() -> dict[str, Any]:
    """The stored clone/migrate policy, normalised over the defaults."""
    from . import settings_store as store
    raw = store.get_json(SETTING_KEY, None)
    cfg = _defaults()
    if isinstance(raw, dict):
        rules = raw.get("ip_rules")
        if isinstance(rules, list):
            cfg["ip_rules"] = [
                {"match": str(r.get("match", "")).strip("."),
                 "replace": str(r.get("replace", "")).strip(".")}
                for r in rules
                if isinstance(r, dict) and str(r.get("match", "")).strip(".")
                and str(r.get("replace", "")).strip(".")
            ]
        if raw.get("fallback_ip"):
            cfg["fallback_ip"] = str(raw["fallback_ip"]).strip()
        if "copy_wpp_default" in raw:
            cfg["copy_wpp_default"] = bool(raw["copy_wpp_default"])
    return cfg


def validate_rule(match: str, replace: str) -> str:
    """'' when valid, else the human error. Match/replace are dotted octet
    prefixes of the SAME length (1–3 octets), each octet 0-255."""
    m, r = match.strip("."), replace.strip(".")
    mo, ro = m.split("."), r.split(".")
    if len(mo) != len(ro):
        return "match %r and replace %r must have the same octet count" % (m, r)
    if not 1 <= len(mo) <= 3:
        return "a rule matches 1 to 3 leading octets, got %r" % m
    for part in mo + ro:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return "octet %r is not in 0-255" % part
    return ""


def save_config(ip_rules: list[dict], fallback_ip: str,
                copy_wpp_default: bool) -> dict[str, Any]:
    """Validate + persist. Raises ValueError with every problem joined."""
    from . import settings_store as store
    errors: list[str] = []
    clean_rules: list[dict] = []
    for row in ip_rules:
        m = str(row.get("match", "")).strip().strip(".")
        r = str(row.get("replace", "")).strip().strip(".")
        if not m and not r:
            continue  # blank row = removed
        err = validate_rule(m, r)
        if err:
            errors.append(err)
        else:
            clean_rules.append({"match": m, "replace": r})
    fb = (fallback_ip or "").strip() or DEFAULT_FALLBACK_IP
    try:
        ipaddress.IPv4Address(fb)
    except ValueError:
        errors.append("fallback IP %r is not a valid IPv4 address" % fb)
    if errors:
        raise ValueError("; ".join(errors))
    cfg = {"ip_rules": clean_rules, "fallback_ip": fb,
           "copy_wpp_default": bool(copy_wpp_default)}
    store.set_json(SETTING_KEY, cfg)
    return cfg


# --------------------------------------------------------------------------- #
#  Pure rule engine                                                             #
# --------------------------------------------------------------------------- #
def dummy_ip(source_ip: str, cfg: dict[str, Any] | None = None) -> str:
    """Transform ``source_ip`` per the first matching rule; fallback otherwise.

    Accepts a bare IP or ``IP/mask`` (mask is stripped — callers re-attach it).
    An unparsable source returns the fallback."""
    cfg = cfg or config()
    ip = str(source_ip or "").split("/")[0].strip()
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return cfg["fallback_ip"]
    octets = ip.split(".")
    for rule in cfg["ip_rules"]:
        mo = rule["match"].split(".")
        if octets[: len(mo)] == mo:
            return ".".join(rule["replace"].split(".") + octets[len(mo):])
    return cfg["fallback_ip"]


def rules_summary(cfg: dict[str, Any] | None = None) -> str:
    """One-line human description for the dialog ('10.x → 240.x · 162.x → 241.x
    · else 203.0.113.9')."""
    cfg = cfg or config()
    parts = ["%s.x → %s.x" % (r["match"], r["replace"]) for r in cfg["ip_rules"]]
    parts.append("else %s" % cfg["fallback_ip"])
    return " · ".join(parts)
