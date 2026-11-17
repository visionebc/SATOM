"""An app's own sign-in: the rules that need no server (services.app_signin).

What a rule may say and what an app package's ``"signin"`` may carry
(contract section 20), as pure functions: no Flask, no database. The SATOM
Builder runs them from the rules pack -- ``package_check`` calls
:func:`clean_package` -- exactly as this server does on import, so this
module must stay importable without the server (tests/test_rules_pack.py).
"""
from __future__ import annotations

import re

MAX_RULES = 10
MAX_GROUPS = 20
#: A directory connection's id; accounts it signs in are named user@<id>.
SLUG_RE = re.compile(r"^[a-z][a-z0-9-]{1,38}[a-z0-9]$")
KIND_LABELS = {"ad": "Active Directory", "ldap": "LDAP", "radius": "RADIUS / FortiAuthenticator"}
#: The connection kinds a packaged rule may name ("local": SATOM's own accounts).
PACKAGE_KINDS = ("ad", "ldap", "radius", "local")
#: The keys a packaged rule may hold per kind (besides connection, kind, require_2fa).
KIND_KEYS = {"ad": ("ldap_filter", "group_dns"), "ldap": ("ldap_filter", "group_dns"),
             "radius": ("radius_groups",), "local": ()}
_FILTER_RE = re.compile(r"^\(.*\)$", re.S)


class PolicyError(ValueError):
    """A sign-in policy that cannot be saved."""


def _balanced(flt: str) -> bool:
    depth = 0
    for ch in flt:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def _strings(raw, key: str) -> list[str]:
    v = raw.get(key)
    if v in (None, ""):
        return []
    if not isinstance(v, list):
        raise PolicyError("%s is a list of strings" % key)
    return [str(x).strip() for x in v if str(x).strip()]


def kind_parts(kind: str, raw: dict) -> dict:
    """The keys a rule of connection *kind* keeps, validated (pure)."""
    if kind in ("ad", "ldap"):
        flt = str(raw.get("ldap_filter") or "").strip()
        if flt and (not _FILTER_RE.match(flt) or not _balanced(flt) or len(flt) > 1000):
            raise PolicyError("LDAP filter: one filter in parentheses, e.g. (department=NOC)")
        dns = _strings(raw, "group_dns")
        if any(len(d) > 500 or "=" not in d for d in dns):
            raise PolicyError("group DN: a distinguished name such as CN=noc,OU=Groups,DC=corp,DC=local")
        return {"ldap_filter": flt, "group_dns": dns[:MAX_GROUPS]}
    groups = _strings(raw, "radius_groups")
    if any(len(g) > 120 for g in groups):
        raise PolicyError("RADIUS group: at most 120 characters")
    return {"radius_groups": groups[:MAX_GROUPS]}


def clean_package(raw) -> tuple[dict | None, list[tuple[str, str]]]:
    """``(signin, problems)`` of an app package's ``signin`` -- pure, no server
    state (the Builder runs it from the rules pack). ``signin`` is None when
    the package has none; a problem is ``(where, message)``."""
    if raw in (None, "", {}):
        return None, []
    if not isinstance(raw, dict):
        return None, [("signin", "signin is an object: {rules, profile, require_approval}")]
    problems = []
    unknown = sorted(set(raw) - {"rules", "profile", "require_approval"})
    if unknown:
        problems.append(("signin", "unknown key(s): %s" % ", ".join(unknown)))
    rules = raw.get("rules")
    if rules in (None, ""):
        rules = []
    if not isinstance(rules, list):
        return None, problems + [("signin.rules", "rules is a list")]
    if len(rules) > MAX_RULES:
        problems.append(("signin.rules", "at most %d rules" % MAX_RULES))
    out = []
    for i, r in enumerate(rules[:MAX_RULES]):
        where = "signin.rules[%d]" % i
        if not isinstance(r, dict):
            problems.append((where, "each rule is an object"))
            continue
        kind = str(r.get("kind") or "")
        conn = str(r.get("connection") or "")
        if kind not in PACKAGE_KINDS:
            problems.append((where, "kind %r: one of %s" % (kind, ", ".join(PACKAGE_KINDS))))
            continue
        if kind == "local" and conn not in ("", "local"):
            problems.append((where, "a local rule names no connection (connection \"local\")"))
            continue
        if kind != "local" and not SLUG_RE.match(conn):
            problems.append((where, "connection %r: the id of a directory connection "
                                    "(lowercase letters, digits and -), e.g. corp-ad" % conn))
            continue
        extra = sorted(set(r) - {"connection", "kind", "require_2fa"} - set(KIND_KEYS[kind]))
        if extra:
            problems.append((where, "%s is not part of a %s rule" % (", ".join(extra), kind)))
            continue
        try:
            parts = kind_parts(kind, r) if kind != "local" else {}
        except PolicyError as exc:
            problems.append((where, str(exc)))
            continue
        out.append(dict({"connection": "local" if kind == "local" else conn, "kind": kind,
                         "require_2fa": bool(r.get("require_2fa"))}, **parts))
    profile = raw.get("profile")
    if profile not in (None, "") and (not isinstance(profile, str) or len(profile) > 64):
        problems.append(("signin.profile", "profile is the name of an Apps only profile"))
        profile = ""
    return ({"rules": out, "profile": str(profile or ""),
             "require_approval": bool(raw.get("require_approval"))}, problems)
