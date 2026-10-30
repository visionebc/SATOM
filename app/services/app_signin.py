"""An app's own sign-in (``/a/<slug>/login``, views.apps_portal).

POLICY (``studio_apps.login_json``)
-----------------------------------
``{"enabled": bool, "rules": [rule, ...], "profile_id": int, "require_approval": bool}``

A rule says who may sign in and how it is proven, tried IN ORDER; the first
that accepts wins and nothing implicit follows (never the global chain)::

    {"connection_id": <directory connection id> | "local",
     "ldap_filter": "(department=NOC)",     # AD / LDAP: ANDed with the user lookup
     "group_dns": ["CN=noc,OU=Groups,..."],  # AD / LDAP: member of any (AD: nested)
     "radius_groups": ["satom-app-users"],   # RADIUS: Fortinet-Group-Name in the Accept
     "require_2fa": bool}                    # SATOM TOTP before the session starts

``local`` proves a local account's password -- for the Apps-only accounts an
administrator creates by hand; what such an account may open is still the app's
access list.

ACCOUNTS
--------
A person proven by a connection becomes ``<name>@<connection slug>``
(``auth_source="app"``, ``login_connection_id``), with the policy's Apps-only
profile. The qualified name is the whole defence against takeover: a directory
``jdoe`` can never be served the console's ``jdoe``, two directories never
share a row, and such a row is only ever proven by its own connection.

WHAT A SIGN-IN GRANTS
---------------------
Signing in through app A proves A and nothing else: A's id goes into the
session (``SESSION_KEY``) and a ``studio_app_grants`` row records it. An app
account may use A while BOTH hold -- the row lets an administrator revoke at
once, the session proof makes leaving the directory group effective at the
next sign-in. Another app is another sign-in, with that app's rules.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime

from flask import session

from ..extensions import db
from ..models_studio import StudioApp, StudioAppGrant
from . import directory_auth
from . import directory_connections as DC

SESSION_KEY = "app_proofs"
MAX_RULES = 10
_FILTER_RE = re.compile(r"^\(.*\)$", re.S)


class PolicyError(ValueError):
    """A sign-in policy that cannot be saved."""


# --------------------------------------------------------------------------- #
#  policy                                                                      #
# --------------------------------------------------------------------------- #
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


def _clean_rule(raw: dict) -> dict:
    if not isinstance(raw, dict):
        raise PolicyError("a rule must be an object")
    cid = raw.get("connection_id")
    out = {"require_2fa": bool(raw.get("require_2fa"))}
    if str(cid) == "local":
        out["connection_id"] = "local"
        return out
    conn = DC.get(cid)
    if conn is None:
        raise PolicyError("a rule names a directory connection that does not exist")
    out["connection_id"] = conn.id
    if conn.kind in ("ad", "ldap"):
        flt = str(raw.get("ldap_filter") or "").strip()
        if flt and (not _FILTER_RE.match(flt) or not _balanced(flt) or len(flt) > 1000):
            raise PolicyError("LDAP filter: one filter in parentheses, e.g. (department=NOC)")
        dns = [str(x).strip() for x in raw.get("group_dns") or [] if str(x).strip()]
        if any(len(d) > 500 or "=" not in d for d in dns):
            raise PolicyError("group DN: a distinguished name such as CN=noc,OU=Groups,DC=corp,DC=local")
        out["ldap_filter"] = flt
        out["group_dns"] = dns[:20]
    else:
        groups = [str(x).strip() for x in raw.get("radius_groups") or [] if str(x).strip()]
        if any(len(g) > 120 for g in groups):
            raise PolicyError("RADIUS group: at most 120 characters")
        out["radius_groups"] = groups[:20]
    return out


def clean_policy(raw: dict) -> dict:
    """The policy as stored, or PolicyError. An enabled policy must name an
    Apps-only profile for the accounts it makes and at least one rule."""
    from ..models import Profile
    if not isinstance(raw, dict):
        raise PolicyError("the sign-in policy must be an object")
    rules = raw.get("rules") or []
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise PolicyError("at most %d rules" % MAX_RULES)
    clean = [_clean_rule(r) for r in rules]
    pid = raw.get("profile_id")
    profile = db.session.get(Profile, int(pid)) if str(pid or "").isdigit() else None
    enabled = bool(raw.get("enabled"))
    needs_profile = any(r["connection_id"] != "local" for r in clean)
    if profile is not None and not profile.is_apps_only:
        raise PolicyError("the profile for new accounts must be an Apps only profile")
    if enabled and not clean:
        raise PolicyError("an enabled sign-in needs at least one rule")
    if enabled and needs_profile and profile is None:
        raise PolicyError("choose the Apps only profile new accounts get")
    return {"enabled": enabled, "rules": clean,
            "profile_id": profile.id if profile is not None else None,
            "require_approval": bool(raw.get("require_approval"))}


def policy_of(a: StudioApp) -> dict:
    """The stored policy, re-validated. Anything that no longer validates (a
    rule whose connection was removed by hand, a corrupt row) disables the
    sign-in instead of widening it."""
    raw = a.login
    if not raw:
        return {"enabled": False, "rules": [], "profile_id": None, "require_approval": False}
    try:
        return clean_policy(raw)
    except (PolicyError, TypeError, ValueError) as exc:
        return {"enabled": False, "rules": [], "profile_id": None,
                "require_approval": False, "problem": str(exc)}


def save_policy(a: StudioApp, raw: dict) -> dict:
    if a.kind not in ("flow", "script"):
        raise PolicyError("unknown app kind")
    pol = clean_policy(raw)
    a.login_json = json.dumps(pol, sort_keys=True)
    db.session.commit()
    return pol


def is_open(a: StudioApp) -> bool:
    """The app has a sign-in page to show at all."""
    from .studio_apps import _runnable_app
    return bool(_runnable_app(a) and policy_of(a)["enabled"])


# --------------------------------------------------------------------------- #
#  grants                                                                      #
# --------------------------------------------------------------------------- #
def has_grant(user, a: StudioApp) -> bool:
    uid = getattr(user, "id", None)
    if uid is None:
        return False
    return db.session.get(StudioAppGrant, (uid, a.id)) is not None


def _proofs() -> dict:
    try:
        p = session.get(SESSION_KEY)
    except RuntimeError:  # no request: nothing was proven here
        return {}
    return p if isinstance(p, dict) else {}


def proven(user, a: StudioApp) -> bool:
    """This session signed in through *a* AS *user*. Bound to the user id: a
    proof left in a browser session by someone else is no one's proof."""
    p = _proofs()
    uid = getattr(user, "id", None)
    return uid is not None and p.get("uid") == uid and a.id in (p.get("apps") or [])


def last_proven_app_id():
    apps = [x for x in (_proofs().get("apps") or []) if isinstance(x, int)]
    return apps[-1] if apps else None


def may_use_by_signin(user, a: StudioApp) -> bool:
    """An app account's way in: this session signed in through *a* and the
    grant still stands."""
    return bool(getattr(user, "is_app_account", False) and proven(user, a)
                and has_grant(user, a))


def grants_of_app(a: StudioApp) -> list[dict]:
    from ..models import User
    rows = (db.session.query(StudioAppGrant, User)
            .join(User, User.id == StudioAppGrant.user_id)
            .filter(StudioAppGrant.app_id == a.id).order_by(User.username).all())
    return [{"user_id": u.id, "username": u.username, "active": bool(u.is_active),
             "granted_at": g.granted_at} for g, u in rows]


def apps_granted_to(user) -> list[StudioApp]:
    uid = getattr(user, "id", None)
    if uid is None:
        return []
    return (StudioApp.query.join(StudioAppGrant, StudioAppGrant.app_id == StudioApp.id)
            .filter(StudioAppGrant.user_id == uid).order_by(StudioApp.name).all())


def revoke(a: StudioApp, user_id: int) -> bool:
    row = db.session.get(StudioAppGrant, (int(user_id), a.id))
    if row is None:
        return False
    db.session.delete(row)
    db.session.commit()
    return True


def _grant(user, a: StudioApp, connection_id) -> None:
    row = db.session.get(StudioAppGrant, (user.id, a.id))
    if row is None:
        db.session.add(StudioAppGrant(user_id=user.id, app_id=a.id,
                                      connection_id=connection_id))
    else:
        row.granted_at = datetime.utcnow()
        row.connection_id = connection_id


def remember_proof(user, a: StudioApp) -> None:
    p = _proofs()
    apps = [x for x in (p.get("apps") or []) if isinstance(x, int)] \
        if p.get("uid") == user.id else []
    if a.id not in apps:
        apps.append(a.id)
    session[SESSION_KEY] = {"uid": user.id, "apps": apps[-50:]}


def forget_proofs() -> None:
    session.pop(SESSION_KEY, None)


# --------------------------------------------------------------------------- #
#  sign-in                                                                     #
# --------------------------------------------------------------------------- #
def qualified(username: str, conn) -> str:
    return "%s@%s" % (username.strip().lower(), conn.slug)


def _extra_filter(rule: dict, kind: str) -> str:
    parts = []
    if rule.get("ldap_filter"):
        parts.append(rule["ldap_filter"])
    dns = rule.get("group_dns") or []
    if dns:
        esc = directory_auth._ldap_escape_dn
        if kind == "ad":
            # LDAP_MATCHING_RULE_IN_CHAIN: membership through nested groups too.
            ors = "".join("(memberOf:1.2.840.113556.1.4.1941:=%s)" % esc(d) for d in dns)
        else:
            ors = "".join("(memberOf=%s)" % esc(d) for d in dns)
        parts.append("(|%s)" % ors if len(dns) > 1 else ors)
    return "".join(parts)


def _prove(rule: dict, conn, username: str, password: str) -> tuple[bool, str]:
    try:
        cfg = DC.cfg_of(conn)
    except Exception as exc:  # noqa: BLE001 -- the vault owns the secret and is away
        return False, "connection %s: %s" % (conn.slug, exc)
    if conn.kind == "radius":
        ok, detail, groups = directory_auth.radius_authenticate_groups(cfg, username, password)
        if not ok:
            return False, detail
        wanted = {g.lower() for g in rule.get("radius_groups") or []}
        if wanted and not wanted & {g.lower() for g in groups}:
            return False, ("Accepted by RADIUS, but the reply names no required group "
                           "(got: %s)." % (", ".join(groups) or "none"))
        return True, detail
    cfg["extra_filter"] = _extra_filter(rule, conn.kind)
    return directory_auth.ldap_authenticate(cfg, username, password)


def candidate_accounts(a: StudioApp, username: str) -> list:
    """The existing rows *username* could sign in as through *a*'s rules --
    checked for a lockout BEFORE any directory sees the password."""
    from ..models import User
    username = (username or "").strip()
    if not username:
        return []
    names = []
    for rule in policy_of(a)["rules"]:
        if rule["connection_id"] == "local":
            names.append(username)
        else:
            conn = DC.get(rule["connection_id"])
            if conn is not None:
                names.append(qualified(username, conn))
    if not names:
        return []
    return User.query.filter(User.username.in_(names)).all()


@dataclass
class Result:
    ok: bool
    user: object = None
    rule: dict | None = None
    connection: object = None
    reason: str = ""          # audit only, never shown to the person
    message: str = ""         # what the page may say ("" = the generic failure)
    tried: list = field(default_factory=list)
    accounts: list = field(default_factory=list)  # existing rows a wrong password counts against


def sign_in(a: StudioApp, username: str, password: str) -> Result:
    """Prove *username* / *password* against *a*'s rules. Writes only the
    account a first sign-in creates; the caller decides about the session."""
    from ..models import User
    pol = policy_of(a)
    username = (username or "").strip()
    if not pol["enabled"] or not username or not password or len(username) > 128:
        return Result(False, reason="sign-in not enabled or empty credentials")
    res = Result(False)
    for rule in pol["rules"]:
        cid = rule["connection_id"]
        if cid == "local":
            user = User.query.filter_by(username=username).first()
            if user is None or not user.is_local:
                res.tried.append("local: no local account")
                continue
            res.accounts.append(user)
            if user.check_password(password):
                return Result(True, user=user, rule=rule, accounts=res.accounts,
                              tried=res.tried + ["local: ok"])
            res.tried.append("local: wrong password")
            continue
        conn = DC.get(cid)
        if conn is None or not conn.enabled:
            res.tried.append("connection %s: disabled or removed" % cid)
            continue
        qname = qualified(username, conn)
        if len(qname) > 64:
            res.tried.append("%s: user name too long" % conn.slug)
            continue
        existing = User.query.filter_by(username=qname).first()
        if existing is not None and (not existing.is_app_account
                                     or existing.login_connection_id != conn.id):
            # A row with this name that this connection did not make: never
            # served to whoever the directory accepts.
            res.tried.append("%s: name held by another account (refused)" % conn.slug)
            res.reason = "collision_refused"
            continue
        if existing is not None:
            res.accounts.append(existing)
        ok, detail = _prove(rule, conn, username, password)
        res.tried.append("%s: %s" % (conn.slug, detail))
        if not ok:
            continue
        user = existing
        if user is None:
            user = _provision(qname, conn, pol)
            if user is None:
                return Result(False, rule=rule, connection=conn, tried=res.tried,
                              reason="new account on a read-only node",
                              message="Sign-in for new users needs the primary node.")
        return Result(True, user=user, rule=rule, connection=conn, tried=res.tried,
                      accounts=res.accounts)
    res.reason = res.reason or "no rule accepted"
    return res


def _provision(qname: str, conn, pol: dict):
    """The account a first sign-in creates, or None on a read-only node."""
    import secrets as _secrets
    from ..models import Profile, User
    profile = db.session.get(Profile, pol["profile_id"]) if pol.get("profile_id") else None
    if profile is None or not profile.is_apps_only:
        return None
    user = User(username=qname, auth_source="app", login_connection_id=conn.id,
                profile_id=profile.id, role="readonly",
                is_active=not pol.get("require_approval"))
    # Never a usable local password: the directory is the only proof.
    user.set_password(_secrets.token_urlsafe(32))
    db.session.add(user)
    try:
        db.session.commit()
    except Exception:  # noqa: BLE001 -- the read-only standby refuses the INSERT
        db.session.rollback()
        return None
    from .audit import log_action
    log_action("login.app.provision", target=qname,
               extra={"connection": conn.slug, "profile": profile.name,
                      "pending_approval": not user.is_active})
    return user


def complete(a: StudioApp, user, connection_id=None) -> None:
    """After the session is issued: the grant (app accounts) and the proof."""
    if getattr(user, "is_app_account", False):
        _grant(user, a, connection_id)
        try:
            db.session.commit()
        except Exception:  # noqa: BLE001 -- read-only standby: the existing grant stands
            db.session.rollback()
    remember_proof(user, a)
