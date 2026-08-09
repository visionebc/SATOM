"""Authentication source configuration + external-auth dispatcher.

``local`` is NOT one of the configurable sources: the local database is always
live and is the anti-lockout floor. On top of it the admin enables ANY NUMBER of
external directories, in an explicit order (Settings -> Authentication):

* ``ad``     — Active Directory (LDAP under the hood, UPN simple bind).
* ``ldap``   — generic LDAP (service-account search + user re-bind).
* ``radius`` — FortiAuthenticator / any RADIUS server (FortiToken-friendly).

Sign-in walks the enabled sources IN ORDER and the FIRST one that accepts the
credential wins; the account is stamped with that source. **Order is not
cosmetic.** It decides latency (a dead directory burns its whole timeout before
the next one is tried) and which directories see a wrong password — every source
ahead of the winner does, so every source ahead of it counts that failure
against its own lockout policy.

Each source carries a LIST of sync groups, and each group its own profile, so
"import group X as readonly and group Y as operator" is one configuration
instead of two passes. The per-group profile is applied by the IMPORTER only: a
RADIUS Access-Accept carries no group, and resolving one at sign-in would put a
REST round-trip to the FortiAuthenticator on the critical path of every first
login. Just-in-time users therefore get the GLOBAL default profile — which is
why that default is ``readonly`` (least privilege) and why the approval gate
exists.

Persistence + secret handling mirror ``email_service``: everything in the
``app_settings`` table, the bind password / RADIUS secret Fernet-encrypted, a
blank secret field on save KEEPS the stored one (blank-keeps-existing).
"""
from __future__ import annotations

import json
import logging
import secrets as _secrets

from ..models import AppSetting
from . import directory_auth, encryption

log = logging.getLogger(__name__)

# ---- keys -----------------------------------------------------------------
K_BACKENDS = "auth.backends"                  # AUTHORITATIVE: JSON ordered list
K_BACKEND = "auth.backend"                    # legacy mirror: the first source
K_DEFAULT_PROFILE = "auth.default_profile"    # profile name for new external users

# LDAP / AD
K_L_HOST = "auth.ldap.host"
K_L_PORT = "auth.ldap.port"
K_L_SSL = "auth.ldap.use_ssl"                 # "1"/"0" (LDAPS)
K_L_STARTTLS = "auth.ldap.start_tls"          # "1"/"0"
K_L_VERIFY = "auth.ldap.tls_verify"           # "1"/"0"
K_L_BASE = "auth.ldap.base_dn"
K_L_USERATTR = "auth.ldap.user_attr"
K_L_BINDDN = "auth.ldap.bind_dn"
K_L_BINDPW = "auth.ldap.bind_password_enc"    # Fernet token
K_L_DOMAIN = "auth.ldap.ad_domain"
K_L_FILTER = "auth.ldap.user_filter"
K_L_SYNCGROUP = "auth.ldap.sync_group_dn"     # legacy single scope (mirror)
K_L_SYNCGROUPS = "auth.ldap.sync_groups"      # JSON [{group, profile}]
K_L_TIMEOUT = "auth.ldap.timeout"

# RADIUS
K_R_HOST = "auth.radius.host"
K_R_PORT = "auth.radius.port"
K_R_SECRET = "auth.radius.secret_enc"         # Fernet token
K_R_NASID = "auth.radius.nas_id"
K_R_TIMEOUT = "auth.radius.timeout"
# RADIUS cannot be enumerated (an Access-Request is a yes/no question about one
# credential). The roster for "import users" therefore comes from the FAC's REST
# API via an appliance ALREADY registered in the inventory - no second secret.
K_R_SYNC_APPLIANCE = "auth.radius.sync_appliance_id"
K_R_SYNC_GROUP = "auth.radius.sync_group"     # legacy single scope (mirror)
K_R_SYNC_GROUPS = "auth.radius.sync_groups"   # JSON [{group, profile}]

# Approval gate (applies to EVERY external source, not just RADIUS).
K_REQUIRE_APPROVAL = "auth.require_approval"   # "1"/"0"

EXTERNAL_BACKENDS = ("ad", "ldap", "radius")
BACKENDS = ("local",) + EXTERNAL_BACKENDS

# Least privilege: a directory user nobody has looked at yet gets the profile
# that cannot change anything. Elevation is an explicit admin action.
DEFAULT_PROFILE_FALLBACK = "readonly"

DEFAULTS = {
    K_BACKEND: "local",
    K_DEFAULT_PROFILE: DEFAULT_PROFILE_FALLBACK,
    K_L_PORT: "389",
    K_L_SSL: "0",
    K_L_STARTTLS: "0",
    K_L_VERIFY: "1",
    K_L_USERATTR: "",        # resolved per-kind below
    K_L_FILTER: "",
    K_L_TIMEOUT: "8",
    K_R_PORT: "1812",
    K_R_TIMEOUT: "8",
    K_REQUIRE_APPROVAL: "0",
}


# ---- low-level ------------------------------------------------------------
def _get(key: str) -> str:
    val = AppSetting.get(key)
    return DEFAULTS.get(key, "") if val is None else val


def _to_int(val, fallback: int) -> int:
    try:
        return int(str(val).strip())
    except (TypeError, ValueError):
        return fallback


def _dec(token: str) -> str:
    if not token:
        return ""
    try:
        return encryption.decrypt(token)
    except Exception:  # noqa: BLE001 — bad key/token behaves as unset
        return ""


#: An unreadable row. NOT the same as an absent one: absent falls back to the
#: legacy single-value key, unreadable must NOT — silently reviving a value the
#: admin replaced is how a directory nobody enabled starts authenticating again.
UNREADABLE = object()


def _json_list(key: str):
    """Stored JSON list, ``None`` when the row is absent, :data:`UNREADABLE`
    when it cannot be parsed as a list."""
    raw = AppSetting.get(key)
    if not raw:
        return None
    try:
        val = json.loads(raw)
    except (TypeError, ValueError):
        log.warning("auth: %s is not valid JSON — ignoring the row", key)
        return UNREADABLE
    if not isinstance(val, list):
        log.warning("auth: %s is not a JSON list — ignoring the row", key)
        return UNREADABLE
    return val


# ---- public state ---------------------------------------------------------
def backends() -> list[str]:
    """Enabled EXTERNAL sources, in sign-in order. ``[]`` = local only."""
    vals = _json_list(K_BACKENDS)
    if vals is UNREADABLE:
        # Fail CLOSED: local sign-in still works (nobody is locked out) and no
        # directory is consulted on the strength of a policy nobody can read.
        return []
    if vals is None:
        legacy = (_get(K_BACKEND) or "").strip()
        return [legacy] if legacy in EXTERNAL_BACKENDS else []
    out: list[str] = []
    for v in vals:
        v = str(v or "").strip()
        if v in EXTERNAL_BACKENDS and v not in out:
            out.append(v)
    return out


def backend() -> str:
    """Single-value view kept for callers/logs that predate multi-source: the
    FIRST enabled source, or ``local`` when none is."""
    order = backends()
    return order[0] if order else "local"


def is_enabled() -> bool:
    """True when at least one EXTERNAL source is active."""
    return bool(backends())


def default_profile_name() -> str:
    return (_get(K_DEFAULT_PROFILE) or "").strip() or DEFAULT_PROFILE_FALLBACK


def require_approval() -> bool:
    """True when a first-time directory user must be approved by an admin.

    The bind still happens at the directory - this gates ACCESS, not identity.
    A gated user is created DISABLED and reported at login as pending approval,
    never as a bad password (blaming the credential for an authorisation
    decision sends the user to reset a password that was correct)."""
    return _get(K_REQUIRE_APPROVAL) == "1"


def fac_sync_appliance_id() -> int:
    return _to_int(_get(K_R_SYNC_APPLIANCE), 0)


def _group_rows(key_list: str, key_legacy: str) -> list[dict]:
    rows = _json_list(key_list)
    if rows is UNREADABLE:
        return []
    if rows is None:
        legacy = (AppSetting.get(key_legacy) or "").strip()
        return [{"group": legacy, "profile": ""}] if legacy else []
    out: list[dict] = []
    seen: set[str] = set()
    for row in rows:
        if isinstance(row, dict):
            grp = str(row.get("group", "") or "").strip()
            prof = str(row.get("profile", "") or "").strip()
        else:
            grp, prof = str(row or "").strip(), ""
        if not grp or grp.lower() in seen:
            continue
        seen.add(grp.lower())
        out.append({"group": grp, "profile": prof})
    return out


def sync_groups(source: str) -> list[dict]:
    """``[{group, profile}]`` for *source*, in order. Empty = no group filter.

    ``profile`` blank means "use the global default"; it is NOT normalised to
    the default here so the UI can keep showing "inherit"."""
    if source == "radius":
        return _group_rows(K_R_SYNC_GROUPS, K_R_SYNC_GROUP)
    if source in ("ad", "ldap"):
        return _group_rows(K_L_SYNCGROUPS, K_L_SYNCGROUP)
    return []


def fac_sync_group() -> str:
    """First RADIUS/FAC import group (back-compat single-value view)."""
    rows = sync_groups("radius")
    return rows[0]["group"] if rows else ""


# ---- config (read) --------------------------------------------------------
def config(*, reveal_secrets: bool = False) -> dict:
    """Full auth config for the Settings template. Secrets are exposed as
    ``has_*`` flags only, unless ``reveal_secrets`` (used by the dispatcher)."""
    order = backends()
    b = order[0] if order else "local"
    l_groups = sync_groups("ldap")
    r_groups = sync_groups("radius")
    cfg = {
        "backends": order,
        "backend": b,
        "default_profile": default_profile_name(),
        "require_approval": require_approval(),
        "ldap": {
            "kind": b if b in ("ad", "ldap") else "ldap",
            "host": _get(K_L_HOST),
            "port": _to_int(_get(K_L_PORT), 389),
            "use_ssl": _get(K_L_SSL) == "1",
            "start_tls": _get(K_L_STARTTLS) == "1",
            "tls_verify": _get(K_L_VERIFY) != "0",
            "base_dn": _get(K_L_BASE),
            "user_attr": _get(K_L_USERATTR),
            "bind_dn": _get(K_L_BINDDN),
            "ad_domain": _get(K_L_DOMAIN),
            "user_filter": _get(K_L_FILTER),
            "sync_groups": l_groups,
            "sync_group_dn": l_groups[0]["group"] if l_groups else "",
            "timeout": _to_int(_get(K_L_TIMEOUT), 8),
            "has_bind_password": bool(AppSetting.get(K_L_BINDPW)),
        },
        "radius": {
            "host": _get(K_R_HOST),
            "port": _to_int(_get(K_R_PORT), 1812),
            "nas_id": _get(K_R_NASID),
            "timeout": _to_int(_get(K_R_TIMEOUT), 8),
            "has_secret": bool(AppSetting.get(K_R_SECRET)),
            "sync_appliance_id": fac_sync_appliance_id(),
            "sync_groups": r_groups,
            "sync_group": r_groups[0]["group"] if r_groups else "",
        },
    }
    if reveal_secrets:
        cfg["ldap"]["bind_password"] = _dec(AppSetting.get(K_L_BINDPW))
        cfg["radius"]["secret"] = _dec(AppSetting.get(K_R_SECRET))
    return cfg


def _resolved_ldap_cfg(kind: str = "", reveal: bool = True) -> dict:
    """An ``ldap``-section dict with per-kind defaults filled in, ready for
    ``directory_auth``. *kind* names WHICH bind style is being attempted — with
    both ``ad`` and ``ldap`` enabled the same server is tried twice, once per
    style, so the caller must say which one it wants."""
    cfg = config(reveal_secrets=reveal)["ldap"]
    if kind in ("ad", "ldap"):
        cfg["kind"] = kind
    if not cfg.get("user_attr"):
        cfg["user_attr"] = "sAMAccountName" if cfg["kind"] == "ad" else "uid"
    return cfg


# ---- config (write) -------------------------------------------------------
def _submitted_backends(form) -> list[str]:
    """Ordered external sources from the form.

    New UI posts ``backends[]`` plus a numeric ``backend_order_<name>``. The
    legacy single ``backend`` field is still honoured so an older form (and the
    existing tests) keep working unchanged."""
    getlist = getattr(form, "getlist", None)
    raw = getlist("backends[]") if callable(getlist) else form.get("backends") or []
    if isinstance(raw, str):
        raw = [raw]
    chosen = []
    for val in raw:
        val = str(val or "").strip()
        if val in EXTERNAL_BACKENDS and val not in chosen:
            chosen.append(val)
    if not chosen:
        legacy = str(form.get("backend", "") or "").strip()
        return [legacy] if legacy in EXTERNAL_BACKENDS else []
    # Stable sort: an unset/garbage order field keeps the submitted position
    # instead of jumping to the front and silently re-ordering the chain.
    return sorted(chosen, key=lambda b: _to_int(form.get("backend_order_" + b), 99))


def _submitted_groups(form, prefix: str) -> list[dict] | None:
    """``[{group, profile}]`` from ``<prefix>_group[]`` / ``<prefix>_group_profile[]``.

    ``None`` unless the form declares ``groups_submitted=1`` — the caller then
    leaves the stored scope ALONE. Deleting every row is a real instruction ("no
    group filter") and posts an EMPTY list, which is why "no rows" cannot be the
    signal for "this form did not mention groups": an older form, or the test
    harness, would otherwise wipe the configured scope by omission."""
    getlist = getattr(form, "getlist", None)
    if not callable(getlist) or str(form.get("groups_submitted") or "") != "1":
        return None
    names = getlist(prefix + "_group[]")
    profs = getlist(prefix + "_group_profile[]")
    rows: list[dict] = []
    seen: set[str] = set()
    for i, grp in enumerate(names):
        grp = (grp or "").strip()
        if not grp or grp.lower() in seen:
            continue
        seen.add(grp.lower())
        rows.append({"group": grp,
                     "profile": (profs[i] if i < len(profs) else "").strip()})
    return rows


def save_config(form) -> None:
    """Persist from a Flask ``request.form`` (or mapping). Secrets: blank field
    keeps the stored value; disabling a source leaves its config intact (so
    toggling it back doesn't lose settings)."""
    def g(key, default=""):
        return (form.get(key, default) or "").strip()

    chosen = _submitted_backends(form)
    AppSetting.set(K_BACKENDS, json.dumps(chosen))
    # Mirror, kept in sync on every write so a DB dump never shows two rows that
    # disagree and a rollback to pre-multi-source code still finds a source.
    AppSetting.set(K_BACKEND, chosen[0] if chosen else "local")
    AppSetting.set(K_DEFAULT_PROFILE, g("default_profile") or DEFAULT_PROFILE_FALLBACK)
    # Saved for EVERY source: the gate must not silently switch off just
    # because the admin was editing the LDAP half of the form.
    AppSetting.set(K_REQUIRE_APPROVAL,
                   "1" if form.get("require_approval") in ("1", "on", "true") else "0")

    # LDAP / AD section (saved whenever either LDAP bind style is enabled).
    if "ad" in chosen or "ldap" in chosen:
        AppSetting.set(K_L_HOST, g("ldap_host"))
        AppSetting.set(K_L_PORT, str(_to_int(g("ldap_port"), 636 if form.get("ldap_use_ssl") in ("1", "on", "true") else 389)))
        AppSetting.set(K_L_SSL, "1" if form.get("ldap_use_ssl") in ("1", "on", "true") else "0")
        AppSetting.set(K_L_STARTTLS, "1" if form.get("ldap_start_tls") in ("1", "on", "true") else "0")
        AppSetting.set(K_L_VERIFY, "1" if form.get("ldap_tls_verify") in ("1", "on", "true") else "0")
        AppSetting.set(K_L_BASE, g("ldap_base_dn"))
        AppSetting.set(K_L_USERATTR, g("ldap_user_attr"))
        AppSetting.set(K_L_BINDDN, g("ldap_bind_dn"))
        AppSetting.set(K_L_DOMAIN, g("ldap_ad_domain"))
        AppSetting.set(K_L_FILTER, g("ldap_user_filter"))
        AppSetting.set(K_L_TIMEOUT, str(max(2, min(60, _to_int(g("ldap_timeout"), 8)))))
        rows = _submitted_groups(form, "ldap")
        if rows is None and form.get("ldap_sync_group_dn") is not None:
            legacy = g("ldap_sync_group_dn")          # older single-field form, clearing included
            rows = [{"group": legacy, "profile": ""}] if legacy else []
        if rows is not None:          # neither field present => stored scope stands
            AppSetting.set(K_L_SYNCGROUPS, json.dumps(rows))
            AppSetting.set(K_L_SYNCGROUP, rows[0]["group"] if rows else "")
        new_pw = form.get("ldap_bind_password", "")
        if new_pw:
            AppSetting.set(K_L_BINDPW, encryption.encrypt(new_pw))

    # RADIUS section.
    if "radius" in chosen:
        AppSetting.set(K_R_HOST, g("radius_host"))
        AppSetting.set(K_R_PORT, str(_to_int(g("radius_port"), 1812)))
        AppSetting.set(K_R_NASID, g("radius_nas_id") or "satom")
        AppSetting.set(K_R_TIMEOUT, str(max(2, min(60, _to_int(g("radius_timeout"), 8)))))
        AppSetting.set(K_R_SYNC_APPLIANCE, str(_to_int(g("radius_sync_appliance_id"), 0)))
        rows = _submitted_groups(form, "radius")
        if rows is None and form.get("radius_sync_group") is not None:
            legacy = g("radius_sync_group")          # older single-field form, clearing included
            rows = [{"group": legacy, "profile": ""}] if legacy else []
        if rows is not None:          # neither field present => stored scope stands
            AppSetting.set(K_R_SYNC_GROUPS, json.dumps(rows))
            AppSetting.set(K_R_SYNC_GROUP, rows[0]["group"] if rows else "")
        new_secret = form.get("radius_secret", "")
        if new_secret:
            AppSetting.set(K_R_SECRET, encryption.encrypt(new_secret))


# ---- test connection ------------------------------------------------------
def test_connection(form) -> dict:
    """Test the SUBMITTED config (so the admin can verify BEFORE saving). Falls
    back to the stored secret when the secret field is left blank.

    With several sources enabled the admin must say WHICH one to test
    (``test_backend``); testing "all of them" would report a green tick for a
    chain in which the source they were editing is broken."""
    b = (form.get("test_backend") or form.get("backend") or "").strip()
    if b not in BACKENDS:
        submitted = _submitted_backends(form)
        b = submitted[0] if submitted else "local"
    test_user = (form.get("test_username") or "").strip()
    test_pw = form.get("test_password") or ""

    if b == "local":
        return {"ok": True, "detail": "Local authentication is always available."}

    if b in ("ad", "ldap"):
        cfg = {
            "kind": b,
            "host": (form.get("ldap_host") or "").strip(),
            "port": _to_int(form.get("ldap_port"), 636 if form.get("ldap_use_ssl") in ("1", "on", "true") else 389),
            "use_ssl": form.get("ldap_use_ssl") in ("1", "on", "true"),
            "start_tls": form.get("ldap_start_tls") in ("1", "on", "true"),
            "tls_verify": form.get("ldap_tls_verify") in ("1", "on", "true"),
            "base_dn": (form.get("ldap_base_dn") or "").strip(),
            "user_attr": (form.get("ldap_user_attr") or "").strip() or ("sAMAccountName" if b == "ad" else "uid"),
            "bind_dn": (form.get("ldap_bind_dn") or "").strip(),
            "ad_domain": (form.get("ldap_ad_domain") or "").strip(),
            "user_filter": (form.get("ldap_user_filter") or "").strip(),
            "timeout": _to_int(form.get("ldap_timeout"), 8),
            "bind_password": form.get("ldap_bind_password") or _dec(AppSetting.get(K_L_BINDPW)),
        }
        ok, detail = directory_auth.ldap_test(cfg, test_user, test_pw)
        return {"ok": ok, "detail": detail}

    if b == "radius":
        cfg = {
            "host": (form.get("radius_host") or "").strip(),
            "port": _to_int(form.get("radius_port"), 1812),
            "nas_id": (form.get("radius_nas_id") or "").strip() or "satom",
            "timeout": _to_int(form.get("radius_timeout"), 8),
            "secret": form.get("radius_secret") or _dec(AppSetting.get(K_R_SECRET)),
        }
        ok, detail = directory_auth.radius_test(cfg, test_user, test_pw)
        return {"ok": ok, "detail": detail}

    return {"ok": False, "detail": f"Unknown backend {b!r}."}


# ---- dispatch (login time) ------------------------------------------------
def _bind_one(source: str, username: str, password: str):
    if source in ("ad", "ldap"):
        return directory_auth.ldap_authenticate(_resolved_ldap_cfg(source), username, password)
    if source == "radius":
        return directory_auth.radius_authenticate(
            config(reveal_secrets=True)["radius"], username, password)
    return False, f"Unknown backend {source!r}."


def authenticate_external(username: str, password: str) -> dict:
    """Bind *username*/*password* against each enabled source, IN ORDER.

    Returns ``{ok, source, detail, tried}``. ``source`` is the source that
    accepted (so the JIT provisioner can stamp ``auth_source``); on failure it
    is the first configured one, and ``detail`` carries EVERY source's reason —
    a chain that fails for three different reasons must not be reported as one."""
    order = backends()
    if not order:
        return {"ok": False, "source": "local", "tried": [],
                "detail": "No external backend configured."}

    details = []
    for idx, source in enumerate(order):
        ok, detail = _bind_one(source, username, password)
        if ok:
            return {"ok": True, "source": source, "detail": detail,
                    "tried": order[:idx + 1]}
        details.append(f"{source}: {detail}")
    return {"ok": False, "source": order[0], "tried": order,
            "detail": " | ".join(details)}


# ---- JIT provisioning -----------------------------------------------------
def _profile_for(name: str):
    """Named profile, else the configured default, else the readonly floor.

    Never returns a profile more privileged than the caller asked for: an
    unknown name falls back DOWN the chain, never up."""
    from ..models import Profile
    for candidate in (name, default_profile_name(), DEFAULT_PROFILE_FALLBACK):
        candidate = (candidate or "").strip()
        if not candidate:
            continue
        prof = Profile.query.filter_by(name=candidate).first()
        if prof is not None:
            return prof
    return None


def provision_external_user(username: str, source: str):
    """Create (or refresh) the local row for an authenticated directory user.

    NEW user → ``auth_source=source`` + the GLOBAL default profile (readonly).
    Per-group profiles are an IMPORT-time concept: at sign-in the accepted bind
    tells us nothing about group membership. EXISTING user → never downgraded
    (keeps the admin-assigned profile); a still-``local`` row is NOT flipped to
    external (protects the seed admin)."""
    from ..extensions import db
    from ..models import User

    user = User.query.filter_by(username=username).first()
    if user is not None:
        # Existing account: never auto-externalize a local account; just ensure
        # the external row is active and its source recorded.
        if (user.auth_source or "local") == "local":
            return user  # local account — leave it entirely alone
        if not user.is_active:
            return user
        user.auth_source = source
        db.session.commit()
        return user

    prof = _profile_for(default_profile_name())
    # Approval gate: a brand-new directory user lands DISABLED so an admin can
    # assign the right profile BEFORE the account can do anything. Existing rows
    # are never touched by this (see the early return above).
    user = User(username=username, auth_source=source,
                is_active=not require_approval())
    # External users authenticate at the directory — give them an unusable
    # local password so check_password() can never succeed locally.
    user.set_password(_secrets.token_urlsafe(48))
    if prof is not None:
        user.profile = prof
        user.role = prof.role_label
    db.session.add(user)
    db.session.commit()
    return user


# ---- FortiAuthenticator roster feed ---------------------------------------
def fac_client():
    """``(client, detail)`` for the appliance configured as the roster source.

    Resolution is explicit-first: the configured id wins; with none set, fall
    back to the single registered FortiAuthenticator. Two of them and no choice
    made is an ERROR, not a coin flip - importing the wrong appliance's users
    would look like it worked."""
    from ..models import Appliance
    from ..clients.fortiauthenticator import FortiAuthenticatorClient

    want = fac_sync_appliance_id()
    if want:
        appliance = Appliance.query.filter_by(id=want).first()
        if appliance is None:
            return None, f"Appliance id {want} is not in the inventory any more."
        if (appliance.kind or "") != "fortiauthenticator":
            return None, (f"Appliance {appliance.name!r} is a "
                          f"{appliance.kind!r}, not a FortiAuthenticator.")
        return FortiAuthenticatorClient(appliance), ""

    found = Appliance.query.filter_by(kind="fortiauthenticator").all()
    if not found:
        return None, ("No FortiAuthenticator registered. Add the FAC under "
                      "Appliances (its API key is reused for the roster).")
    if len(found) > 1:
        names = ", ".join(a.name for a in found)
        return None, (f"{len(found)} FortiAuthenticators registered ({names}) - "
                      f"pick one in Settings -> Authentication.")
    return FortiAuthenticatorClient(found[0]), ""


def _scopes(source: str) -> list[dict]:
    """Group scopes to enumerate for *source*; no configured group means one
    unfiltered pass over everything the directory exposes."""
    return sync_groups(source) or [{"group": "", "profile": ""}]


def _list_fac_users(limit: int = 500) -> dict:
    """Roster from the FAC REST API. Logins keep going over RADIUS."""
    from . import fac_directory

    client, detail = fac_client()
    if client is None:
        return {"ok": False, "users": [], "detail": detail}

    users: list[dict] = []
    seen: set[str] = set()
    scopes = []
    for scope in _scopes("radius"):
        ok, res = fac_directory.list_group_members(client, scope["group"], limit=limit)
        if not ok:
            # One bad group name fails the WHOLE import. A partial roster that
            # reports success is how a typo becomes permanent.
            return {"ok": False, "users": [],
                    "detail": f"group {scope['group']!r}: {res}" if scope["group"] else str(res)}
        for entry in res:
            uname = (entry.get("username") or "").strip()
            if not uname or uname.lower() in seen:
                continue
            seen.add(uname.lower())
            users.append({**entry, "source": "radius",
                          "source_group": scope["group"],
                          "profile": scope["profile"]})
        scopes.append(f"{scope['group'] or 'all groups'} ({len(res)})")
    return {"ok": True, "users": users[:max(1, int(limit))],
            "detail": f"{len(users)} user(s) found in {', '.join(scopes)}."}


def _list_ldap_users(source: str, limit: int = 500) -> dict:
    cfg = _resolved_ldap_cfg(source)
    users: list[dict] = []
    seen: set[str] = set()
    for scope in _scopes(source):
        ok, res = directory_auth.ldap_list_users(cfg, group_dn=scope["group"], limit=limit)
        if not ok:
            return {"ok": False, "users": [],
                    "detail": f"{source}: {res}"}
        for entry in res:
            uname = (entry.get("username") or "").strip()
            if not uname or uname.lower() in seen:
                continue
            seen.add(uname.lower())
            users.append({**entry, "source": source,
                          "source_group": scope["group"],
                          "profile": scope["profile"]})
    return {"ok": True, "users": users[:max(1, int(limit))],
            "detail": f"{len(users)} user(s) found."}


# ---- directory sync (admin action) ----------------------------------------
def list_directory_users(limit: int = 500) -> dict:
    """Enumerate EVERY enabled source, scoped to its configured groups.

    ``{ok, users, detail}``. Each user carries ``source``, ``source_group`` and
    the group's ``profile`` (blank = global default). A username seen in more
    than one scope keeps the FIRST one, so source/group order decides the
    profile — the same order that decides sign-in."""
    order = backends()
    if not order:
        return {"ok": False, "users": [],
                "detail": "Directory sync needs at least one external "
                          "authentication source (AD, LDAP or FortiAuthenticator)."}

    users: list[dict] = []
    seen: set[str] = set()
    notes = []
    for source in order:
        res = _list_fac_users(limit=limit) if source == "radius" \
            else _list_ldap_users(source, limit=limit)
        if not res["ok"]:
            return res
        for entry in res["users"]:
            uname = (entry.get("username") or "").strip()
            if not uname or uname.lower() in seen:
                continue
            seen.add(uname.lower())
            users.append(entry)
        # Carry each source's OWN detail through: which groups were read, and
        # how many each yielded. A bare total hides an empty group inside a
        # healthy-looking number.
        notes.append(f"{source}: {res['detail']}")
    return {"ok": True, "users": users[:max(1, int(limit))],
            "detail": " | ".join(notes)}


def sync_directory_users(default_active: bool = False, limit: int = 500) -> dict:
    """Provision local rows for every directory user (see ``list_directory_users``).

    NEW rows: ``auth_source`` = the source that listed them, the group's profile
    (or the global default), an unusable local password, ``is_active=default_active``
    (default DISABLED / pending — the admin enables + refines from Settings ->
    Users). EXISTING rows are NEVER touched.
    ``{ok, created, existing, total, detail}``."""
    listing = list_directory_users(limit=limit)
    if not listing["ok"]:
        return {"ok": False, "created": 0, "existing": 0, "total": 0,
                "detail": listing["detail"]}

    from ..extensions import db
    from ..models import User

    fallback_source = backend()
    created = existing = 0
    for entry in listing["users"]:
        uname = (entry.get("username") or "").strip()
        if not uname:
            continue
        if User.query.filter_by(username=uname).first() is not None:
            existing += 1
            continue
        prof = _profile_for(entry.get("profile") or "")
        user = User(username=uname,
                    auth_source=entry.get("source") or fallback_source,
                    is_active=bool(default_active))
        user.set_password(_secrets.token_urlsafe(48))
        if prof is not None:
            user.profile = prof
            user.role = prof.role_label
        db.session.add(user)
        created += 1
    db.session.commit()
    state = "active" if default_active else "disabled (pending approval)"
    return {"ok": True, "created": created, "existing": existing,
            "total": created + existing,
            "detail": (f"{created} new user(s) imported as {state}; "
                       f"{existing} already existed.")}


__all__ = [
    "BACKENDS", "EXTERNAL_BACKENDS", "DEFAULT_PROFILE_FALLBACK",
    "backend", "backends", "is_enabled", "default_profile_name",
    "config", "save_config", "test_connection", "require_approval",
    "fac_client", "fac_sync_group", "fac_sync_appliance_id", "sync_groups",
    "authenticate_external", "provision_external_user",
    "list_directory_users", "sync_directory_users",
]
