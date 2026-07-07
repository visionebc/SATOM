"""Authentication backend configuration + external-auth dispatcher.

The admin picks ONE active source of truth for sign-in (Settings → Authentication):

* ``local``  — local DB accounts only (always available; the anti-lockout floor).
* ``ad``     — Active Directory (LDAP under the hood, UPN simple bind).
* ``ldap``   — generic LDAP (service-account search + user re-bind).
* ``radius`` — FortiAuthenticator / any RADIUS server (FortiToken-friendly).

At most ONE external backend is enabled at a time — the safest model against
lockout (local always works; you can't misconfigure two directories into a
deadlock). New directory users are just-in-time provisioned as local rows with
``auth_source`` set and the **operator** profile by default; an admin elevates
them afterwards from Settings → Users.

Persistence + secret handling mirror ``email_service``: everything in the
``app_settings`` table, the bind password / RADIUS secret Fernet-encrypted, a
blank secret field on save KEEPS the stored one (blank-keeps-existing).
"""
from __future__ import annotations

import secrets as _secrets

from ..models import AppSetting
from . import directory_auth, encryption

# ---- keys -----------------------------------------------------------------
K_BACKEND = "auth.backend"                    # local | ad | ldap | radius
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
K_L_SYNCGROUP = "auth.ldap.sync_group_dn"    # optional group/OU DN to scope Sync
K_L_TIMEOUT = "auth.ldap.timeout"

# RADIUS
K_R_HOST = "auth.radius.host"
K_R_PORT = "auth.radius.port"
K_R_SECRET = "auth.radius.secret_enc"         # Fernet token
K_R_NASID = "auth.radius.nas_id"
K_R_TIMEOUT = "auth.radius.timeout"

BACKENDS = ("local", "ad", "ldap", "radius")

DEFAULTS = {
    K_BACKEND: "local",
    K_DEFAULT_PROFILE: "operator",
    K_L_PORT: "389",
    K_L_SSL: "0",
    K_L_STARTTLS: "0",
    K_L_VERIFY: "1",
    K_L_USERATTR: "",        # resolved per-kind below
    K_L_FILTER: "",
    K_L_TIMEOUT: "8",
    K_R_PORT: "1812",
    K_R_TIMEOUT: "8",
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


# ---- public state ---------------------------------------------------------
def backend() -> str:
    val = _get(K_BACKEND)
    return val if val in BACKENDS else "local"


def is_enabled() -> bool:
    """True when an EXTERNAL backend is active (i.e. not plain local)."""
    return backend() != "local"


def default_profile_name() -> str:
    return (_get(K_DEFAULT_PROFILE) or "operator").strip() or "operator"


# ---- config (read) --------------------------------------------------------
def config(*, reveal_secrets: bool = False) -> dict:
    """Full auth config for the Settings template. Secrets are exposed as
    ``has_*`` flags only, unless ``reveal_secrets`` (used by the dispatcher)."""
    b = backend()
    cfg = {
        "backend": b,
        "default_profile": default_profile_name(),
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
            "sync_group_dn": _get(K_L_SYNCGROUP),
            "timeout": _to_int(_get(K_L_TIMEOUT), 8),
            "has_bind_password": bool(AppSetting.get(K_L_BINDPW)),
        },
        "radius": {
            "host": _get(K_R_HOST),
            "port": _to_int(_get(K_R_PORT), 1812),
            "nas_id": _get(K_R_NASID),
            "timeout": _to_int(_get(K_R_TIMEOUT), 8),
            "has_secret": bool(AppSetting.get(K_R_SECRET)),
        },
    }
    if reveal_secrets:
        cfg["ldap"]["bind_password"] = _dec(AppSetting.get(K_L_BINDPW))
        cfg["radius"]["secret"] = _dec(AppSetting.get(K_R_SECRET))
    return cfg


def _resolved_ldap_cfg(reveal: bool = True) -> dict:
    """An ``ldap``-section dict with sensible per-kind defaults filled in, ready
    for ``directory_auth``."""
    cfg = config(reveal_secrets=reveal)["ldap"]
    kind = cfg["kind"]
    if not cfg.get("user_attr"):
        cfg["user_attr"] = "sAMAccountName" if kind == "ad" else "uid"
    return cfg


# ---- config (write) -------------------------------------------------------
def save_config(form) -> None:
    """Persist from a Flask ``request.form`` (or mapping). Secrets: blank field
    keeps the stored value; switching away from a backend leaves its config
    intact (so toggling back doesn't lose settings)."""
    def g(key, default=""):
        return (form.get(key, default) or "").strip()

    b = g("backend", "local")
    b = b if b in BACKENDS else "local"
    AppSetting.set(K_BACKEND, b)
    AppSetting.set(K_DEFAULT_PROFILE, g("default_profile") or "operator")

    # LDAP / AD section (saved whenever the chosen backend is ad/ldap).
    if b in ("ad", "ldap"):
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
        AppSetting.set(K_L_SYNCGROUP, g("ldap_sync_group_dn"))
        AppSetting.set(K_L_TIMEOUT, str(max(2, min(60, _to_int(g("ldap_timeout"), 8)))))
        new_pw = form.get("ldap_bind_password", "")
        if new_pw:
            AppSetting.set(K_L_BINDPW, encryption.encrypt(new_pw))

    # RADIUS section.
    if b == "radius":
        AppSetting.set(K_R_HOST, g("radius_host"))
        AppSetting.set(K_R_PORT, str(_to_int(g("radius_port"), 1812)))
        AppSetting.set(K_R_NASID, g("radius_nas_id") or "fortinet-manager")
        AppSetting.set(K_R_TIMEOUT, str(max(2, min(60, _to_int(g("radius_timeout"), 8)))))
        new_secret = form.get("radius_secret", "")
        if new_secret:
            AppSetting.set(K_R_SECRET, encryption.encrypt(new_secret))


# ---- test connection ------------------------------------------------------
def test_connection(form) -> dict:
    """Test the SUBMITTED config (so the admin can verify BEFORE saving). Falls
    back to the stored secret when the secret field is left blank."""
    b = (form.get("backend") or "local").strip()
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
            "nas_id": (form.get("radius_nas_id") or "").strip() or "fortinet-manager",
            "timeout": _to_int(form.get("radius_timeout"), 8),
            "secret": form.get("radius_secret") or _dec(AppSetting.get(K_R_SECRET)),
        }
        ok, detail = directory_auth.radius_test(cfg, test_user, test_pw)
        return {"ok": ok, "detail": detail}

    return {"ok": False, "detail": f"Unknown backend {b!r}."}


# ---- dispatch (login time) ------------------------------------------------
def authenticate_external(username: str, password: str) -> dict:
    """Bind *username*/*password* against the active external backend.

    Returns ``{ok, source, detail}``. ``source`` is the backend name so the
    JIT provisioner can stamp ``auth_source``."""
    b = backend()
    if b == "local":
        return {"ok": False, "source": "local", "detail": "No external backend configured."}
    if b in ("ad", "ldap"):
        ok, detail = directory_auth.ldap_authenticate(_resolved_ldap_cfg(), username, password)
        return {"ok": ok, "source": b, "detail": detail}
    if b == "radius":
        cfg = config(reveal_secrets=True)["radius"]
        ok, detail = directory_auth.radius_authenticate(cfg, username, password)
        return {"ok": ok, "source": "radius", "detail": detail}
    return {"ok": False, "source": b, "detail": f"Unknown backend {b!r}."}


# ---- JIT provisioning -----------------------------------------------------
def provision_external_user(username: str, source: str):
    """Create (or refresh) the local row for an authenticated directory user.

    NEW user → ``auth_source=source`` + the configured default profile
    (operator). EXISTING user → never downgraded (keeps the admin-assigned
    profile); a still-``local`` row is NOT flipped to external (protects the
    seed admin)."""
    from ..extensions import db
    from ..models import Profile, User

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

    prof = (Profile.query.filter_by(name=default_profile_name()).first()
            or Profile.query.filter_by(name="operator").first())
    user = User(username=username, auth_source=source, is_active=True)
    # External users authenticate at the directory — give them an unusable
    # local password so check_password() can never succeed locally.
    user.set_password(_secrets.token_urlsafe(48))
    if prof is not None:
        user.profile = prof
        user.role = prof.role_label
    db.session.add(user)
    db.session.commit()
    return user


# ---- directory sync (admin action) ----------------------------------------
def list_directory_users(limit: int = 500) -> dict:
    """Enumerate the active AD/LDAP backend's users (scoped to the configured
    sync group/OU). ``{ok, users, detail}``. Not supported on RADIUS/local."""
    b = backend()
    if b not in ("ad", "ldap"):
        return {"ok": False, "users": [],
                "detail": "Directory sync needs an Active Directory or LDAP backend."}
    cfg = _resolved_ldap_cfg()
    ok, res = directory_auth.ldap_list_users(cfg, group_dn=_get(K_L_SYNCGROUP), limit=limit)
    if not ok:
        return {"ok": False, "users": [], "detail": str(res)}
    return {"ok": True, "users": res, "detail": f"{len(res)} user(s) found."}


def sync_directory_users(default_active: bool = False, limit: int = 500) -> dict:
    """Provision local rows for every directory user (see ``list_directory_users``).

    NEW rows: ``auth_source`` = active backend, the default profile, an unusable
    local password, ``is_active=default_active`` (default DISABLED / pending —
    the admin enables + refines from Settings -> Users). EXISTING rows are NEVER
    touched. ``{ok, created, existing, total, detail}``."""
    listing = list_directory_users(limit=limit)
    if not listing["ok"]:
        return {"ok": False, "created": 0, "existing": 0, "total": 0,
                "detail": listing["detail"]}

    from ..extensions import db
    from ..models import Profile, User

    source = backend()
    prof = (Profile.query.filter_by(name=default_profile_name()).first()
            or Profile.query.filter_by(name="operator").first())

    created = existing = 0
    for entry in listing["users"]:
        uname = (entry.get("username") or "").strip()
        if not uname:
            continue
        if User.query.filter_by(username=uname).first() is not None:
            existing += 1
            continue
        user = User(username=uname, auth_source=source, is_active=bool(default_active))
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
    "BACKENDS", "backend", "is_enabled", "default_profile_name",
    "config", "save_config", "test_connection",
    "authenticate_external", "provision_external_user",
    "list_directory_users", "sync_directory_users",
]
