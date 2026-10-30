"""Administrator > Access > Directory connections -- the directory servers an
app's sign-in may prove people against (services.app_signin).

A connection is one AD, LDAP or RADIUS / FortiAuthenticator server with its
own address, bind identity and secret; any number of them, independent of the
global sign-in chain (``auth_store``), which they never change. The same
transport code (``directory_auth``) talks to them -- a connection only builds
a different ``cfg`` dict.

SECRETS
-------
The bind password (LDAP) and the RADIUS shared secret are never a column and
never leave the server: an ``app_settings`` row (Fernet) mirrored to the vault
when one is configured, exactly like the global directory secrets. The UI only
learns ``has_secret``; a blank secret field on save keeps the stored one.

These are NOT Plugin Studio connections: those are handed to app and script
code on purpose, and a secret that proves who may sign in must not be.
"""
from __future__ import annotations

import json
import re

from ..extensions import db
from ..models_studio import DirectoryConnection, StudioApp

SLUG_RE = re.compile(r"^[a-z][a-z0-9-]{1,38}[a-z0-9]$")
KINDS = DirectoryConnection.KINDS
KIND_LABELS = {"ad": "Active Directory", "ldap": "LDAP", "radius": "RADIUS / FortiAuthenticator"}

#: The non-secret settings each kind keeps, with their type.
_FIELDS = {
    "ad": {"host": str, "port": int, "use_ssl": bool, "start_tls": bool, "tls_verify": bool,
           "base_dn": str, "user_attr": str, "ad_domain": str, "timeout": int},
    "ldap": {"host": str, "port": int, "use_ssl": bool, "start_tls": bool, "tls_verify": bool,
             "base_dn": str, "user_attr": str, "bind_dn": str, "user_filter": str,
             "timeout": int},
    "radius": {"host": str, "port": int, "nas_id": str, "timeout": int},
}
_DEFAULTS = {"tls_verify": True, "timeout": 8}


class ConnectionError_(ValueError):
    """A connection that cannot be saved, tested or removed as asked."""


def _secret_key(cid: int) -> str:
    return "directory_connection.%d.secret_enc" % cid


def _vault_path(slug: str) -> str:
    return "directory/%s" % slug


def secret_field(kind: str) -> str:
    return "secret" if kind == "radius" else "bind_password"


def all_connections() -> list[DirectoryConnection]:
    return DirectoryConnection.query.order_by(DirectoryConnection.name).all()


def get(cid) -> DirectoryConnection | None:
    try:
        return db.session.get(DirectoryConnection, int(cid))
    except (TypeError, ValueError):
        return None


def has_secret(c: DirectoryConnection) -> bool:
    from ..models import AppSetting
    return bool(AppSetting.get(_secret_key(c.id)))


def _secret(c: DirectoryConnection) -> str:
    from .auth_store import _vault_first
    return _vault_first(_vault_path(c.slug), secret_field(c.kind), _secret_key(c.id))


def cfg_of(c: DirectoryConnection, *, reveal: bool = True) -> dict:
    """The ``directory_auth`` config of *c*: its settings, the per-kind
    defaults, and (``reveal``) the secret. Never handed to a template."""
    cfg = dict(_DEFAULTS)
    cfg.update(c.cfg)
    cfg["kind"] = c.kind
    if c.kind in ("ad", "ldap") and not cfg.get("user_attr"):
        cfg["user_attr"] = "sAMAccountName" if c.kind == "ad" else "uid"
    if reveal:
        cfg[secret_field(c.kind)] = _secret(c)
    return cfg


def public(c: DirectoryConnection) -> dict:
    """What the page may show: the settings and whether a secret is stored."""
    return {"id": c.id, "slug": c.slug, "name": c.name, "kind": c.kind,
            "kind_label": KIND_LABELS.get(c.kind, c.kind), "enabled": bool(c.enabled),
            "cfg": cfg_of(c, reveal=False), "has_secret": has_secret(c),
            "accounts": accounts_of(c.id), "apps": apps_using(c.id)}


def _coerce(kind: str, raw: dict) -> dict:
    out = {}
    for key, typ in _FIELDS[kind].items():
        val = raw.get(key)
        if typ is bool:
            out[key] = bool(val) if val is not None else bool(_DEFAULTS.get(key, False))
        elif typ is int:
            if val in (None, ""):
                if key in _DEFAULTS:
                    out[key] = _DEFAULTS[key]
                continue
            try:
                n = int(str(val).strip())
            except ValueError:
                raise ConnectionError_("%s: a whole number" % key) from None
            if key == "port" and not 1 <= n <= 65535:
                raise ConnectionError_("port: 1 to 65535")
            if key == "timeout" and not 1 <= n <= 60:
                raise ConnectionError_("timeout: 1 to 60 seconds")
            out[key] = n
        else:
            s = str(val or "").strip()
            if len(s) > 1000:
                raise ConnectionError_("%s: too long" % key)
            if s:
                out[key] = s
    if not out.get("host"):
        raise ConnectionError_("a host is required")
    if out.get("use_ssl") and out.get("start_tls"):
        raise ConnectionError_("choose LDAPS or StartTLS, not both")
    flt = out.get("user_filter")
    if flt and ("{username}" not in flt or not (flt.startswith("(") and flt.endswith(")"))):
        raise ConnectionError_("user filter: an LDAP filter in parentheses that contains "
                               "{username}, e.g. (sAMAccountName={username})")
    return out


def save(c: DirectoryConnection | None, form: dict, by: str) -> DirectoryConnection:
    """Create (``c`` None) or update a connection. The slug and the kind are
    fixed at creation: accounts are qualified with the slug and pinned to the
    kind, so changing either would re-point every account it made."""
    name = str(form.get("name") or "").strip()[:120]
    if not name:
        raise ConnectionError_("a name is required")
    # Everything is checked BEFORE the row joins the session: a half-made row
    # left behind by a refusal would be flushed by the next query.
    if c is None:
        slug = str(form.get("slug") or "").strip().lower()
        if not SLUG_RE.match(slug):
            raise ConnectionError_("id: 3 to 40 characters, lower-case letters, digits and "
                                   "dashes, starting with a letter")
        if DirectoryConnection.query.filter_by(slug=slug).first() is not None:
            raise ConnectionError_("a connection with id %s already exists" % slug)
        kind = str(form.get("kind") or "")
        if kind not in KINDS:
            raise ConnectionError_("kind: one of %s" % ", ".join(KINDS))
        cfg = _coerce(kind, form.get("cfg") or {})
        secret = form.get("secret")
        if kind == "radius" and not (isinstance(secret, str) and secret):
            raise ConnectionError_("a RADIUS connection needs its shared secret")
        c = DirectoryConnection(slug=slug, kind=kind, created_by=by)
        db.session.add(c)
    else:
        cfg = _coerce(c.kind, form.get("cfg") or {})
    c.name = name
    c.cfg_json = json.dumps(cfg, sort_keys=True)
    c.updated_by = by
    if "enabled" in form:
        c.enabled = bool(form.get("enabled"))
    db.session.flush()
    secret = form.get("secret")
    if isinstance(secret, str) and secret != "":
        from .auth_store import _store_secret
        _store_secret(_vault_path(c.slug), secret_field(c.kind), _secret_key(c.id), secret,
                      extra={"connection": c.slug})
    if c.kind == "radius" and not has_secret(c):
        db.session.rollback()
        raise ConnectionError_("a RADIUS connection needs its shared secret")
    db.session.commit()
    return c


def accounts_of(cid: int) -> int:
    from ..models import User
    return User.query.filter_by(login_connection_id=cid).count()


def apps_using(cid: int) -> list[str]:
    out = []
    for a in StudioApp.query.order_by(StudioApp.slug).all():
        if any(str(r.get("connection_id")) == str(cid) for r in a.login.get("rules") or []
               if isinstance(r, dict)):
            out.append(a.slug)
    return out


def delete(c: DirectoryConnection) -> None:
    """Refused while accounts or app rules point at it: disable it instead."""
    n = accounts_of(c.id)
    if n:
        raise ConnectionError_("%d account(s) were made through this connection; disable it "
                               "instead (its accounts can then no longer sign in)" % n)
    used = apps_using(c.id)
    if used:
        raise ConnectionError_("used by the sign-in of: %s" % ", ".join(used))
    from ..models import AppSetting
    row = db.session.get(AppSetting, _secret_key(c.id))
    if row is not None:
        db.session.delete(row)
    db.session.delete(c)
    db.session.commit()


def test(c: DirectoryConnection, username: str = "", password: str = "") -> tuple[bool, str]:
    """The Settings test, against this connection's own config."""
    from . import directory_auth
    try:
        cfg = cfg_of(c)
    except Exception as exc:  # noqa: BLE001 -- e.g. the vault owns the secret and is away
        return False, str(exc)
    if c.kind == "radius":
        if username and password:
            ok, detail, groups = directory_auth.radius_authenticate_groups(cfg, username, password)
            if ok:
                detail += (" Groups in the reply: %s." % ", ".join(groups) if groups
                           else " The reply named no group (Fortinet-Group-Name).")
            return ok, detail
        return directory_auth.radius_test(cfg)
    return directory_auth.ldap_test(cfg, username, password)
