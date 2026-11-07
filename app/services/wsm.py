"""Web Server Manager (Linux ADOM) -- who may do what on which server, as whom.

The wire is :mod:`services.wsm_transport`; the server side is
``hostctl/satom-wsm.py``. This module is the policy between them, and every
operation of every page goes through :func:`execute`:

1. **SATOM permission** (RBAC, in the server, never trusted from the browser):
   reading needs ``webserver.view``; changing needs the module's permission
   (``webserver.files`` / ``.sites`` / ``.system``); running anything as root
   needs ``webserver.root`` on top.
2. **The credential may be used**: active, not expired, not revoked, the
   caller's own or a shared service credential, allowed for this module.
3. **The server may be changed**: a write needs Allow writes on the server.
4. **Who runs it on the server** -- the credential's run-as:
   ``self`` (the SSH account), ``root`` (always through sudo) or ``auto``
   (as the account first; when the server answers *permission denied* and the
   credential may escalate, the same operation again through sudo). How sudo
   is reached is the operator's choice on the credential: with the account's
   own password, with a separate password asked each time, or a NOPASSWD rule.
5. **Secrets on demand**: a credential that does not keep its secret makes
   :func:`execute` raise :class:`NeedSecret`; the page asks and sends it with
   the retry, it is used for that one call and never stored or logged.
6. **One audit row per attempt** (:class:`models_wsm.WsmAudit`) with the
   three identities -- SATOM user, SSH user, effective Linux user -- whether
   sudo was used, the credential and the session id; writes also go to the
   application audit log.
"""
from __future__ import annotations

import json
import logging
import re
import threading
from datetime import datetime, timedelta

from ..extensions import db
from ..models_wsm import WsmAudit, WsmCredential, WsmRun, WsmSchedule, WsmScript
from . import prefixed_secret as PS
from . import wsm_transport as T

_log = logging.getLogger(__name__)

#: op -> (module, writes). Module "" = always allowed with webserver.view.
OPS: dict[str, tuple[str, bool]] = {
    "whoami": ("", False), "info": ("sites", False), "host.health": ("", False),
    "vhosts.list": ("sites", False), "vhost.get": ("sites", False),
    "vhost.test": ("sites", False), "http.check": ("sites", False),
    "apache.override": ("sites", False),
    "vhost.put": ("sites", True), "vhost.create": ("sites", True),
    "vhost.enable": ("sites", True), "vhost.disable": ("sites", True),
    "vhost.delete": ("sites", True), "vhost.snippet": ("sites", True),
    "htaccess.apply": ("sites", True),
    "fs.list": ("files", False), "fs.stat": ("files", False), "fs.read": ("files", False),
    "fs.search": ("files", False), "fs.history": ("files", False),
    "fs.version": ("files", False),
    "fs.write": ("files", True), "fs.mkdir": ("files", True), "fs.move": ("files", True),
    "fs.copy": ("files", True), "fs.delete": ("files", True), "fs.chmod": ("files", True),
    "fs.chown": ("files", True), "fs.archive": ("files", True), "fs.extract": ("files", True),
    "fs.restore": ("files", True),
    "certs.list": ("certs", False), "cert.get": ("certs", False),
    "acme.status": ("certs", False), "tls.check": ("certs", False),
    "cert.csr": ("certs", True), "cert.install": ("certs", True),
    "cert.assign": ("certs", True), "cert.delete": ("certs", True),
    "cert.import": ("certs", True), "acme.issue": ("certs", True),
    "acme.renew": ("certs", True), "acme.revoke": ("certs", True),
    "acme.autorenew": ("certs", True),
    "pkg.search": ("packages", False), "pkg.installed": ("packages", False),
    "pkg.show": ("packages", False), "pkg.updates": ("packages", False),
    "pkg.plan": ("packages", False),
    "pkg.refresh": ("packages", True), "pkg.apply": ("packages", True),
    "svc.list": ("services", False), "svc.status": ("services", False),
    "svc.deps": ("services", False), "svc.logs": ("services", False),
    "svc.action": ("services", True),
    "cron.get": ("cron", False), "cron.users": ("cron", False), "cron.log": ("cron", False),
    "cron.put": ("cron", True),
    "logs.sources": ("logs", False), "logs.read": ("logs", False),
    "journal.read": ("logs", False),
    "security.scan": ("security", False), "f2b.status": ("security", False),
    "fw.rule": ("security", True), "fw.enable": ("security", True),
    "f2b.unban": ("security", True),
    "users.list": ("users", False),
    "user.add": ("users", True), "user.mod": ("users", True), "user.del": ("users", True),
    "group.add": ("users", True), "group.del": ("users", True),
    "sshd.get": ("ssh", False), "authkeys.get": ("ssh", False),
    "sshd.set": ("ssh", True), "authkeys.put": ("ssh", True),
    "script.run": ("scripts", True),
}
#: Operations the restricted agent (satom-webctl as satom-mon) answers, and
#: their session-helper equivalents.
AGENT_OPS = {"host.health", "info", "vhosts.list", "vhost.get", "vhost.put", "vhost.create", "vhost.enable",
             "vhost.disable", "vhost.delete", "certs.list", "cert.get", "cert.csr",
             "cert.install", "cert.assign", "cert.delete"}
MODULE_PERM = {"files": "webserver.files", "sites": "webserver.sites",
               "certs": "webserver.sites"}
SYSTEM_PERM = "webserver.system"
ROOT_PERM = "webserver.root"
VIEW_PERM = "webserver.view"
CRED_PERM = "webserver.credentials"
MODULES = {
    "health": ("Health", "bi-heart-pulse", "Memory, disks, load, processes, failed services"),
    "files": ("File Manager", "bi-folder2-open", "Browse, edit, upload and download files"),
    "sites": ("Domains & VHosts", "bi-globe2", "Websites, domains, PHP, redirects"),
    "certs": ("SSL Certificates", "bi-shield-lock", "Let's Encrypt, import, renew, expiry"),
    "security": ("Security", "bi-shield-check", "Risk score, findings, firewall, fail2ban"),
    "htaccess": (".htaccess", "bi-sliders", "Redirects, blocks and rules without writing code"),
    "scripts": ("Scripts", "bi-terminal", "Script library: upload, run, history"),
    "cron": ("Cron Jobs", "bi-clock-history", "Scheduled tasks on the server and by SATOM"),
    "packages": ("Package Manager", "bi-box-seam", "Search, install, update, remove"),
    "services": ("Services", "bi-gear-wide-connected", "Start, stop, restart, boot"),
    "logs": ("Logs", "bi-journal-text", "Web, PHP, system, auth and cron logs"),
    "users": ("Users & Permissions", "bi-people", "Accounts, groups, passwords"),
    "ssh": ("SSH Configuration", "bi-key", "SSH server settings and authorized keys"),
}
SECRET_ARGS = ("content", "content_b64", "private_key", "password", "certificate", "chain",
               "keys", "env", "settings")
TARGET_ARGS = ("path", "paths", "to", "dest", "name", "names", "server", "user", "unit",
               "domains", "action", "port", "jail", "ip", "cert", "q", "host", "interpreter",
               "mode", "owner", "group")


def module_adoms() -> tuple:
    """The active ADOMs the Web Server Manager is switched on in (ADOM
    capability ``webserver``). Empty = the module is off: no menu, its pages
    404, scheduled scripts and certificate reads wait."""
    from .. import branding
    try:
        return tuple(branding.products_with("webserver"))
    except Exception:  # noqa: BLE001 -- unreadable registry = off (fail closed)
        return ()


def module_active() -> bool:
    return bool(module_adoms())


# --------------------------------------------------------------------------- #
#  device scope: a server is a chassis, a site its partition (2026-11-07)     #
# --------------------------------------------------------------------------- #
#: Scope entry of a server in the profile's device scope (services.device_scope).
SCOPE_ENTRY = "server:"
#: With only SOME sites of a server, the operations on those sites and on
#: their files; everything else acts on the whole server (packages, services,
#: users, SSH, cron, security, certificates, scripts, logs) and is refused --
#: the chassis rule of the device scope.
SITE_OPS = frozenset({"whoami", "info", "vhosts.list", "vhost.get", "vhost.put",
                      "vhost.enable", "vhost.disable", "vhost.test", "http.check",
                      "htaccess.apply"}) | frozenset(op for op in (
                          "fs.list", "fs.stat", "fs.read", "fs.search", "fs.history",
                          "fs.version", "fs.write", "fs.mkdir", "fs.move", "fs.copy",
                          "fs.delete", "fs.chmod", "fs.chown", "fs.archive", "fs.extract",
                          "fs.restore"))
#: Operations whose paths are confined to the sites' document roots (by the
#: helper on the server, symlinks resolved: services never trust a path).
JAIL_OPS = frozenset(op for op in SITE_OPS if op.startswith("fs.")) | {"htaccess.apply"}
#: Operations that name ONE site (``args["name"]``).
SITE_NAMED = frozenset({"vhost.get", "vhost.put", "vhost.enable", "vhost.disable"})
#: The pages of a server a site-scoped profile opens.
SITE_PAGES = ("files", "sites", "htaccess")
VHOSTS_KEY = "wsm.vhosts."


def site_key(name) -> str:
    """A site as the scope names it: lower case, without ``.conf``."""
    n = str(name or "").strip().lower()
    return n[:-5] if n.endswith(".conf") else n


def server_scope(user) -> dict | None:
    """``{slug: None | frozenset(sites)}`` the user reaches; ``None`` = every
    server. From the profile's device scope under the manager's ADOM(s): an
    ADOM the profile does not have reaches no server; a scope that names no
    server there keeps every server."""
    from .product_scope import adoms_of, device_scope_of
    keys = module_adoms()
    adoms = adoms_of(user)
    if adoms is not None:
        keys = tuple(k for k in keys if k in adoms)
        if not keys:
            return {}
    scope = device_scope_of(user)
    if scope is None:
        return None
    out, scoped = {}, False
    for k in keys:
        entries = scope.get(k, scope.get("*"))
        if entries is None:
            return None                       # this ADOM is not scoped
        scoped = True
        for key, parts in entries.items():
            if key.startswith(SCOPE_ENTRY):
                slug = key[len(SCOPE_ENTRY):]
                prev = out.get(slug, frozenset())
                out[slug] = None if parts is None or prev is None else (
                    prev | {site_key(p) for p in parts})
    return out if scoped else None


def visible_servers(user) -> list:
    sc = server_scope(user)
    return [c for c in servers() if sc is None or c.slug in sc]


def may_see_server(user, slug: str) -> bool:
    sc = server_scope(user)
    return sc is None or slug in sc


def site_scope(user, slug: str):
    """``None`` = the whole server; a frozenset = only those sites."""
    sc = server_scope(user)
    return None if sc is None else sc.get(slug, frozenset())


def scope_gate(user, c, op: str, args: dict):
    """The device scope of ``user`` on server ``c`` for ``op``. Raises
    WsmDenied; returns the sites (None = whole server)."""
    sc = server_scope(user)
    if sc is None:
        return None
    if c.slug not in sc:
        raise WsmDenied("no server %s" % c.slug)
    sites = sc[c.slug]
    if sites is None:
        return None
    if op not in SITE_OPS:
        raise WsmDenied("your profile reaches only some sites of %s (%s): %s acts on the "
                        "whole server" % (c.name, ", ".join(sorted(sites)) or "none",
                                          MODULES.get(OPS.get(op, ("", False))[0],
                                                      (op,))[0]))
    if op in SITE_NAMED and site_key(args.get("name")) not in sites:
        raise WsmDenied("your profile does not reach the site %s of %s"
                        % (args.get("name"), c.name))
    return sites


def remember_vhosts(slug: str, result) -> None:
    """Keep the sites a server answered (name -> document roots): the
    Profiles form offers them, and a site-scoped profile's files are confined
    to their roots. Never raises."""
    from . import settings_store as ST
    try:
        rows = (result or {}).get("vhosts") or []
        sites = {}
        for v in rows:
            if isinstance(v, dict) and v.get("name"):
                roots = [r for r in (v.get("docroots") or []) if isinstance(r, str)]
                sites.setdefault(site_key(v["name"]), [])
                sites[site_key(v["name"])] += [r for r in roots
                                               if r not in sites[site_key(v["name"])]]
        ST.set_json(VHOSTS_KEY + slug, {"at": datetime.utcnow().isoformat(timespec="seconds"),
                                        "sites": sites})
    except Exception:  # noqa: BLE001
        _log.debug("remember_vhosts failed for %s", slug, exc_info=True)


def known_sites(slug: str) -> dict:
    """``{site: [document roots]}`` from the last answer of the server."""
    from . import settings_store as ST
    raw = ST.get_json_checked(VHOSTS_KEY + slug, {}, dict)
    if raw is ST.MALFORMED or not isinstance(raw, dict):
        return {}
    sites = raw.get("sites")
    return {str(k): [str(r) for r in v if isinstance(r, str)]
            for k, v in (sites or {}).items() if isinstance(v, list)} \
        if isinstance(sites, dict) else {}


def safe_root(path: str) -> bool:
    """A document root may confine files only below the top level: "/",
    "/var" or "/home" as a jail would be the whole server."""
    import posixpath
    p = posixpath.normpath(str(path or ""))
    return p.startswith("/") and len([x for x in p.split("/") if x]) >= 2


def jail_roots(sites, slug: str) -> list[str]:
    roots = []
    for s, rs in known_sites(slug).items():
        if s in sites:
            roots += [r for r in rs if safe_root(r) and r not in roots]
    return roots


class WsmDenied(Exception):
    """Refused by SATOM's own policy (HTTP 403)."""


class NeedSecret(Exception):
    """The credential keeps no secret, or sudo asks one: the page must ask.
    ``fields``: subset of ("secret", "passphrase", "sudo")."""

    def __init__(self, cred: WsmCredential, fields: list[str], why: str = ""):
        super().__init__(why or "credentials needed")
        self.cred = cred
        self.fields = fields
        self.why = why


# --------------------------------------------------------------------------- #
#  permissions                                                                 #
# --------------------------------------------------------------------------- #
def can(user, perm: str) -> bool:
    from ..rbac import has_permission
    return has_permission(user, perm)


def module_perm(module: str) -> str:
    return MODULE_PERM.get(module, SYSTEM_PERM)


def check_op(user, op: str, *, elevated: bool) -> tuple[str, bool]:
    if op not in OPS:
        raise WsmDenied("unknown operation %s" % op)
    module, writes = OPS[op]
    if not can(user, VIEW_PERM):
        raise WsmDenied("your profile does not include the Web Server Manager")
    if writes and not can(user, module_perm(module)):
        raise WsmDenied("your profile cannot change %s (needs %s)"
                        % (MODULES.get(module, (module,))[0], module_perm(module)))
    if elevated and not can(user, ROOT_PERM):
        raise WsmDenied("your profile cannot run operations as root (needs %s)" % ROOT_PERM)
    return module, writes


# --------------------------------------------------------------------------- #
#  servers = Plugin Studio server connections                                  #
# --------------------------------------------------------------------------- #
def servers():
    from . import studio_connections as SC
    return SC.list_connections("server")


def server(slug: str):
    from . import studio_connections as SC
    c = SC.get(slug)
    if c is None or c.kind != "server":
        raise WsmDenied("no server %s" % slug)
    return c


def server_state(c) -> dict:
    from . import studio_connections as SC
    from .studio_server import fingerprint
    opts = SC.server_opts(c.slug)
    return {"host_key": opts.get("host_key") or "",
            "fingerprint": fingerprint(opts["host_key"]) if opts.get("host_key") else "",
            "allow_writes": bool(opts.get("allow_writes")),
            "agent_key": SC.has_secret(c.slug)}


def target(c) -> dict:
    st = server_state(c)
    return {"host": c.host, "port": int(c.port or 22), "host_key": st["host_key"]}


SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,46}$")


def create_server(form: dict, by: str):
    from . import studio_connections as SC
    slug = (form.get("slug") or "").strip().lower()
    if not SLUG_RE.match(slug):
        slug = re.sub(r"[^a-z0-9-]+", "-", (form.get("name") or form.get("host") or "")
                      .strip().lower()).strip("-")[:40] or "server"
    base, n = slug, 2
    while SC.get(slug) is not None:
        slug, n = "%s-%d" % (base, n), n + 1
    c = SC.create(slug, (form.get("name") or form.get("host") or slug).strip()[:120],
                  "server", by)
    SC.save(c, {"name": form.get("name") or c.name, "host": form.get("host"),
                "port": form.get("port") or 22, "username": "satom-mon",
                "description": form.get("description") or "Web Server Manager",
                "allow_writes": "1" if form.get("allow_writes") else "0",
                "timeout": form.get("timeout") or 30}, by)
    return c


def update_server(c, form: dict, by: str) -> bool:
    from . import studio_connections as SC
    return SC.save(c, {"name": form.get("name") or c.name, "host": form.get("host") or c.host,
                       "port": form.get("port") or c.port, "username": c.username or "satom-mon",
                       "description": form.get("description", c.description),
                       "allow_writes": "1" if form.get("allow_writes") else "0",
                       "timeout": form.get("timeout") or c.timeout}, by)


# --------------------------------------------------------------------------- #
#  credentials                                                                 #
# --------------------------------------------------------------------------- #
SECRET_PREFIX = "wsm.cred."      # secret_backend._PREFIXED_SECRETS migrates and scrubs it


def _skey(cid: int, field: str) -> str:
    return "%s%d.%s" % (SECRET_PREFIX, cid, field)


def _vpath(cid: int, field: str) -> str:
    """One vault path PER FIELD: storing an empty field deletes its path
    (prefixed_secret.store), and a shared path took the SSH secret with it
    when a credential cleared its passphrase or sudo password."""
    return "wsm/credentials/%d/%s" % (cid, field)


def secret(cred: WsmCredential, field: str) -> str:
    val, _problem = PS.state(_skey(cred.id, field), _vpath(cred.id, field), "value")
    return val or ""


def has(cred: WsmCredential, field: str) -> bool:
    return PS.present(_skey(cred.id, field))


def set_secret(cred: WsmCredential, field: str, value: str) -> None:
    PS.store(_skey(cred.id, field), _vpath(cred.id, field), value or "", "value")


def drop_secrets(cred: WsmCredential) -> None:
    for f in ("secret", "passphrase", "sudo"):
        try:
            set_secret(cred, f, "")
        except Exception:  # noqa: BLE001 -- a revoke must not stop on one field
            _log.warning("wsm: cannot drop %s of credential %s", f, cred.id, exc_info=True)


USER_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._@()-]{0,63}$")


def visible_credentials(slug: str, user) -> list[WsmCredential]:
    q = WsmCredential.query.filter_by(connection_slug=slug).order_by(WsmCredential.name)
    rows = q.all()
    if can(user, CRED_PERM):
        return rows
    me = getattr(user, "username", "")
    return [r for r in rows if r.owner == me or r.shared]


def usable(cred: WsmCredential, user) -> bool:
    return cred.owner == getattr(user, "username", "") or cred.shared


def manageable(cred: WsmCredential, user) -> bool:
    return cred.owner == getattr(user, "username", "") or can(user, CRED_PERM)


def save_credential(cred: WsmCredential | None, slug: str, form: dict, user) -> WsmCredential:
    """Create or update from the form. Secrets in the form are stored only when
    the credential keeps them; an empty secret field keeps the current one."""
    me = getattr(user, "username", "")
    name = (form.get("name") or "").strip()
    if not NAME_RE.match(name):
        raise WsmDenied("a name of letters, digits, spaces and . _ @ ( ) -")
    auth = form.get("auth_type") or "password"
    if auth not in WsmCredential.AUTH_TYPES:
        raise WsmDenied("unknown authentication")
    ssh_user = (form.get("ssh_user") or "").strip()
    if auth == "agent":
        ssh_user = server(slug).username or "satom-mon"
    if not USER_RE.match(ssh_user):
        raise WsmDenied("the SSH user is a Linux account name")
    esc = form.get("escalation") or "none"
    if esc not in WsmCredential.ESCALATIONS or (auth == "agent" and esc != "none"):
        raise WsmDenied("unknown privilege mode")
    run_as = form.get("run_as") or ("auto" if esc != "none" else "self")
    if run_as not in WsmCredential.RUN_AS or (esc == "none" and run_as != "self"):
        run_as = "self"
    sudo_pw = form.get("sudo_password") or "same"
    if sudo_pw not in WsmCredential.SUDO_PASSWORD:
        sudo_pw = "same"
    if auth == "key" and sudo_pw == "same":
        sudo_pw = "ask"           # a key has no password sudo could take
    shared = str(form.get("shared")).lower() in ("1", "true", "on", "yes")
    if shared and not can(user, CRED_PERM):
        raise WsmDenied("sharing a service credential needs %s" % CRED_PERM)
    store = str(form.get("store_secret", "1")).lower() in ("1", "true", "on", "yes") \
        or auth == "agent"
    mods = [m for m in (form.getlist("modules") if hasattr(form, "getlist")
                        else form.get("modules") or []) if m in WsmCredential.MODULES]
    exp = (form.get("expires_at") or "").strip()
    expires = None
    if exp:
        try:
            expires = datetime.strptime(exp[:10], "%Y-%m-%d")
        except ValueError:
            raise WsmDenied("expiry is a date YYYY-MM-DD") from None
    clash = WsmCredential.query.filter_by(connection_slug=slug, name=name).first()
    if clash is not None and (cred is None or clash.id != cred.id):
        raise WsmDenied("this server already has a credential named %s" % name)
    new = cred is None
    if new:
        cred = WsmCredential(connection_slug=slug, owner=me, created_by=me)
        db.session.add(cred)
    cred.name, cred.ssh_user, cred.auth_type = name, ssh_user, auth
    cred.description = (form.get("description") or "").strip()[:2000]
    cred.escalation, cred.run_as, cred.sudo_password = esc, run_as, sudo_pw
    cred.shared, cred.store_secret = shared, store
    cred.modules_json = json.dumps(mods)
    cred.expires_at = expires
    cred.updated_at = datetime.utcnow()
    db.session.flush()
    if auth == "agent":
        drop_secrets(cred)
    elif not store:
        drop_secrets(cred)
    else:
        if auth == "key" and form.get("generate_key"):
            from .studio_server import generate_key
            pem, _pub = generate_key("satom-wsm-%s" % name.replace(" ", "-"))
            set_secret(cred, "secret", pem)
            set_secret(cred, "passphrase", "")
        else:
            sec = form.get("secret") or ""
            if sec:
                if auth == "key" and "PRIVATE KEY" not in sec:
                    raise WsmDenied("paste the PRIVATE key (OpenSSH or PEM)")
                set_secret(cred, "secret", sec.strip() + ("\n" if auth == "key" else ""))
            if auth == "key" and form.get("passphrase"):
                set_secret(cred, "passphrase", form.get("passphrase"))
        if esc == "sudo" and sudo_pw == "ask":
            set_secret(cred, "sudo", "")
    db.session.commit()
    from .audit import log_action
    log_action("wsm.credential.%s" % ("create" if new else "update"),
               target="%s/%s" % (slug, name),
               extra={"ssh_user": ssh_user, "auth": auth, "escalation": esc, "run_as": run_as,
                      "store_secret": store, "shared": shared})
    return cred


def public_key(cred: WsmCredential) -> str:
    if cred.auth_type == "agent":
        from . import studio_connections as SC
        return SC.server_public_key(server(cred.connection_slug))
    if cred.auth_type != "key" or not cred.store_secret:
        return ""
    pem = secret(cred, "secret")
    if not pem or has(cred, "passphrase"):
        return ""
    from .studio_server import public_key as pk
    return pk(pem, "satom-wsm-%s" % cred.name.replace(" ", "-"))


def set_status(cred: WsmCredential, status: str, user) -> None:
    if status not in WsmCredential.STATUSES:
        raise WsmDenied("unknown status")
    cred.status = status
    cred.updated_at = datetime.utcnow()
    if status == "revoked":
        cred.revoked_at, cred.revoked_by = datetime.utcnow(), getattr(user, "username", "")
        drop_secrets(cred)
    db.session.commit()
    from .audit import log_action
    log_action("wsm.credential.%s" % status, target="%s/%s" % (cred.connection_slug, cred.name))
    if status != "active":
        park_schedules(cred, "the credential %s was %s" % (cred.name, status))


def delete_credential(cred: WsmCredential) -> None:
    park_schedules(cred, "the credential %s was deleted" % cred.name)
    drop_secrets(cred)
    from .audit import log_action
    log_action("wsm.credential.delete", target="%s/%s" % (cred.connection_slug, cred.name))
    db.session.delete(cred)
    db.session.commit()


def ensure_agent_credential(c, by: str = "system") -> WsmCredential | None:
    """The satom-webctl key of a server, as a shared credential the manager can
    pick (restricted to the agent's operations)."""
    from . import studio_connections as SC
    if not SC.has_secret(c.slug):
        return None
    row = WsmCredential.query.filter_by(connection_slug=c.slug, auth_type="agent").first()
    if row is None:
        row = WsmCredential(connection_slug=c.slug, name="satom-webctl agent",
                            ssh_user=c.username or "satom-mon", auth_type="agent",
                            escalation="none", run_as="self", shared=True, store_secret=True,
                            owner=by, created_by=by,
                            description="The restricted agent key installed with "
                                        "install-satom-webctl.sh: virtual hosts and "
                                        "certificates only, no shell.")
        db.session.add(row)
        db.session.commit()
    return row


# --------------------------------------------------------------------------- #
#  execute                                                                     #
# --------------------------------------------------------------------------- #
def _target_summary(args: dict) -> str:
    parts = []
    for k in TARGET_ARGS:
        if k in args and args[k] not in (None, "", [], {}):
            v = args[k]
            if isinstance(v, list):
                v = ",".join(str(x) for x in v[:10]) + ("..." if len(v) > 10 else "")
            parts.append("%s=%s" % (k, str(v)[:150]))
    return " ".join(parts)[:500]


def _audit(*, user, c, cred, op, module, args, ok, error="", detail="", who=None,
           session_id="", ms=None, sudo=False, mode="", exit_code=None) -> None:
    try:
        from ..extensions import real_client_ip
        ip = real_client_ip() or ""
    except Exception:  # noqa: BLE001 -- no request (scheduler)
        ip = ""
    who = who or {}
    row = WsmAudit(app_user=getattr(user, "username", "") or str(user or "system"),
                   ssh_user=cred.ssh_user if cred else "",
                   effective_user=str(who.get("user") or "")[:64],
                   effective_uid=who.get("uid") if isinstance(who.get("uid"), int) else None,
                   connection_slug=c.slug, host=c.host or "", module=module, op=op,
                   target=_target_summary(args or {}), ok=ok, error=(error or "")[:32],
                   detail=(detail or "")[:600], exit_code=exit_code, sudo=sudo,
                   credential_id=cred.id if cred else None,
                   credential_name=cred.name if cred else "", auth_mode=mode,
                   session_id=session_id, ms=ms, ip=ip[:45])
    db.session.add(row)
    db.session.commit()


def _account(cred: WsmCredential, provided: dict) -> dict:
    need = []
    if cred.store_secret:
        sec = secret(cred, "secret")
        pp = secret(cred, "passphrase") if cred.auth_type == "key" else ""
        if not sec:
            raise NeedSecret(cred, ["secret"], "the stored secret of %s is missing: enter it"
                             % cred.name)
    else:
        sec = provided.get("secret") or ""
        pp = provided.get("passphrase") or ""
        if not sec:
            need.append("secret")
            if cred.auth_type == "key":
                need.append("passphrase")
    if need:
        raise NeedSecret(cred, need, "%s asks for its %s at every operation"
                         % (cred.name, "password" if cred.auth_type == "password" else "key"))
    return {"user": cred.ssh_user, "auth_type": cred.auth_type, "secret": sec,
            "passphrase": pp}


def _sudo_password(cred: WsmCredential, account: dict, provided: dict) -> str:
    if cred.escalation != "sudo":
        return ""
    if cred.sudo_password == "same" and cred.auth_type == "password":
        return account["secret"]
    if provided.get("sudo"):
        return provided["sudo"]
    raise NeedSecret(cred, ["sudo"], "sudo needs the password of %s for this operation"
                     % cred.ssh_user)


def _elevate_kind(cred: WsmCredential) -> str:
    return "nopasswd" if cred.escalation == "sudo_nopasswd" else "sudo"


def pick_credential(c, user, cred_id) -> WsmCredential:
    cred = db.session.get(WsmCredential, int(cred_id)) if cred_id else None
    if cred is None or cred.connection_slug != c.slug:
        raise WsmDenied("pick a credential for %s (Servers > %s > Credentials)" % (c.name, c.name))
    if not usable(cred, user):
        raise WsmDenied("credential %s belongs to %s and is not shared" % (cred.name, cred.owner))
    st = cred.state
    if st != "active":
        raise WsmDenied("credential %s is %s" % (cred.name, st))
    return cred


def execute(slug: str, cred_id, op: str, args: dict | None = None, *, user,
            run_as: str = "", provided: dict | None = None, timeout: float = 120,
            mode: str = "") -> dict:
    """Run one operation. Returns ``{"result", "who", "sudo", "ms", "credential"}``.
    Raises WsmDenied (SATOM said no), NeedSecret (ask and retry) or
    T.WsmError (the server or the wire said no).

    The device scope of ``user`` comes first (:func:`scope_gate`): a server
    outside it does not exist, and with only some sites the operation must
    be one of :data:`SITE_OPS`, a named site one of them, and every path of a
    file operation is confined to their document roots BY THE HELPER (the
    ``_jail`` argument, symlinks resolved there). Arguments starting with
    ``_`` never come from a caller."""
    c = server(slug)
    args = {k: v for k, v in (args or {}).items() if not str(k).startswith("_")}
    sites = scope_gate(user, c, op, args)
    if sites is not None and op in JAIL_OPS:
        roots = jail_roots(sites, slug)
        if not roots or any(s not in known_sites(slug) for s in sites):
            listed = _execute(slug, cred_id, "vhosts.list", {}, user=user, run_as=run_as,
                              provided=provided, timeout=timeout, mode=mode)
            remember_vhosts(slug, listed["result"])
            roots = jail_roots(sites, slug)
        if not roots:
            raise WsmDenied("none of your sites on %s has a document root SATOM may confine "
                            "files to" % c.name)
        args["_jail"] = roots
    r = _execute(slug, cred_id, op, args, user=user, run_as=run_as, provided=provided,
                 timeout=timeout, mode=mode)
    if op == "vhosts.list" and isinstance(r.get("result"), dict):
        remember_vhosts(slug, r["result"])
        if sites is not None:
            r["result"] = dict(r["result"], vhosts=[
                v for v in r["result"].get("vhosts") or []
                if isinstance(v, dict) and site_key(v.get("name")) in sites])
    return r


def _execute(slug: str, cred_id, op: str, args: dict | None = None, *, user,
             run_as: str = "", provided: dict | None = None, timeout: float = 120,
             mode: str = "") -> dict:
    provided = provided or {}
    args = args or {}
    c = server(slug)
    check_op(user, op, elevated=False)      # the profile first: no credential detail leaks
    cred = pick_credential(c, user, cred_id)
    run_as = run_as or cred.run_as
    if run_as not in ("self", "auto", "root"):
        run_as = "self"
    if run_as != "self" and not cred.can_escalate:
        run_as = "self"
    if run_as == "auto" and not can(user, ROOT_PERM):
        run_as = "self"
    module, writes = check_op(user, op, elevated=(run_as == "root"))
    if cred.modules and module and module not in cred.modules and module != "logs":
        raise WsmDenied("credential %s is not allowed for %s" % (
            cred.name, MODULES.get(module, (module,))[0]))
    if writes and not server_state(c)["allow_writes"]:
        raise WsmDenied("%s is read-only in SATOM: turn on Allow changes on its server page"
                        % c.name)
    mode = mode or ("agent" if cred.auth_type == "agent" else
                    "service" if cred.store_secret else "interactive")
    if cred.auth_type == "agent":
        return _execute_agent(c, cred, op, args, user=user, module=module, mode=mode)
    account = _account(cred, provided)
    tgt = target(c)
    timeout = max(timeout, float(c.timeout or 30))

    def attempt(elevate: str):
        sudo_pw = _sudo_password(cred, account, provided) if elevate == "sudo" else ""
        try:
            r = T.call(tgt, account, op, args, elevate=elevate, sudo_password=sudo_pw,
                       timeout=timeout, by=getattr(user, "username", "") or "system")
        except T.WsmError as exc:
            _audit(user=user, c=c, cred=cred, op=op, module=module, args=args, ok=False,
                   error=exc.remote_error or exc.code, detail=str(exc), who=exc.who,
                   sudo=bool(elevate), mode=mode)
            raise
        res = r["result"] if isinstance(r["result"], dict) else {}
        _audit(user=user, c=c, cred=cred, op=op, module=module, args=args, ok=True,
               who=r["who"], session_id=r["session_id"], ms=r["ms"], sudo=bool(elevate),
               mode=mode, exit_code=res.get("exit_code") if isinstance(
                   res.get("exit_code"), int) else None)
        return r

    if run_as == "root":
        r = attempt(_elevate_kind(cred))
    else:
        try:
            r = attempt("")
        except T.WsmError as exc:
            if not (run_as == "auto" and exc.remote_error == "permission_denied"):
                raise
            r = attempt(_elevate_kind(cred))
    cred.last_used_at = datetime.utcnow()
    db.session.commit()
    if writes:
        from .audit import log_action
        log_action("wsm.%s" % op, target="%s %s" % (c.slug, _target_summary(args))[:256],
                   extra={"ssh_user": cred.ssh_user, "effective": r["who"].get("user"),
                          "sudo": r["elevated"], "credential": cred.name,
                          "session": r["session_id"]})
    return {"result": r["result"], "who": r["who"], "sudo": r["elevated"], "ms": r["ms"],
            "credential": cred.name, "session_id": r["session_id"]}


def _execute_agent(c, cred, op, args, *, user, module, mode):
    from . import studio_connections as SC
    if op not in AGENT_OPS:
        raise WsmDenied("%s is the restricted satom-webctl agent: it only manages virtual hosts "
                        "and certificates. Pick an SSH account credential for %s"
                        % (cred.name, MODULES.get(module, (module,))[0]))
    if op == "vhost.create":
        allowed = ("server", "name", "server_names", "kind", "docroot", "https", "cert", "key",
                   "php_socket")
        args = {k: v for k, v in args.items() if k in allowed}
    started = datetime.utcnow()
    try:
        res = SC.server_call(c, op, args)
    except Exception as exc:  # noqa: BLE001
        _audit(user=user, c=c, cred=cred, op=op, module=module, args=args, ok=False,
               error="agent", detail=str(exc), who={"user": cred.ssh_user}, mode=mode)
        raise T.WsmError("remote", str(exc)) from None
    ms = int((datetime.utcnow() - started).total_seconds() * 1000)
    _audit(user=user, c=c, cred=cred, op=op, module=module, args=args, ok=True,
           who={"user": cred.ssh_user}, ms=ms, mode=mode)
    if OPS[op][1]:
        from .audit import log_action
        log_action("wsm.%s" % op, target="%s %s" % (c.slug, _target_summary(args))[:256],
                   extra={"ssh_user": cred.ssh_user, "credential": cred.name, "agent": True})
    return {"result": res, "who": {"user": cred.ssh_user}, "sudo": False, "ms": ms,
            "credential": cred.name, "session_id": ""}


# --------------------------------------------------------------------------- #
#  long operations as jobs                                                     #
# --------------------------------------------------------------------------- #
LONG_OPS = {"pkg.apply", "pkg.refresh", "acme.issue", "acme.renew", "script.run",
            "security.scan", "pkg.plan", "pkg.updates", "fs.extract", "fs.archive", "fs.search"}


def start_job(app, slug: str, cred_id, op: str, args: dict, *, user, run_as: str,
              provided: dict, title: str, run_kind: str = "", run_meta: dict | None = None,
              script_id=None) -> dict:
    """Run a long operation in the background. Policy checks happen NOW (in the
    request), so a refusal is immediate; the secrets live only in the
    worker's closure for the length of the call."""
    from . import jobs
    c = server(slug)
    check_op(user, op, elevated=False)
    scope_gate(user, c, op, args or {})         # refused now, not in the worker
    cred = pick_credential(c, user, cred_id)
    check_op(user, op, elevated=(run_as or cred.run_as) == "root" and cred.can_escalate)
    if not cred.store_secret:
        _account(cred, provided)
    if (run_as or cred.run_as) == "root" and cred.escalation == "sudo":
        _sudo_password(cred, _account(cred, provided), provided)
    uid = user.id
    uname = user.username
    # plain values only: the worker runs in another thread with its own session
    host, ssh_user, cred_id = c.host, cred.ssh_user, cred.id
    run_id = None
    if run_kind:
        run = WsmRun(kind=run_kind, title=title[:300], connection_slug=slug,
                     credential_id=cred_id, by=uname, ssh_user=ssh_user,
                     script_id=script_id, meta_json=json.dumps(run_meta or {}))
        db.session.add(run)
        db.session.commit()
        run_id = run.id
    job = jobs.create_job("wsm_" + op.replace(".", "_"), title, by=uname,
                          meta={"server": slug, "op": op, "run_id": run_id})
    if run_id:
        WsmRun.query.filter_by(id=run_id).update({"job_id": job["id"]})
        db.session.commit()

    def worker(app_, job_id):
        from ..models import User
        with app_.app_context():
            u = db.session.get(User, uid)
            jobs.set_progress(job_id, 10, "Connecting to %s as %s" % (host, ssh_user))
            try:
                out = execute(slug, cred_id, op, args, user=u, run_as=run_as,
                              provided=provided, timeout=3700)
            except Exception as exc:  # noqa: BLE001
                if run_id:
                    _finish_run(run_id, ok=False, stderr=str(exc))
                raise
            res = out["result"] if isinstance(out["result"], dict) else {}
            if run_id:
                _finish_run(run_id, ok=res.get("ok", res.get("exit_code", 0) == 0),
                            stdout=res.get("stdout") or res.get("output") or "",
                            stderr=res.get("stderr") or "", exit_code=res.get("exit_code"),
                            effective=out["who"].get("user", ""), sudo=out["sudo"])
            out["run_id"] = run_id
            return out

    jobs.run_async(app, job["id"], worker)
    return {"job_id": job["id"], "run_id": run_id}


def _finish_run(run_id, *, ok, stdout="", stderr="", exit_code=None, effective="", sudo=False):
    run = db.session.get(WsmRun, run_id)
    if run is None:
        return
    run.status = "ok" if ok else "failed"
    run.stdout, run.stderr = (stdout or "")[-1024 * 1024:], (stderr or "")[-256 * 1024:]
    run.exit_code = exit_code if isinstance(exit_code, int) else None
    run.effective_user, run.sudo = (effective or "")[:64], bool(sudo)
    run.finished_at = datetime.utcnow()
    db.session.commit()


# --------------------------------------------------------------------------- #
#  schedules SATOM runs                                                        #
# --------------------------------------------------------------------------- #
SCHED_ACTION = "wsm_schedules"
SCHED_ACTION_NAME = "Web Server Manager -- scheduled scripts"


def cron_ok(expr: str) -> str:
    from .scheduler import CronError, parse_cron
    try:
        parse_cron(expr)
        return ""
    except CronError as exc:
        return str(exc)


def cron_matches(expr: str, when: datetime) -> bool:
    from .scheduler import parse_cron
    mins, hours, doms, months, dows, dom_star, dow_star = parse_cron(expr)
    if when.minute not in mins or when.hour not in hours or when.month not in months:
        return False
    dow = (when.weekday() + 1) % 7
    dom_ok, dow_ok = when.day in doms, dow in dows
    if dom_star or dow_star:
        return dom_ok and dow_ok
    return dom_ok or dow_ok


def schedule_problem(s: WsmSchedule) -> str:
    """Why this schedule cannot run unattended now ('' = it can)."""
    cred = db.session.get(WsmCredential, s.credential_id) if s.credential_id else None
    if cred is None:
        return "its credential no longer exists"
    if cred.state != "active":
        return "credential %s is %s" % (cred.name, cred.state)
    if cred.auth_type == "agent":
        return "the satom-webctl agent cannot run scripts"
    if not cred.store_secret or not has(cred, "secret"):
        return "credential %s does not keep its secret (asks at every operation)" % cred.name
    if s.run_as == "root" and cred.escalation == "sudo" and not (
            cred.sudo_password == "same" and cred.auth_type == "password"):
        return "running as root needs sudo without asking (NOPASSWD, or the stored password)"
    if s.script_id is None or db.session.get(WsmScript, s.script_id) is None:
        return "its script no longer exists"
    return ""


def park_schedules(cred: WsmCredential, why: str) -> int:
    n = 0
    for s in WsmSchedule.query.filter_by(credential_id=cred.id).all():
        s.state, s.state_detail = "pending_auth", why[:500]
        n += 1
    db.session.commit()
    if n:
        _notify_pending()
    return n


def _notify_pending() -> None:
    try:
        from ..models_notifications import Notification
        from . import notifications as notify_svc
        from .alerts import _admin_ids
        from ..branding import PRODUCTS
        adom = "linux" if "linux" in PRODUCTS else "global"
        for s in WsmSchedule.query.filter_by(state="pending_auth").all():
            if s.notified_state == "pending_auth":
                continue
            notify_svc.push_many(
                _admin_ids(), "Scheduled script %s is waiting for authentication" % s.name,
                kind=Notification.KIND_WARNING,
                body="%s on %s will not run: %s. Pick another credential in Web Server "
                     "Manager > Cron Jobs > Scheduled by SATOM." % (s.name, s.connection_slug,
                                                                   s.state_detail),
                link="/webserver/%s/cron" % s.connection_slug, product=adom)
            s.notified_state = "pending_auth"
        db.session.commit()
    except Exception:  # noqa: BLE001 -- a bell must not stop the scheduler
        _log.warning("wsm: pending-auth notification failed", exc_info=True)


class _SystemUser:
    """The scheduler's identity: what a schedule's creator was allowed to do
    when it was saved is re-checked against that user at every run."""


def run_due(now: datetime | None = None, *, dry_run: bool = False) -> dict:
    from ..models import User
    now = (now or datetime.utcnow()).replace(second=0, microsecond=0)
    out = {"due": 0, "ran": 0, "failed": 0, "pending": 0, "lines": []}
    if not module_active():
        out["lines"].append("the Web Server Manager is switched off (no ADOM has it): "
                            "no schedule runs")
        return out
    for s in WsmSchedule.query.filter_by(enabled=True).order_by(WsmSchedule.id).all():
        try:
            if not cron_matches(s.cron, now):
                continue
        except Exception:  # noqa: BLE001
            continue
        if s.last_run_at and s.last_run_at >= now:
            continue
        out["due"] += 1
        why = schedule_problem(s)
        if why:
            s.state, s.state_detail = "pending_auth", why
            out["pending"] += 1
            out["lines"].append("PENDING %s: %s" % (s.name, why))
            db.session.commit()
            continue
        if dry_run:
            out["lines"].append("would run %s" % s.name)
            continue
        owner = User.query.filter_by(username=s.created_by).first()
        script = db.session.get(WsmScript, s.script_id)
        run = WsmRun(kind="schedule", title="%s (scheduled)" % s.name,
                     connection_slug=s.connection_slug, credential_id=s.credential_id,
                     schedule_id=s.id, script_id=s.script_id, by="scheduler",
                     meta_json=json.dumps({"interpreter": script.interpreter, "cron": s.cron,
                                           "run_as": s.run_as}))
        db.session.add(run)
        s.last_run_at = now
        db.session.commit()
        try:
            if owner is None or not owner.is_active:
                raise WsmDenied("its creator %s is no longer an active user" % s.created_by)
            r = execute(s.connection_slug, s.credential_id, "script.run",
                        {"interpreter": script.interpreter, "content": script.content,
                         "args": script.args, "cwd": script.cwd or "",
                         "timeout": min(script.timeout or 300, 900)},
                        user=owner, run_as=s.run_as, timeout=960, mode="schedule")
            res = r["result"]
            ok = res.get("exit_code") == 0
            _finish_run(run.id, ok=ok, stdout=res.get("stdout", ""),
                        stderr=res.get("stderr", ""), exit_code=res.get("exit_code"),
                        effective=r["who"].get("user", ""), sudo=r["sudo"])
            s.state, s.last_exit = ("ok" if ok else "failed"), res.get("exit_code")
            s.state_detail = "" if ok else "exit code %s" % res.get("exit_code")
            out["ran" if ok else "failed"] += 1
            out["lines"].append("%s %s: exit %s" % ("OK" if ok else "FAIL", s.name,
                                                    res.get("exit_code")))
        except (WsmDenied, NeedSecret, T.WsmError) as exc:
            _finish_run(run.id, ok=False, stderr=str(exc))
            pending = isinstance(exc, NeedSecret) or getattr(exc, "code", "") in (
                "auth", "sudo_password", "sudo_denied")
            s.state = "pending_auth" if pending else "failed"
            s.state_detail = str(exc)[:500]
            out["pending" if pending else "failed"] += 1
            out["lines"].append("%s %s: %s" % ("PENDING" if pending else "FAIL", s.name, exc))
        if s.state != "pending_auth":
            s.notified_state = ""
        db.session.commit()
    if out["pending"]:
        _notify_pending()
    return out


def ensure_scheduled(by: str = "system:web-server-manager") -> bool:
    from ..models import ScheduledAction
    from . import scheduled_actions as sa
    from .scheduler import compute_next_run
    try:
        if ScheduledAction.query.filter_by(action=SCHED_ACTION).first() is not None:
            return False
        sched = {"every": 1, "unit": "minutes"}
        row = ScheduledAction(
            name=SCHED_ACTION_NAME, scope="admin", product="global", action=SCHED_ACTION,
            targets="[]", params="{}", schedule_kind="interval", schedule=json.dumps(sched),
            enabled=True, catch_up=False, created_by=by)
        row.next_run = compute_next_run("interval", sched, tz=sa._configured_tz())
        db.session.add(row)
        db.session.commit()
        return True
    except Exception:  # noqa: BLE001
        _log.warning("wsm.ensure_scheduled failed", exc_info=True)
        db.session.rollback()
        return False


def service_credentials(slug: str) -> list[WsmCredential]:
    """The shared, active credentials of the server that keep their secret --
    what an unattended read (certificate expiry, host health) may sign in with."""
    return [cred for cred in WsmCredential.query.filter_by(
        connection_slug=slug, shared=True, status="active").order_by(WsmCredential.id)
        if cred.state == "active" and cred.auth_type in ("password", "key")
        and cred.store_secret and has(cred, "secret")]


def service_credential(slug: str) -> WsmCredential | None:
    rows = service_credentials(slug)
    return rows[0] if rows else None


def read_as_service(c, op: str, args: dict | None = None, *, cred: WsmCredential | None = None,
                    by: str = "scheduler") -> dict:
    """An unattended READ (never a write, never sudo) with the server's service
    credential -- or ``cred``, which must qualify the same way (shared, active,
    password or key, secret kept); audited as ``by``."""
    if OPS.get(op, ("", True))[1]:
        raise WsmDenied("%s changes the server: not an unattended read" % op)
    if cred is not None and cred not in service_credentials(c.slug):
        raise WsmDenied("credential %s cannot sign in unattended: it must be shared, active, "
                        "a password or key, and keep its secret" % cred.name)
    cred = cred or service_credential(c.slug)
    if cred is None:
        raise WsmDenied("%s has no shared service credential that keeps its secret" % c.slug)
    account = {"user": cred.ssh_user, "auth_type": cred.auth_type,
               "secret": secret(cred, "secret"), "passphrase": secret(cred, "passphrase")}
    module = OPS[op][0]
    try:
        r = T.call(target(c), account, op, args or {}, timeout=float(c.timeout or 60),
                   by=by)
    except T.WsmError as exc:
        _audit(user=by, c=c, cred=cred, op=op, module=module, args=args, ok=False,
               error=exc.remote_error or exc.code, detail=str(exc), who=exc.who, mode="schedule")
        raise
    _audit(user=by, c=c, cred=cred, op=op, module=module, args=args, ok=True,
           who=r["who"], session_id=r["session_id"], ms=r["ms"], mode="schedule")
    return r["result"]


# --------------------------------------------------------------------------- #
#  audit queries                                                               #
# --------------------------------------------------------------------------- #
def audit_rows(*, slug: str = "", user: str = "", op: str = "", ok: str = "",
               since_days: int = 30, limit: int = 500) -> list[WsmAudit]:
    q = WsmAudit.query
    if slug:
        q = q.filter(WsmAudit.connection_slug == slug)
    if user:
        q = q.filter(db.or_(WsmAudit.app_user == user, WsmAudit.ssh_user == user,
                            WsmAudit.effective_user == user))
    if op:
        q = q.filter(WsmAudit.op.like(op.replace("%", "") + "%"))
    if ok in ("1", "0"):
        q = q.filter(WsmAudit.ok.is_(ok == "1"))
    q = q.filter(WsmAudit.at >= datetime.utcnow() - timedelta(days=max(1, since_days)))
    return q.order_by(WsmAudit.id.desc()).limit(limit).all()


_LOCK = threading.Lock()
