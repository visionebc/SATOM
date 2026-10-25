"""Plugin package import -- ONE code path for the console and the API.

Plugin Studio's import wizard (``views.plugins``) and
``POST /api/v1/builder/import`` (``api_v1.builder``) both end in
:func:`import_package`. What it does, in order, before anything is written:

1. **Read** the package (``plugin_package.read_package``), trusting the Vision
   EBC keys plus the enabled publishers of this ADOM. A signature by any other
   key -- a disabled publisher included -- refuses the package.
2. **Pick the policy** (contract §6, :func:`select_policy`): ``import`` for a
   Vision EBC signature; ``builder`` for a publisher's signature and for an
   unsigned package that arrives through the API; an unsigned upload in the
   console keeps ``import``.
3. **Own rules**, whatever the rules module says: ``kind: code`` installs only
   when Vision EBC signed it -- a publisher can never make code acceptable --
   and ``min_satom`` above this server's version is refused.
4. **The rules module** (``package_check.install_guard``) with that policy,
   against this server's target snapshot (``builder_target``). Any problem
   refuses the import.
5. **Install** (``studio_app_package.install`` for apps, ``plugin_code`` for
   code, a Plugin Studio row for views and widgets), then store the secrets
   given for the connections the import CREATED through
   ``studio_connections.set_secret`` (vault or Fernet). A secret for a
   connection that already existed is ignored and reported in ``kept``; a
   secret is never written anywhere else and never logged.

The console's two steps keep the uploaded bytes between upload and confirm
under the data directory (:func:`stage`), owner-bound and gone after one hour
-- never in the session cookie.
"""
from __future__ import annotations

import json
import os
import re
import secrets as _secrets
import time
from pathlib import Path

from . import plugin_package as P

POLICIES = ("builder", "import")
VIA = ("ui", "api")
#: The longest secret value accepted for one connection.
MAX_SECRET = 8 * 1024
#: How long an uploaded package waits for its confirmation.
STAGE_TTL = 3600
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,64}$")


class ImportRefused(Exception):
    """The import was refused. ``problems`` is ``[{"where", "message"}]``."""

    def __init__(self, message: str, problems=None):
        super().__init__(message)
        self.problems = norm_problems(problems) or [{"where": "package", "message": message}]


def norm_problems(items) -> list[dict]:
    out = []
    for p in items or []:
        if isinstance(p, dict):
            out.append({"where": str(p.get("where") or "package"),
                        "message": str(p.get("message") or "")})
        else:
            out.append({"where": "package", "message": str(p)})
    return out


def select_policy(signed_by: str, via: str) -> str:
    """Contract §6. *signed_by* is ``plugin_package.signed_by(signer)``."""
    if signed_by == "vision-ebc":
        return "import"
    if signed_by == "publisher":
        return "builder"
    return "builder" if via == "api" else "import"


def _checker():
    from . import package_check
    return package_check


def read(data: bytes, product: str | None) -> P.Package:
    try:
        return P.read_package(data, keys=P.trusted_keys_with_publishers(product))
    except P.PackageError as exc:
        raise ImportRefused(str(exc)) from None


def own_problems(pk: P.Package, signed_by: str) -> list[dict]:
    """The rules this module enforces itself, for every policy."""
    from ..version import app_version
    out = []
    if pk.kind == "code" and signed_by != "vision-ebc":
        out.append({"where": "manifest", "message": (
            "a code plugin is installed only when Vision EBC signed it; a publisher's "
            "signature never makes code acceptable" if signed_by == "publisher" else
            "a code plugin must be signed by a key this server trusts; unsigned code is "
            "never installed")})
    need = pk.manifest.get("min_satom")
    if need and P.version_tuple(need) > P.version_tuple(app_version()):
        out.append({"where": "manifest", "message": (
            "%s %s needs SATOM %s or newer (this server runs %s)"
            % (pk.slug, pk.version, need, app_version()))})
    return out


def app_body(pk: P.Package) -> dict:
    if pk.kind != "app":
        return {}
    try:
        body = json.loads(pk.files[P.APP_FILE].decode("utf-8"))
    except (KeyError, UnicodeDecodeError, ValueError):
        return {}
    return body if isinstance(body, dict) else {}


def _needs_secret(c: dict) -> bool:
    # studio_connections.needs_secret, on the package's description
    return c.get("kind") == "postgres" or (c.get("auth") or "none") != "none"


def creating_connections(pk: P.Package) -> list[dict]:
    """The connections an app package would CREATE here (they do not exist
    yet), each with whether it needs a secret."""
    from . import studio_connections as SC
    out = []
    for c in app_body(pk).get("connections") or []:
        if not isinstance(c, dict):
            continue
        slug = str(c.get("slug") or "")
        if not slug or SC.get(slug) is not None:
            continue
        out.append({"slug": slug, "name": str(c.get("name") or slug),
                    "kind": str(c.get("kind") or "http"), "auth": str(c.get("auth") or "none"),
                    "needs_secret": _needs_secret(c)})
    return out


def inspect(data: bytes, *, user, product: str, via: str = "ui") -> dict:
    """What the wizard's preview shows: the check result with the policy this
    import would use, who signed, and the secrets it asks for. Writes nothing."""
    from . import builder_target as BT
    from . import plugin_publishers as PP
    pk = read(data, product)
    signed = P.signed_by(pk.signer)
    policy = select_policy(signed, via)
    res = _checker().check(data, BT.snapshot(user, product), policy) or {}
    problems = own_problems(pk, signed) + norm_problems(res.get("problems"))
    summary = dict(res.get("summary") or {})
    return {"kind": pk.kind, "slug": pk.slug, "version": pk.version,
            "name": pk.manifest.get("name") or pk.slug,
            "signer": pk.signer or "", "signed_by": signed,
            "signer_label": PP.label_of(pk.signer) if pk.signer else "",
            "policy": policy, "ok": not problems, "problems": problems,
            "warnings": norm_problems(res.get("warnings")),
            "creates": list(summary.get("creates") or []),
            "keeps": list(summary.get("keeps") or []),
            "lands_in": summary.get("lands_in") or ("testing" if pk.signer and pk.kind in (
                "view", "widget") else "draft"),
            "connections": creating_connections(pk)}


def clean_secrets(raw) -> dict[str, str]:
    """``{slug: value}`` of the usable entries: string values, not empty,
    at most :data:`MAX_SECRET` characters. Anything else is dropped."""
    if not isinstance(raw, dict):
        return {}
    out = {}
    for k, v in raw.items():
        if isinstance(k, str) and isinstance(v, str) and v and len(v) <= MAX_SECRET:
            out[k] = v
    return out


# --------------------------------------------------------------------------- #
#  install                                                                     #
# --------------------------------------------------------------------------- #
def _install_view(pk: P.Package, by: str, allow_downgrade: bool) -> dict:
    from ..extensions import db
    from ..models import Plugin
    from . import plugin_sandbox as sandbox
    from .product_scope import scope_query, stamp
    existing = Plugin.query.filter_by(slug=pk.slug).first()
    if existing is not None and (scope_query(Plugin.query, Plugin.product)
                                 .filter_by(id=existing.id).first() is None):
        raise ImportRefused("the slug %s belongs to a plugin of another ADOM" % pk.slug)
    if (existing is not None and existing.pkg_version and not allow_downgrade
            and P.version_tuple(pk.version) < P.version_tuple(existing.pkg_version)):
        raise ImportRefused("%s %s is installed and %s is older (tick “Allow downgrade”)"
                            % (pk.slug, existing.pkg_version, pk.version))
    wanted = [str(k) for k in pk.manifest.get("datasets") or []]
    ds = [k for k in wanted if k in sandbox.DATASETS]
    dropped = [k for k in wanted if k not in sandbox.DATASETS]
    if existing is None:
        from .product_scope import ProductScopeUnresolved
        try:
            product = stamp()
        except ProductScopeUnresolved as exc:
            raise ImportRefused(str(exc)) from None
        plugin = Plugin(created_by=by, product=product, slug=pk.slug,
                        status="testing" if pk.signer else "draft")
        db.session.add(plugin)
    else:
        plugin = existing
    plugin.name = pk.manifest["name"].strip()[:200]
    plugin.kind = pk.kind
    plugin.icon = pk.manifest["icon"]
    plugin.jinja = pk.text("body.jinja")
    plugin.css = pk.text("style.css")
    plugin.js = pk.text("script.js")
    plugin.data_sources = json.dumps(ds)
    plugin.params = json.dumps(sandbox.clean_param_defs(pk.manifest.get("params") or []))
    plugin.pkg_version = pk.version
    plugin.pkg_signer = pk.signer or ""
    todo, warnings = [], []
    if plugin.status == "published":
        # The publish gate holds for an update too: a body that no longer
        # renders goes back to testing instead of breaking Custom Views.
        data = sandbox.load_datasets(plugin.datasets)
        _html, err = sandbox.safe_render(plugin.jinja, data,
                                         sandbox.resolve_params(plugin.param_defs, {}))
        if err:
            plugin.status = "testing"
            warnings.append("it no longer renders cleanly (%s), so it is back in testing" % err)
    db.session.commit()
    if dropped:
        warnings.append("datasets this server does not have were dropped: " + ", ".join(dropped))
    if plugin.status != "published":
        todo.append("preview it and move it through testing to published (Report Studio)")
    return {"plugin": plugin, "updated": existing is not None,
            "created": [] if existing is not None else ["%s %s" % (pk.kind, pk.slug)],
            "kept": ["%s %s: updated in place, status %s" % (pk.kind, pk.slug, plugin.status)]
            if existing is not None else [],
            "todo": todo, "warnings": warnings}


def import_package(data: bytes, *, user, product: str, via: str = "ui",
                   allow_downgrade: bool = False, secrets=None, audit=None) -> dict:
    """Check and install a package. Raises :class:`ImportRefused`.

    *via* is ``ui`` or ``api`` (it decides the policy of an unsigned
    package). *secrets* maps connection slugs to secrets for the connections
    this import creates. *audit* is merged into every audit line (the API's
    token attribution)."""
    from . import builder_target as BT
    from . import plugin_publishers as PP
    from .audit import log_action
    if via not in VIA:
        raise ValueError("via is ui or api")
    by = getattr(user, "username", "") or ""
    pk = read(data, product)
    signed = P.signed_by(pk.signer)
    policy = select_policy(signed, via)
    mine = own_problems(pk, signed)
    if mine:
        raise ImportRefused(mine[0]["message"], mine)
    target = BT.snapshot(user, product)
    found = norm_problems(_checker().install_guard(pk, target, policy))
    if found:
        raise ImportRefused("the package breaks %d rule(s) of the %s policy"
                            % (len(found), policy), found)
    wanted = clean_secrets(secrets)
    creating = {c["slug"] for c in creating_connections(pk)}
    extra = {"version": pk.version, "signer": pk.signer, "signed_by": signed,
             "policy": policy, "via": via}
    extra.update(audit or {})
    out = {"ok": True, "kind": pk.kind, "slug": pk.slug, "version": pk.version,
           "name": pk.manifest.get("name") or pk.slug, "signer": pk.signer or "",
           "signed_by": signed, "signer_label": PP.label_of(pk.signer),
           "policy": policy, "created": [], "kept": [], "todo": [], "problems": [],
           "warnings": []}

    if pk.kind == "app":
        from . import studio_app_package as SAP
        try:
            rep = SAP.install(pk, by, allow_downgrade=allow_downgrade)
        except P.PackageError as exc:
            raise ImportRefused(str(exc)) from None
        a = rep["app"]
        out.update(slug=a.slug, lands_in="draft", app_slug=a.slug,
                   created=list(rep["created"]), kept=list(rep["kept"]),
                   todo=list(rep["todo"]), problems=norm_problems(rep.get("problems")))
        stored = _store_secrets(wanted, creating, out)
        out["todo"] = [t for t in out["todo"] if not any(
            t.startswith("set the secret of connection %s " % s) for s in stored)]
        log_action("studio.app.import", target=a.slug,
                   extra=dict(extra, created=out["created"], kept=out["kept"],
                              secrets_set=stored))
        return out

    if wanted:
        out["kept"].append("secrets ignored: a %s package creates no connection" % pk.kind)

    if pk.kind == "code":
        from . import plugin_code
        try:
            plugin_code.install(pk, by, allow_downgrade=allow_downgrade)
        except P.PackageError as exc:
            raise ImportRefused(str(exc)) from None
        log_action("plugin.code.install", target=pk.slug, extra=extra)
        out.update(lands_in="restart", created=["code plugin %s" % pk.slug],
                   todo=["it loads at the next `satom execute restart-all`"])
        return out

    rep = _install_view(pk, by, allow_downgrade)
    plugin = rep["plugin"]
    log_action("plugin.import", target=plugin.slug,
               extra=dict(extra, id=plugin.id, updated=rep["updated"]))
    out.update(lands_in=plugin.status, plugin_id=plugin.id, created=rep["created"],
               kept=out["kept"] + rep["kept"], todo=rep["todo"], warnings=rep["warnings"],
               updated=rep["updated"])
    return out


def _store_secrets(wanted: dict, creating: set, out: dict) -> list[str]:
    """Store the secrets of the connections this import created. Returns the
    slugs stored; the rest is reported in ``kept`` / ``todo``."""
    from . import studio_connections as SC
    stored = []
    for slug in sorted(wanted):
        if slug not in creating:
            out["kept"].append("secret for connection %s ignored: %s" % (
                slug, "the connection already existed here, its secret is this server's"
                if SC.get(slug) is not None else "the package has no such connection"))
            continue
        try:
            SC.set_secret(slug, wanted[slug])
        except SC.ConnectionError_ as exc:
            out["todo"].append("set the secret of connection %s: storing it failed (%s)"
                               % (slug, exc))
            continue
        stored.append(slug)
        out["created"].append("secret of connection %s" % slug)
    return stored


# --------------------------------------------------------------------------- #
#  the console's two steps: the upload waits here for its confirmation         #
# --------------------------------------------------------------------------- #
def stage_dir() -> Path:
    env = os.environ.get("SATOM_IMPORT_STAGING_DIR")
    if env:
        return Path(env)
    from .api_pack import data_root
    return data_root() / "plugin-import"


def sweep(now: float | None = None) -> int:
    """Delete staged uploads older than :data:`STAGE_TTL`."""
    d = stage_dir()
    if not d.is_dir():
        return 0
    now = time.time() if now is None else now
    n = 0
    for f in d.iterdir():
        try:
            if f.is_file() and now - f.stat().st_mtime > STAGE_TTL:
                f.unlink()
                n += 1
        except OSError:
            continue
    return n


def stage(data: bytes, *, owner_id: int, product: str, filename: str = "",
          allow_downgrade: bool = False) -> str:
    """Keep *data* until the owner confirms it. Returns the token."""
    sweep()
    d = stage_dir()
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    token = _secrets.token_urlsafe(32)
    meta = {"owner": int(owner_id), "product": product or "", "at": time.time(),
            "filename": str(filename or "")[:200], "allow_downgrade": bool(allow_downgrade)}
    for name, blob in ((token + ".pkg", data),
                       (token + ".json", json.dumps(meta).encode("utf-8"))):
        fd = os.open(str(d / name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
    return token


def load(token: str, owner_id: int) -> tuple[bytes, dict] | None:
    """``(data, meta)`` of a staged upload of *owner_id*, or ``None`` when it
    is unknown, expired or someone else's."""
    if not _TOKEN_RE.match(str(token or "")):
        return None
    d = stage_dir()
    try:
        meta = json.loads((d / (token + ".json")).read_text("utf-8"))
        if int(meta.get("owner")) != int(owner_id):
            return None
        if time.time() - float(meta.get("at") or 0) > STAGE_TTL:
            discard(token)
            return None
        return (d / (token + ".pkg")).read_bytes(), meta
    except (OSError, ValueError, TypeError):
        return None


def discard(token: str) -> None:
    if not _TOKEN_RE.match(str(token or "")):
        return
    d = stage_dir()
    for suffix in (".pkg", ".json"):
        try:
            (d / (token + suffix)).unlink()
        except OSError:
            pass
