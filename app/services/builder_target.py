"""The target snapshot SATOM Builder validates against (contract §2).

``snapshot(owner, product)`` is what ``GET /api/v1/builder/target`` returns
and, unchanged, the ``target`` argument of ``package_check.check()``: this
server's version, the picker values its app editor offers, the Examples
templates, the Studio objects that already exist (no row data, never a
secret -- only whether a connection HAS one; directory connections by id and
kind only, contract section 20), the enabled publishers that
apply to the ADOM, and the schema computed from all of that.

The same function feeds the console's import wizard, so a package is judged
against one description of this server whichever door it comes through.
"""
from __future__ import annotations

FORMAT = "satom.builder-target/1"
GLOBAL = "global"


def _rules():
    # builder-core owns these modules; imported lazily so a node without them
    # fails at the call, not at import time of every page.
    from . import package_check, rules_pack
    return package_check, rules_pack


def caller(owner, scopes=None) -> dict:
    from . import studio_apps as SA
    can_import = bool(owner is not None and owner.can("studio.plugin_studio"))
    return {"username": getattr(owner, "username", "") or "",
            "is_super_admin": can_import,
            "scopes": list(scopes or []),
            "can_author": SA.is_author(owner),
            "can_import": can_import}


def adoms_for(owner) -> list[str]:
    """The product ADOMs *owner* may enter, sorted: every one for an owner
    whose profile names none."""
    from . import product_scope as PSc
    allowed = PSc.adoms_of(owner)
    return sorted(k for k in PSc.concrete_products() if allowed is None or k in allowed)


def offered(owner, product: str | None) -> list[dict]:
    """The datasets a plugin installed in ADOM *product* may read, for
    *owner*. Global ('' or 'global') is every ADOM the owner may enter, never
    the products a confined owner may not (their Global console is the union
    of their ADOMs)."""
    from . import plugin_datasets as PD
    p = "" if product in (None, "", GLOBAL) else product
    out = PD.catalog(p)
    if p:
        return out
    mine = set(adoms_for(owner))
    return [d for d in out if not d.get("product") or d["product"] in mine]


def elsewhere(owner, product: str | None) -> dict:
    """Contract §17: the datasets that exist in the owner's OTHER ADOMs but
    not in *product*, as ``{"datasets": {key: adom}}``. Names only: what lets
    a check say "it lives in ADOM X" instead of "this server has no such
    dataset". Empty in Global, which already offers all of them."""
    from . import plugin_datasets as PD
    p = "" if product in (None, "", GLOBAL) else product
    out: dict[str, str] = {}
    if not p:
        return {"datasets": out}
    here = set(PD.keys(p))
    for adom in adoms_for(owner):
        if adom == p:
            continue
        for k in PD.keys(adom):
            if k not in here:
                out.setdefault(k, adom)
    return {"datasets": out}


def reach(owner, token_adom: str | None, product: str | None) -> dict:
    """Contract §17: what this connection reaches. A Global token chooses the
    ADOM per call (``?adom=``) among Global and the owner's ADOMs; a token
    bound to an ADOM stays in it."""
    tok = token_adom or GLOBAL
    can_choose = tok == GLOBAL
    return {"token_adom": tok, "adom": product or GLOBAL, "can_choose": can_choose,
            "adoms": ([GLOBAL] + adoms_for(owner)) if can_choose else [tok]}


def choices(owner=None, product: str | None = None) -> dict:
    from flask import g, has_request_context
    from . import studio_apps as SA
    out = dict(SA.choices())
    if product is None:
        product = (getattr(g, "product", "") or "") if has_request_context() else ""
    out["datasets"] = [d["key"] for d in offered(owner, product)]   # the call's ADOM
    return out


def templates() -> dict:
    from . import studio_examples as EX
    out = {"apps": [], "stores": [], "connections": [], "scripts": []}
    for kind, slug in sorted(EX.TEMPLATE_OBJECTS):
        key = {"app": "apps", "store": "stores", "connection": "connections",
               "script": "scripts"}.get(kind)
        if key:
            out[key].append(slug)
    return out


def existing() -> dict:
    from ..models_studio import StudioApp, StudioConnection, StudioDataStore
    from . import script_library as SL
    from . import studio_apis as SAPI
    from . import studio_apps as SA
    from . import studio_connections as SC
    from . import app_signin as AS
    apps = {}
    for a in StudioApp.query.order_by(StudioApp.slug).all():
        apps[a.slug] = {"kind": a.kind or "flow", "pkg_version": a.pkg_version or "",
                        "status": a.status or "draft", "template": SA.is_template(a),
                        "signin": bool(AS.policy_of(a)["rules"])}
    stores = {}
    for s in StudioDataStore.query.order_by(StudioDataStore.slug).all():
        stores[s.slug] = {"columns": [{"name": c.get("name"), "type": c.get("type")}
                                      for c in s.columns if isinstance(c, dict)]}
    conns = {}
    for c in StudioConnection.query.order_by(StudioConnection.slug).all():
        conns[c.slug] = {"kind": c.kind, "base_url": c.base_url or "",
                         "auth": c.auth or "none", "has_secret": bool(SC.has_secret(c.slug))}
    versions = []
    for api in SAPI.list_apis():
        for v in SAPI.versions(api):
            versions.append([api.slug, v.version, v.status])
    scripts = {}
    try:
        for s in SL.list_scripts():
            scripts[s["slug"]] = {"published": bool(s.get("published"))}
    except Exception:  # noqa: BLE001 -- a broken library dir lists no script
        pass
    return {"apps": apps, "stores": stores, "connections": conns,
            "api_versions": versions, "scripts": scripts,
            **sign_in_directories()}


def sign_in_directories() -> dict:
    """Contract section 20: the directory connections an app's sign-in may name
    (id -> kind) and the Apps only profiles, by name. Never a server, a bind
    account or a secret."""
    from ..models import Profile
    from . import directory_connections as DC
    return {"directory_connections": {c.slug: {"kind": c.kind}
                                      for c in DC.all_connections()},
            "apps_only_profiles": sorted(p.name for p in Profile.query.all()
                                         if p.is_apps_only)}


def publishers(product: str | None) -> list[dict]:
    """The enabled publishers this ADOM trusts, with their public key so the
    rules pack can verify a signature exactly as this server will."""
    from . import plugin_publishers as PP
    return [{"key_id": r.key_id, "label": r.label, "public_key": r.public_key}
            for r in PP.list_publishers() if r.enabled and PP.applies_to(r, product)]


def snapshot(owner_user, product_key: str, *, scopes=None, token_adom=None) -> dict:
    """Contract §2, for *owner_user* in ADOM *product_key*. ``elsewhere``
    (§17) names the datasets of the owner's other ADOMs; ``reach`` is there
    when the call came with a token (*token_adom*)."""
    from ..version import app_version
    package_check, rules_pack = _rules()
    _zip, sha = rules_pack.build()
    target = {
        "format": FORMAT,
        "satom_version": app_version(),
        "rules_sha256": sha,
        "product": product_key or "",
        "caller": caller(owner_user, scopes),
        "choices": choices(owner_user, product_key or ""),
        "templates": templates(),
        "existing": existing(),
        "publishers": publishers(product_key),
        "elsewhere": elsewhere(owner_user, product_key),
    }
    if token_adom is not None:
        target["reach"] = reach(owner_user, token_adom, product_key)
    target["schema"] = package_check.schema(dict(target))
    return target
