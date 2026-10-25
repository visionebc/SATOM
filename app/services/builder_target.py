"""The target snapshot SATOM Builder validates against (contract §2).

``snapshot(owner, product)`` is what ``GET /api/v1/builder/target`` returns
and, unchanged, the ``target`` argument of ``package_check.check()``: this
server's version, the picker values its app editor offers, the Examples
templates, the Studio objects that already exist (no row data, never a
secret -- only whether a connection HAS one), the enabled publishers that
apply to the ADOM, and the schema computed from all of that.

The same function feeds the console's import wizard, so a package is judged
against one description of this server whichever door it comes through.
"""
from __future__ import annotations

FORMAT = "satom.builder-target/1"


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


def choices() -> dict:
    from . import plugin_datasets as PD
    from . import studio_apps as SA
    out = dict(SA.choices())
    out["datasets"] = PD.keys()          # every source, the token's ADOM
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
    apps = {}
    for a in StudioApp.query.order_by(StudioApp.slug).all():
        apps[a.slug] = {"kind": a.kind or "flow", "pkg_version": a.pkg_version or "",
                        "status": a.status or "draft", "template": SA.is_template(a)}
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
            "api_versions": versions, "scripts": scripts}


def publishers(product: str | None) -> list[dict]:
    """The enabled publishers this ADOM trusts, with their public key so the
    rules pack can verify a signature exactly as this server will."""
    from . import plugin_publishers as PP
    return [{"key_id": r.key_id, "label": r.label, "public_key": r.public_key}
            for r in PP.list_publishers() if r.enabled and PP.applies_to(r, product)]


def snapshot(owner_user, product_key: str, *, scopes=None) -> dict:
    """Contract §2, for *owner_user* in ADOM *product_key*."""
    from ..version import app_version
    package_check, rules_pack = _rules()
    _zip, sha = rules_pack.build()
    target = {
        "format": FORMAT,
        "satom_version": app_version(),
        "rules_sha256": sha,
        "product": product_key or "",
        "caller": caller(owner_user, scopes),
        "choices": choices(),
        "templates": templates(),
        "existing": existing(),
        "publishers": publishers(product_key),
    }
    target["schema"] = package_check.schema(dict(target))
    return target
