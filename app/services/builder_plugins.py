"""What this server already has, for SATOM Builder to open (contract ``satom-api`` §21).

The Builder could only adopt a ``.satomplugin`` an author uploaded by hand,
so the plugins and apps that live here -- the ones SATOM itself ships as
plugins (DNS & LB Lookup, spo-fortiweb...) and the ones built in Plugin Studio
-- never showed up there. :func:`listing` says what there is and whether the
Builder can open it; :func:`package` exports one exactly as the console's
*Export* buttons do (unsigned ``satom.plugin/1``, no secret by construction).

What the Builder cannot open is listed anyway, with the reason, so a missing
entry is never a mystery:

* a ``code`` plugin -- the Builder builds views, widgets and apps only;
* a script app -- its code is a Script Library script, not a diagram;
* a Report Studio view or widget for an owner who is not a super-admin --
  the console's own export needs ``studio.plugin_studio``.

Report Studio plugins follow the call's ADOM like the Report Studio list
(``scope_query``); Plugin Studio apps are not ADOM-bound and are all listed,
as Plugin Studio lists them to an author.
"""
from __future__ import annotations

from .product_scope import scope_query

FORMAT = "satom.builder-plugins/1"
#: what the Builder edits (``code`` is refused there, contract §1)
OPENABLE_PLUGIN_KINDS = ("view", "widget")
SUPER_ADMIN = "studio.plugin_studio"

WHY_CODE = "A code plugin: the Builder builds views, widgets and apps only."
WHY_SCRIPT = ("A script app: its code is a Script Library script, not a diagram; edit it "
              "in SATOM's Script Library.")
WHY_ADMIN = ("Opening a Report Studio plugin needs a super-admin owner "
             "(studio.plugin_studio), as its export in the console does.")


class NotOpenable(Exception):
    """The item exists but the Builder cannot open it (``why`` is the reason)."""


def _iso(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt is not None else ""


def _plugins():
    from ..models import Plugin
    return scope_query(Plugin.query, Plugin.product).order_by(Plugin.slug).all()


def listing(owner) -> dict:
    """``satom.builder-plugins/1``: every plugin and app, with ``openable``."""
    from ..models_studio import StudioApp
    from ..version import app_version
    from . import studio_examples as SE
    admin = bool(owner is not None and owner.can(SUPER_ADMIN))
    items = []
    for a in StudioApp.query.order_by(StudioApp.slug).all():
        kind = a.kind or "flow"
        it = {"kind": "app", "slug": a.slug, "name": a.name, "icon": a.icon or "",
              "description": (a.description or "")[:500],
              "version": a.pkg_version or "", "status": a.status or "",
              "app_kind": kind, "template": SE.is_template(kind, a.slug),
              "signed": bool(a.pkg_signer), "updated_at": _iso(a.updated_at),
              "adom": "", "openable": kind == "flow"}
        if kind != "flow":
            it["why"] = WHY_SCRIPT
        items.append(it)
    for p in _plugins():
        it = {"kind": p.kind, "slug": p.slug, "name": p.name, "icon": p.icon or "",
              "description": "", "version": p.pkg_version or "", "status": p.status or "",
              "template": False, "signed": bool(p.pkg_signer),
              "updated_at": _iso(p.updated_at), "adom": p.product or "", "openable": False}
        if p.kind not in OPENABLE_PLUGIN_KINDS:
            it["why"] = WHY_CODE
        elif not admin:
            it["why"] = WHY_ADMIN
        else:
            it["openable"] = True
        items.append(it)
    return {"format": FORMAT, "satom_version": app_version(), "items": items,
            "counts": {"total": len(items),
                       "openable": sum(1 for i in items if i["openable"])}}


def package(owner, kind: str, slug: str) -> tuple[str, bytes] | None:
    """``(filename, bytes)`` of one item's unsigned package; ``None`` when
    there is no such item here; :class:`NotOpenable` when it exists but the
    Builder cannot open it."""
    from ..version import app_version
    if kind == "app":
        from . import studio_app_package as SAP
        from . import studio_apps as SA
        a = SA.get(slug)
        if a is None:
            return None
        if (a.kind or "flow") != "flow":
            raise NotOpenable(WHY_SCRIPT)
        return SAP.export_app(a, app_version())
    if kind in ("view", "widget", "code"):
        from . import plugin_package as P
        from ..models import Plugin
        p = scope_query(Plugin.query, Plugin.product).filter_by(slug=slug).first()
        if p is None or p.kind != kind:
            return None
        if p.kind not in OPENABLE_PLUGIN_KINDS:
            raise NotOpenable(WHY_CODE)
        if owner is None or not owner.can(SUPER_ADMIN):
            raise NotOpenable(WHY_ADMIN)
        return P.export_plugin(p, app_version())
    return None
