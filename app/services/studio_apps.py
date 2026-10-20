"""Python Studio > Apps -- a form, a diagram and an output, published into
Operations > Plugins for the ADOMs and the people the administrator picks.
"""
from __future__ import annotations

from ..models_studio import StudioApp

#: Node / action parameters that name another Studio object.
REF_PARAMS = {"store": ("store",), "connection": ("connection",), "script": ("script",),
              "app": ("app",)}


def _refs(graph: dict, actions: list, kind: str) -> set:
    names = REF_PARAMS.get(kind, ())
    out = set()
    for n in (graph or {}).get("nodes") or []:
        p = n.get("params") or {}
        for k in names:
            if p.get(k):
                out.add(str(p[k]))
    for a in actions or []:
        p = a.get("params") or {}
        for k in names:
            if p.get(k):
                out.add(str(p[k]))
    return out


def used_by(kind: str, slug: str) -> list[str]:
    """Apps whose draft or published version names *slug* (a data store,
    connection, script or app). Deleting it would break them."""
    hits = []
    for a in StudioApp.query.order_by(StudioApp.slug).all():
        pub = a.published
        if slug in _refs(a.graph, a.actions, kind) \
                or slug in _refs(pub.get("graph") or {}, pub.get("actions") or [], kind):
            hits.append(a.slug)
    return hits
