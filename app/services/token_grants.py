"""Object grants on API tokens: which Processes and which Plugin Studio apps a
token may run from /api/v1 (2026-10-24).

The rule lives on the token (``ApiToken.authorize_grant``); this module knows
the objects: what a grant's FINGERPRINT is, which objects a token may be
granted, and what happens to grants when an object changes or goes away.

THE FINGERPRINT IS WHAT RUNS, NOT WHEN IT WAS SAVED
--------------------------------------------------
A grant approves one version. ``updated_at`` would pause a grant every time a
node is dragged on the canvas, and an app's version number moves on a
republish that changes nothing. So the fingerprint is a hash of what the
engine executes: a Process's nodes (key, kind, params) and edges; an app's
PUBLISHED fields, diagram and actions. Positions and step labels are left out
-- they change nothing a walk does. Anything else that changes, pauses the
grant until an administrator re-approves it.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime

from ..extensions import db
from ..models_api_token import GRANT_KINDS, GRANT_LABEL, ApiToken

#: Node keys that place a step on the canvas or name it, and do nothing else.
_COSMETIC = frozenset({"x", "y", "pos_x", "pos_y", "position", "w", "h", "label"})


def _hash(body) -> str:
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _canon_graph(graph) -> dict:
    graph = graph if isinstance(graph, dict) else {}
    nodes = [{k: v for k, v in (n or {}).items() if k not in _COSMETIC}
             for n in graph.get("nodes") or [] if isinstance(n, dict)]
    edges = [e for e in graph.get("edges") or [] if isinstance(e, dict)]
    return {"nodes": sorted(nodes, key=lambda n: str(n.get("key"))),
            "edges": sorted(edges, key=lambda e: json.dumps(e, sort_keys=True, default=str))}


# --------------------------------------------------------------------------- #
#  the objects                                                                 #
# --------------------------------------------------------------------------- #
def _get(kind: str, obj_id):
    from ..models_studio import StudioApp
    return db.session.get(StudioApp, obj_id)


def key_of(kind: str, obj) -> str:
    return obj.slug


def name_of(kind: str, obj) -> str:
    return obj.name or key_of(kind, obj)


def fingerprint(kind: str, obj) -> str:
    """The version a grant approves. '' = nothing runnable to approve (an app
    with no published version, a script app)."""
    if getattr(obj, "kind", "flow") != "flow":
        return ""
    pub = obj.published or {}
    if not pub:
        return ""
    return _hash({"fields": pub.get("fields") or [], "graph": _canon_graph(pub.get("graph")),
                  "actions": pub.get("actions") or []})


def grantable(kind: str, obj, tok: ApiToken) -> bool:
    """May *tok* be granted *obj*? The token's ADOM must see it and, for an
    app, the token's OWNER must be allowed to use it: a token never exceeds
    the human behind it."""
    from . import studio_apps as SA
    return (getattr(obj, "kind", "flow") == "flow" and bool(fingerprint(kind, obj))
            and SA.shown_in(obj, tok.product) and SA.can_use(tok.owner, obj))


def candidates(kind: str) -> list:
    """Every object of *kind* the token form offers (the route re-checks each
    against the token's ADOM and owner on save)."""
    from ..models_studio import StudioApp
    return [a for a in StudioApp.query.order_by(StudioApp.name.asc()).all()
            if getattr(a, "kind", "flow") == "flow" and fingerprint("app", a)]


def authorize(tok: ApiToken, kind: str, obj) -> tuple[bool, str, str]:
    return tok.authorize_grant(kind, obj.id, key_of(kind, obj), fingerprint(kind, obj))


# --------------------------------------------------------------------------- #
#  the token form                                                              #
# --------------------------------------------------------------------------- #
def select(tok: ApiToken, kind: str, wanted_ids, by: str) -> list[str]:
    """Make *wanted_ids* the token's grants of *kind*. A grant already held is
    kept as it was approved -- ticking a paused grant again does not
    re-approve it (that is ``reapprove``, one deliberate click). Returns the
    names refused because the token's ADOM or owner cannot reach them."""
    held = {g["id"]: g for g in tok.grants(kind)}
    rows, refused = [], []
    for raw in wanted_ids or []:
        try:
            oid = int(raw)
        except (TypeError, ValueError):
            continue
        obj = _get(kind, oid)
        if obj is None:
            continue
        if not grantable(kind, obj, tok):
            refused.append(name_of(kind, obj))
            continue
        old = held.get(oid)
        if old is not None and old["key"] == key_of(kind, obj):
            rows.append(old)
        else:
            rows.append({"id": oid, "key": key_of(kind, obj), "fp": fingerprint(kind, obj),
                         "by": by or "", "at": datetime.utcnow().isoformat(timespec="seconds")})
    tok.set_grants(kind, rows)
    return refused


def reapprove(tok: ApiToken, kind: str, obj_id: int, by: str) -> dict | None:
    """Approve the CURRENT version of a granted object. ``None`` when the
    token holds no such grant or the object is gone / no longer grantable."""
    rows = tok.grants(kind)
    for g in rows:
        if g["id"] != obj_id:
            continue
        obj = _get(kind, obj_id)
        if obj is None or key_of(kind, obj) != g["key"] or not grantable(kind, obj, tok):
            return None
        old = g["fp"]
        g.update(fp=fingerprint(kind, obj), by=by or "",
                 at=datetime.utcnow().isoformat(timespec="seconds"))
        tok.set_grants(kind, rows)
        return {"key": g["key"], "from": old, "to": g["fp"]}
    return None


def status(tok: ApiToken) -> list[dict]:
    """Every grant of the token with its state, for the page: ``ok`` (runs),
    ``paused`` (the object changed since it was approved) or ``gone``."""
    out = []
    for kind in GRANT_KINDS:
        for g in tok.grants(kind):
            obj = _get(kind, g["id"])
            if obj is None or key_of(kind, obj) != g["key"]:
                state, name = "gone", g["key"]
            else:
                name = name_of(kind, obj)
                state = "ok" if fingerprint(kind, obj) == g["fp"] else "paused"
            out.append({"kind": kind, "label": GRANT_LABEL[kind], "id": g["id"],
                        "key": g["key"], "name": name, "state": state,
                        "by": g["by"], "at": g["at"]})
    return out


# --------------------------------------------------------------------------- #
#  an object goes away                                                         #
# --------------------------------------------------------------------------- #
def forget(kind: str, obj_id: int, key: str) -> list[str]:
    """Remove every grant on a deleted object, from every token, and audit
    each removal. Called by the delete paths BEFORE they commit, so the
    removal and the delete land together. Returns the tokens' public ids."""
    from .audit import log_action
    changed = []
    for tok in ApiToken.query.all():
        rows = tok.grants(kind)
        keep = [g for g in rows if not (g["id"] == obj_id and g["key"] == key)]
        if len(keep) != len(rows):
            tok.set_grants(kind, keep)
            changed.append(tok)
    if changed:
        db.session.flush()
    for tok in changed:
        log_action("api_token.grant_removed", target=f"token:{tok.public_id}",
                   extra={"kind": kind, "key": key, "reason": "deleted",
                          "token_name": tok.name})
    return [t.public_id for t in changed]
