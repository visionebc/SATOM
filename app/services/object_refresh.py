"""Targeted rediscovery: after a write lands, re-read ONLY what it touched.

The pages draw from the DB-first cache; the box is swept on an explicit ⟳ or a
rediscovery. Every config write SATOM makes to a FortiWeb goes through
``FortiWebOps._apply``, but only a few routes refreshed the cache afterwards
(the policy editor, a sub-table row save, a new policy). Everything else —
enable/disable, delete, clone, bulk, scheduled actions, exception injection —
landed on the device while every list kept drawing the pre-write copy until the
next full sweep (measured 2026-10-12 on fortiweb17: two policies the device had
enabled were still drawn disabled).

One rule, at the one choke point: an OK write → one GET of the object (or the
sub-table) it touched → that object's cache rows, in every layer, are refreshed,
inserted or removed. Nothing else is read, so the cost is one request per write,
and only when the cache actually holds something to keep current.

Never raises into the write path: a failed re-read leaves the row as it was and
reports why; the next ⟳ fixes it.
"""
from __future__ import annotations

import logging
from urllib.parse import parse_qs

from . import write_through as wt

log = logging.getLogger(__name__)


def _split(path: str) -> tuple[str, dict]:
    """``("api/v2.0/cmdb/x/y", {"mkey": "a", "sub_mkey": "1"})`` from a request path."""
    base, _, query = (path or "").partition("?")
    q = {k: v[0] for k, v in parse_qs(query, keep_blank_values=True).items() if v}
    return base, q


def target_of(base: str, version: str = "") -> tuple[str, str | None, str | None]:
    """What a write to ``base`` touches, by the registry for ``version``.

    ``("object", logical, None)`` for a top-level collection,
    ``("subtable", parent_logical, subtable)`` for a by-parent sub-table
    (``server-pool/pserver-list`` → ``server_pool`` / ``pserver-list``: the deep
    store names a child by the field it hangs from, which is the last URN
    segment), ``("", None, None)`` when the registry does not know it.
    """
    tail = wt._norm_tail(base)
    m = wt._tail_to_logical(version)
    # The parent FIRST: the registry lists by-parent sub-tables as endpoints of
    # their own too, and a child is defined (as in rediscovery) by its parent
    # URN being an endpoint.
    if "/" in tail:
        parent, sub = tail.rsplit("/", 1)
        if parent in m:
            return "subtable", m[parent], sub
    if tail in m:
        return "object", m[tail], None
    return "", None, None


def _name_of(data) -> str:
    """The object name a create carries (``{"data": {"name": …}}`` or bare)."""
    if not isinstance(data, dict):
        return ""
    inner = data.get("data") if isinstance(data.get("data"), dict) else data
    return str(inner.get("name") or "")


def _results(resp):
    if resp is None or getattr(resp, "status_code", 500) >= 400:
        return None
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001 — non-JSON is not a read
        return None
    if isinstance(body, dict) and "results" in body:
        res = body["results"]
        # FortiWeb answers a logical error with HTTP 200 + {"errcode": …}
        if isinstance(res, dict) and res.get("errcode") not in (None, 0) and "name" not in res:
            return None
        return res
    return None


def _one(res, name: str):
    if isinstance(res, dict):
        return res if res else None
    if isinstance(res, list):
        hit = [r for r in res if isinstance(r, dict) and str(r.get("name")) == name]
        return hit[0] if hit else None
    return None


def _cached(session, appliance_id, logical, mkey=None, *, layer=None) -> bool:
    from ..models_cache import DeviceObject
    q = session.query(DeviceObject.id).filter_by(
        appliance_id=appliance_id, logical_name=logical, depth=0)
    if mkey is not None:
        q = q.filter_by(mkey=str(mkey))
    if layer:
        q = q.filter_by(layer=layer)
    return q.first() is not None


def after_write(appliance, client, action: str, path: str, data=None, *,
                session=None) -> dict:
    """Bring the cache rows of what ``action`` on ``path`` touched up to the
    device. Call ONLY after the device accepted the write.

    Returns ``{"refreshed": bool, "what": "<logical>[/<sub>]:<mkey>", "why": str}``
    — ``why`` says what was done or why nothing was (never raises).
    """
    out = {"refreshed": False, "what": "", "why": ""}
    try:
        from ..extensions import db
        from ..registry import loader
        session = session or db.session
        aid = getattr(appliance, "id", None)
        if aid is None:
            out["why"] = "no appliance id"
            return out
        base, q = _split(path)
        kind, logical, sub = target_of(base, loader.version_of(appliance))
        if not kind:
            out["why"] = "not a registry collection"
            return out
        mkey = q.get("mkey") or ""
        if kind == "subtable":
            out["what"] = "%s/%s:%s" % (logical, sub, mkey)
            if not mkey:
                out["why"] = "sub-table write without a parent"
                return out
            if not _cached(session, aid, logical, mkey, layer="deep"):
                # its sub-tables were never captured: unknown, not empty
                out["why"] = "parent has no deep capture"
                return out
            rows = _results(client.api_call("GET", "%s?mkey=%s" % (base, mkey)))
            if not isinstance(rows, list):
                out["why"] = "re-read failed"
                return out
            n = wt.local_subrows(aid, logical, mkey, sub, rows, session=session)
            out["refreshed"] = n is not None
            out["why"] = "sub-table re-read (%s rows)" % n
            return out
        name = mkey or (_name_of(data) if action == "create" else "")
        out["what"] = "%s:%s" % (logical, name)
        if not name:
            out["why"] = "write names no object"
            return out
        if action == "delete":
            out["refreshed"] = bool(wt.local_delete(aid, wt._norm_tail(base), name,
                                                    session=session))
            out["why"] = "removed from cache" if out["refreshed"] else "was not cached"
            return out
        if not _cached(session, aid, logical, name if action != "create" else None):
            out["why"] = "type not cached on this device"
            return out
        obj = _one(_results(client.api_call("GET", "%s?mkey=%s" % (base, name))), name)
        if obj is None:
            out["why"] = "re-read failed"
            return out
        out["refreshed"] = bool(wt.local_insert(aid, logical, name, obj, session=session))
        out["why"] = "object re-read"
        return out
    except Exception as exc:  # noqa: BLE001 — the write already succeeded
        try:
            from ..extensions import db
            (session or db.session).rollback()
        except Exception:  # noqa: BLE001
            pass
        log.warning("object_refresh after %s %s: %s", action, path, exc)
        out["why"] = "error: %s" % exc
        return out
