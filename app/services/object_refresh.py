"""Targeted rediscovery + verification: after a write lands, re-read ONLY what
it touched, keep SATOM's copy current, and check the device now holds what was
asked.

The pages draw from the DB-first cache; the box is swept on an explicit ⟳ or a
rediscovery. Every config write SATOM makes to a FortiWeb goes through
``FortiWebOps._apply``, but only a few routes refreshed the cache afterwards
(the policy editor, a sub-table row save, a new policy). Everything else —
enable/disable, delete, clone, bulk, scheduled actions, exception injection —
landed on the device while every list kept drawing the pre-write copy until the
next full sweep (measured 2026-10-12 on fortiweb17: two policies the device had
enabled were still drawn disabled).

And "ok" used to mean only "the device ACCEPTED the request" (no errcode).
FortiWeb builds are known to answer 200 and drop a field (see
``version_compat``), so an accepted write is not proof of a change. The same
re-read answers both questions.

One rule, at the one choke point: an OK write → one GET of the object (or the
sub-table) it touched →

* **cache**: that object's rows, in every layer, are refreshed, inserted or
  removed — only when SATOM holds a copy of it;
* **verify**: every scalar field that was sent is compared with what the device
  now returns. ``verified`` = all compared fields match (a delete: the object is
  gone); ``mismatch`` = the device accepted the write and does NOT hold it;
  ``unverified`` = nothing could be compared (re-read failed, only secrets or
  sub-tables were sent, a field the read does not return).

The verdict is reported, never acted on here: whether a mismatch fails an
operation is the caller's decision (``policy_ops`` fails it). Never raises into
the write path.
"""
from __future__ import annotations

import logging
from urllib.parse import parse_qs

from . import write_through as wt

log = logging.getLogger(__name__)

VERIFIED, MISMATCH, UNVERIFIED = "verified", "mismatch", "unverified"

#: Field names never compared: the device masks them or never returns them.
_SECRET_HINTS = ("pass", "secret", "psk", "private", "token")

#: Read-only counters the device derives itself (``sz_vip-list`` = how many
#: rows the sub-table holds). A clone echoes the source's count in the parent's
#: POST, before its rows exist: comparing it is a false mismatch.
_DERIVED_PREFIXES = ("sz_",)

#: FortiWeb's "no such entry" (HTTP 500, measured on 7.6.8): the object is
#: ABSENT, which a delete wants and an update/create does not.
_NOT_FOUND = -3

_ABSENT = object()


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


def _inner(data):
    if not isinstance(data, dict):
        return {}
    return data.get("data") if isinstance(data.get("data"), dict) else data


def _name_of(data) -> str:
    """The object name a create carries (``{"data": {"name": …}}`` or bare)."""
    return str(_inner(data).get("name") or "")


def _read(client, path):
    """The ``results`` of a GET, ``_ABSENT`` for "no such entry", None when the
    read itself failed."""
    try:
        resp = client.api_call("GET", path)
        body = resp.json() if resp is not None else None
    except Exception:  # noqa: BLE001 — no read is not a verdict
        return None
    res = body.get("results") if isinstance(body, dict) else None
    if isinstance(res, dict) and res.get("errcode") not in (None, 0) and "name" not in res:
        return _ABSENT if res.get("errcode") == _NOT_FOUND else None
    if getattr(resp, "status_code", 500) >= 400:
        return None
    return res


def presence(client, base: str, mkey: str):
    """Does the device hold ``mkey`` in collection ``base``? ``True`` / ``False``
    (FortiWeb answered "entry not found", errcode -3) / ``None`` (the read
    itself failed — unknown, never "absent"). One GET."""
    got = _read(client, "%s?mkey=%s" % ((base or "").lstrip("/"), mkey))
    if got is _ABSENT:
        return False
    if got is None:
        return None
    return _one(got, str(mkey)) is not None


def _one(res, name: str):
    if isinstance(res, dict):
        return res if res else None
    if isinstance(res, list):
        hit = [r for r in res if isinstance(r, dict) and str(r.get("name")) == name]
        return hit[0] if hit else None
    return None


def _norm(v) -> str:
    return str(v).strip().lower()


def compare(sent, device) -> dict:
    """Pure: the sent scalar fields against the device's copy.

    ``{"verdict", "checked": [field…], "mismatch": {field: {"sent", "device"}},
    "unchecked": [field…]}``. Sub-tables (lists/dicts), secrets and derived
    counters (``sz_*``) are not compared; a masked value (``******``) or a field the read does not return
    is ``unchecked``. ``int 80`` and ``"80"`` match; case is ignored.
    """
    out = {"verdict": UNVERIFIED, "checked": [], "mismatch": {}, "unchecked": []}
    if not isinstance(device, dict):
        return out
    for k, v in _inner(sent).items():
        if isinstance(v, (list, dict)) or isinstance(v, bool) or v is None:
            continue
        if any(h in str(k).lower() for h in _SECRET_HINTS):
            continue
        if str(k).startswith(_DERIVED_PREFIXES):
            continue
        if k not in device:
            out["unchecked"].append(k)
            continue
        dv = device[k]
        if isinstance(dv, str) and dv and set(dv) == {"*"}:
            out["unchecked"].append(k)
            continue
        if _norm(v) == _norm(dv):
            out["checked"].append(k)
        else:
            out["mismatch"][k] = {"sent": v, "device": dv}
    if out["mismatch"]:
        out["verdict"] = MISMATCH
    elif out["checked"]:
        out["verdict"] = VERIFIED
    return out


def _gone(verdict_ok: bool, why: str) -> dict:
    return {"verdict": VERIFIED if verdict_ok else MISMATCH, "checked": [],
            "mismatch": {} if verdict_ok else {"(object)": {"sent": "deleted",
                                                           "device": "still present"}},
            "unchecked": [], "why": why}


def _unverified(why: str) -> dict:
    return {"verdict": UNVERIFIED, "checked": [], "mismatch": {}, "unchecked": [],
            "why": why}


def _cached(session, appliance_id, logical, mkey=None, *, layer=None) -> bool:
    from ..models_cache import DeviceObject
    q = session.query(DeviceObject.id).filter_by(
        appliance_id=appliance_id, logical_name=logical, depth=0)
    if mkey is not None:
        q = q.filter_by(mkey=str(mkey))
    if layer:
        q = q.filter_by(layer=layer)
    return q.first() is not None


def _subtable(session, aid, client, action, base, logical, sub, q, data, out):
    mkey, row_id = q.get("mkey") or "", q.get("sub_mkey") or ""
    out["what"] = "%s/%s:%s" % (logical, sub, mkey)
    if not mkey:
        out["why"] = "sub-table write without a parent"
        out["verify"] = _unverified(out["why"])
        return out
    rows = _read(client, "%s?mkey=%s" % (base, mkey))
    if not isinstance(rows, list):
        out["why"] = "re-read failed"
        out["verify"] = _unverified(out["why"])
        return out
    rows = [r for r in rows if isinstance(r, dict)]
    if action == "delete":
        present = any(str(r.get("id")) == row_id for r in rows) if row_id else None
        out["verify"] = (_unverified("no row id") if present is None
                         else _gone(not present, "row %s %s" % (
                             row_id, "still present" if present else "gone")))
    elif action == "update" and row_id:
        row = next((r for r in rows if str(r.get("id")) == row_id), None)
        out["verify"] = (compare(data, row) if row is not None
                         else _gone(False, "row %s is missing" % row_id) | {
                             "mismatch": {"(row)": {"sent": "update", "device": "missing"}}})
    else:
        # A new row has no id yet: verified when SOME row carries what was sent.
        # The ``id`` a copied row carries is the SOURCE's; the box assigns its
        # own, so it is not compared.
        inner = _inner(data)
        sent = {k: v for k, v in inner.items() if k != "id"} if isinstance(inner, dict) else data
        verdicts = [compare(sent, r) for r in rows]
        best = next((v for v in verdicts if v["verdict"] == VERIFIED), None)
        out["verify"] = best or (
            {"verdict": MISMATCH, "checked": [], "unchecked": [],
             "mismatch": {"(row)": {"sent": sent, "device": "no row matches"}}}
            if any(v["checked"] or v["mismatch"] for v in verdicts) or not rows
            else _unverified("nothing comparable was sent"))
    if _cached(session, aid, logical, mkey, layer="deep"):
        n = wt.local_subrows(aid, logical, mkey, sub, rows, session=session)
        out["refreshed"] = n is not None
        out["why"] = "sub-table re-read (%s rows)" % n
    else:
        # its sub-tables were never captured: unknown, not empty
        out["why"] = "parent has no deep capture"
    return out


def after_write(appliance, client, action: str, path: str, data=None, *,
                session=None) -> dict:
    """Re-read what ``action`` on ``path`` touched: refresh the cache rows and
    verify the device holds the change. Call ONLY after the device accepted it.

    Returns ``{"refreshed": bool, "what": "<logical>[/<sub>]:<mkey>",
    "why": str, "verify": {"verdict": verified|mismatch|unverified, …}}``.
    Never raises.
    """
    out = {"refreshed": False, "what": "", "why": "",
           "verify": _unverified("not checked")}
    try:
        from ..extensions import db
        from ..registry import loader
        session = session or db.session
        aid = getattr(appliance, "id", None)
        base, q = _split(path)
        kind, logical, sub = target_of(base, loader.version_of(appliance))
        if kind == "subtable":
            return _subtable(session, aid, client, action, base, logical, sub, q,
                             data, out)
        name = q.get("mkey") or (_name_of(data) if action == "create" else "")
        out["what"] = "%s:%s" % (logical or wt._norm_tail(base), name)
        if not name:
            # a singleton (system/global…): verify by reading it whole
            if action == "update":
                got = _read(client, base)
                out["verify"] = (compare(data, got) if isinstance(got, dict)
                                 else _unverified("re-read failed"))
            out["why"] = "write names no object"
            return out
        got = _read(client, "%s?mkey=%s" % (base, name))
        if action == "delete":
            if got is _ABSENT:
                out["verify"] = _gone(True, "the device no longer has it")
            elif got is None:
                out["verify"] = _unverified("re-read failed")
            else:
                out["verify"] = _gone(_one(got, name) is None, "the device still has it")
            if kind and aid is not None:
                out["refreshed"] = bool(wt.local_delete(aid, wt._norm_tail(base), name,
                                                        session=session))
            out["why"] = "removed from cache" if out["refreshed"] else "was not cached"
            return out
        if got is _ABSENT:
            out["verify"] = _gone(False, "the device does not have it") | {
                "mismatch": {"(object)": {"sent": action, "device": "not found"}}}
            out["why"] = "re-read: not found"
            return out
        obj = _one(got, name)
        if obj is None:
            out["why"] = "re-read failed"
            out["verify"] = _unverified(out["why"])
            return out
        out["verify"] = compare(data, obj)
        if not kind or aid is None:
            out["why"] = "not a registry collection"
        elif not _cached(session, aid, logical, name if action != "create" else None):
            out["why"] = "type not cached on this device"
        else:
            out["refreshed"] = bool(wt.local_insert(aid, logical, name, obj,
                                                    session=session))
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
        out["verify"] = _unverified(out["why"])
        return out


def describe_mismatch(verify: dict) -> str:
    """One line for an operator: what the device holds instead of what was sent."""
    mm = (verify or {}).get("mismatch") or {}
    parts = []
    for k, d in list(mm.items())[:4]:
        if k.startswith("("):
            parts.append("%s: %s" % (d.get("sent"), d.get("device")))
        else:
            parts.append("%s is %r (sent %r)" % (k, d.get("device"), d.get("sent")))
    more = " (+%d more)" % (len(mm) - 4) if len(mm) > 4 else ""
    return ("the device accepted the write but does not hold it — "
            + "; ".join(parts) + more)


def verdict_of(res) -> str:
    """The re-read verdict an ``OpResult`` carries ("" when none: dry-run,
    refused write, or a writer that did not verify)."""
    v = (res.get("verify") if hasattr(res, "get") else None) or {}
    return str(v.get("verdict") or "") if isinstance(v, dict) else ""


def enforce(res):
    """The caller-side rule: an ACCEPTED write the device does not hold is a
    FAILED write. Flips ``res["ok"]`` to False and puts the value the device
    kept in ``res["error"]`` (``not_applied=True``) on a ``mismatch``;
    ``unverified`` is left ok (reported, not failed). Returns ``res``; a
    non-dict (or a dry-run) passes through untouched. Never raises."""
    try:
        if (isinstance(res, dict) and res.get("ok") and not res.get("dry_run")
                and verdict_of(res) == MISMATCH):
            res["ok"] = False
            res["not_applied"] = True
            res["error"] = describe_mismatch(res.get("verify"))
    except Exception:  # noqa: BLE001
        pass
    return res
