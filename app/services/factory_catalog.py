"""Factory catalog — predefined WPPs read once per firmware build, not per sweep.

Every FortiWeb ships the same ~20 predefined Web Protection Profiles (10
inline, 10 offline; measured on all 15 lab captures, 2026-10-05). The deep pass
walked every one of them on every appliance on every sweep, up to ~125 device
reads each, to re-read content the vendor wrote. This module stores each one
ONCE per surface and lets the next sweep rebuild it without the sub-table
reads.

The surface is (product, firmware, build number, REST API version). Both
halves matter: a newer build adds fields to the same profile (fortiweb17
serves six more on "Inline Standard Protection" than 7.6.8), and the API
version is the stamp a template carries (``template_compat.api_version_for``),
so a catalog entry and a template are comparable without translation.

How a sweep uses it (:class:`CatalogSession`, pure, no database):

1. Only a profile the box marks as predefined (``clone_scope.is_factory``)
   is a candidate. Everything else is walked exactly as before.
2. A candidate is REPLAYED: ``deep_capture._collect_node`` runs again with a
   reader that answers top-level lists from the appliance (one listing per
   object type per sweep, already shared with the rest of the walk) and every
   scoped sub-table read from the reads recorded when the entry was captured.
   The tree is therefore built by the same code from the same answers: it is
   not a hand-made copy.
3. The replay is accepted only when the appliance's OWN top-level rows (the
   profile and every object it names, ``sz_*`` sub-table counters included)
   hash to the entry's, the entry is not ambiguous, and it was verified by a
   full walk within :func:`reverify_days`. Anything else walks in full and
   records what it read.

What it cannot see: a sub-table row edited IN PLACE on one appliance (the
``sz_*`` counters catch rows added or removed, not rows changed). Two
defences: every entry is re-read in full every :func:`reverify_days` days, and
a full walk that finds the same top-level rows with a different tree marks
every such variant ``ambiguous`` — from then on that profile is always walked
on that surface.

A walk with a failed read (transport error, auth, HTTP 5xx; see
``deep_capture.FlaggingClient``) is never stored: an incomplete tree replayed
for a week would be worse than the slow walk it replaced.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import threading
from datetime import datetime, timedelta
from typing import Any

from . import clone, clone_scope
from . import deep_capture as dc

#: Reverse-reference projections. ``q_ref`` counts the objects pointing AT a
#: profile, which is how many policies use it on THIS appliance — usage, not
#: content. Kept in the tree an appliance gets, left out of identity.
REVERSE_REF_KEYS = frozenset({"q_ref", "q_ref_string"})

KIND_INLINE = "wpp_inline"
KIND_OFFLINE = "wpp_offline"
KIND_LABEL = {KIND_INLINE: "Inline WPP", KIND_OFFLINE: "Offline WPP"}

ACT_REUSED = "reused"
ACT_WALKED = "walked"

DEFAULT_REVERIFY_DAYS = 7


def enabled() -> bool:
    """``SATOM_FACTORY_CATALOG`` (default on). 0 = every profile is walked."""
    return os.environ.get("SATOM_FACTORY_CATALOG", "1").strip().lower() not in (
        "0", "false", "off", "no")


def reverify_days() -> int:
    """``SATOM_FACTORY_REVERIFY_DAYS`` (default 7, minimum 1): how old an
    entry's last full read may be before the next sweep reads it again."""
    try:
        n = int(os.environ.get("SATOM_FACTORY_REVERIFY_DAYS", DEFAULT_REVERIFY_DAYS))
    except ValueError:
        n = DEFAULT_REVERIFY_DAYS
    return max(1, n)


# ---------------------------------------------------------------------------
# identity
# ---------------------------------------------------------------------------

def _strip(value):
    if isinstance(value, list):
        return [_strip(v) for v in value]
    if isinstance(value, dict):
        return {k: _strip(v) for k, v in value.items() if k not in REVERSE_REF_KEYS}
    return value


def identity(value):
    """What two reads of the same vendor object must agree on.

    ``sot_store.normalise`` first — the rules the source-of-truth store
    already uses for "is this a configuration change" (internal ``*_val``
    handles, the clock, rolling windows) — then the reverse-reference
    counters, which describe the appliance's usage of the object."""
    from .sot_store import normalise
    return _strip(normalise(value))


def sha(value) -> str:
    return hashlib.sha256(json.dumps(identity(value), sort_keys=True, default=str,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def count_nodes(tree) -> int:
    """Objects + sub-table rows in a nested deep tree."""
    if isinstance(tree, list):
        return sum(count_nodes(t) for t in tree)
    if not isinstance(tree, dict):
        return 0
    n = 1
    for sub in (tree.get(dc.DEEP_KEY) or {}).values():
        n += count_nodes(sub)
    return n


def top_rows(seen: set, cache: dict) -> list:
    """``[[urn, mkey, row-or-None], …]`` for every top-level object a walk
    visited, sorted. ``None`` records a name that was looked up and is not
    there, which is as much a part of the tree's shape as a row that is."""
    out = []
    for urn, mkey in sorted(seen):
        row = dc._find(cache.get(urn) or [], mkey)
        out.append([urn, str(mkey), dict(row) if row is not None else None])
    return out


# ---------------------------------------------------------------------------
# firmware surface
# ---------------------------------------------------------------------------

_BUILD_RE = re.compile(r"build\s*0*(\d+)", re.IGNORECASE)


def build_no_of(raw: str) -> str:
    """``1128`` from ``v7.6.8,build1128,240829 (GA.M)``; "" when absent."""
    m = _BUILD_RE.search(str(raw or ""))
    return m.group(1) if m else ""


def live_firmware(client) -> str:
    """The firmware string the appliance reports RIGHT NOW (``status``
    ``firmwareVersion``, e.g. ``8.0.3 build0093,260401``), "" when it cannot
    be read. One request. Preferred over ``Appliance.firmware``, which other
    flows fill and which was empty on two of three live FortiWebs (see
    ``rediscovery._device_firmware``): the catalog files content under the
    build that served it, so it asks the box."""
    try:
        body = client.status_check()
        d = body.get("results", body) if isinstance(body, dict) else {}
        return str((d or {}).get("firmwareVersion") or "")
    except Exception:  # noqa: BLE001 — no answer = fall back to the record
        return ""


def surface_for(appliance, firmware_raw: str = "") -> dict | None:
    """The catalog key of an appliance, or None when it has none.

    ``firmware_raw`` (from :func:`live_firmware`) wins over what the
    appliance record says. No firmware = no surface: a profile read off a box
    whose build is unknown cannot be filed under any build, and replaying one
    onto it would be a guess. Those appliances keep the full walk.
    """
    from . import firmware_versions as fv
    from .template_compat import api_version_for
    product = (getattr(appliance, "kind", "") or "fortiweb").lower()
    if product != "fortiweb":
        return None
    # A raw firmware string first: it carries the build number
    # (``FortiWeb-VM v7.6.8,build1128``); ``fw_version`` is only X.Y.Z.
    raw = (firmware_raw or getattr(appliance, "firmware", "")
           or getattr(appliance, "fw_version", "") or "")
    firmware = fv.normalize(raw)
    if not firmware or fv.is_line_only(firmware):
        return None
    return {"product": product, "firmware": firmware, "build_no": build_no_of(raw),
            "api_version": api_version_for(product), "firmware_raw": str(raw)[:128]}


def surface_label(s: dict) -> str:
    b = (" build %s" % s["build_no"]) if s.get("build_no") else ""
    return "%s %s%s · API %s" % (s.get("product", ""), s.get("firmware", ""), b,
                                  s.get("api_version") or "—")


# ---------------------------------------------------------------------------
# readers
# ---------------------------------------------------------------------------

class CatalogMiss(LookupError):
    """A replay asked for a read the entry never recorded: the appliance's
    tree takes a path the captured one did not, so it must be walked."""


def _key(kind: str, a: str, b: str) -> tuple:
    return (kind, str(a), str(b or ""))


class Recorder:
    """Records every scoped read one object's walk makes, on top of the sweep's
    memo. Top-level listings (``get_raw(urn, "")``) are not recorded: on
    replay they come from the appliance being swept."""

    def __init__(self, live: Any) -> None:
        self._live = live
        self.client = getattr(live, "client", None)
        self.reads: dict = {}
        self.incomplete = False
        if not callable(getattr(live, "get_object", None)):
            self.get_object = None

    def _note(self, key: tuple, rows) -> None:
        self.reads[key] = rows
        if key in getattr(self._live, "failed", ()):
            self.incomplete = True

    def get_raw(self, urn: str, mkey: str = ""):
        rows = self._live.get_raw(urn, mkey)
        if mkey:
            self._note(_key("raw", urn, mkey), rows)
        elif _key("raw", urn, "") in getattr(self._live, "failed", ()):
            self.incomplete = True
        return rows

    def get_object(self, logical: str, mkey: str = ""):
        rows = self._live.get_object(logical, mkey)
        self._note(_key("obj", logical, mkey), rows)
        return rows


class ReplayReader:
    """Top-level listings from the appliance; scoped reads from a recording."""

    def __init__(self, live: Any, reads: dict, has_get_object: bool = True) -> None:
        self._live = live
        self._reads = reads
        self.client = getattr(live, "client", None)
        if not has_get_object:
            self.get_object = None

    @staticmethod
    def _copy(rows):
        return [dict(r) if isinstance(r, dict) else r for r in rows] \
            if isinstance(rows, list) else rows

    def get_raw(self, urn: str, mkey: str = ""):
        if not mkey:
            return self._live.get_raw(urn, "")
        k = _key("raw", urn, mkey)
        if k not in self._reads:
            raise CatalogMiss(k)
        return self._copy(self._reads[k])

    def get_object(self, logical: str, mkey: str = ""):
        k = _key("obj", logical, mkey)
        if k not in self._reads:
            raise CatalogMiss(k)
        return self._copy(self._reads[k])


class _NoLive:
    """The 'appliance' of an offline replay: a catalog entry's own rows."""

    def __init__(self, top: list) -> None:
        self._by_urn: dict = {}
        for urn, _mkey, row in top:
            if row is not None:
                self._by_urn.setdefault(urn, []).append(row)
        self.client = None

    def get_raw(self, urn: str, mkey: str = ""):
        return [dict(r) for r in self._by_urn.get(urn, [])]


class CatalogReader(ReplayReader):
    """A clone Reader over ONE catalog entry, with no appliance at all.

    Serves what :class:`clone.ClonePlanner` asks for: an object by name
    (from the recorded top-level rows) and its sub-tables (from the recorded
    reads). Anything else raises :class:`CatalogMiss`.
    """

    def __init__(self, payload: dict) -> None:
        self._top = payload.get("top") or []
        super().__init__(_NoLive(self._top), decode_reads(payload.get("reads")),
                         has_get_object=payload.get("has_get_object", True))
        self.client = None

    def _top_lookup(self, collection: str, mkey: str):
        from .objform import collection_of
        for urn, m, row in self._top:
            if str(m) == str(mkey) and collection_of(urn) == collection:
                # looked up and absent at capture time: the box said "none"
                return [dict(row)] if row is not None else []
        return None

    def get_raw(self, urn: str, mkey: str = ""):
        k = _key("raw", urn, mkey)
        if mkey and k in self._reads:
            return self._copy(self._reads[k])
        if mkey:
            from .objform import collection_of
            rows = self._top_lookup(collection_of(urn), mkey)
            if rows is not None:
                return rows
            raise CatalogMiss(k)
        return self._live.get_raw(urn, "")

    def get_object(self, logical: str, mkey: str = ""):
        k = _key("obj", logical, mkey)
        if k in self._reads:
            return self._copy(self._reads[k])
        from .objform import collection_of
        for coll, lg in clone.registry_urn_index().items():
            if lg != logical:
                continue
            rows = self._top_lookup(coll, mkey)
            if rows is not None:
                return rows
            # a sub-table of an object the capture found absent: the box
            # serves no rows under a parent that does not exist
            if any(row is None and str(m) == str(mkey)
                   and coll.startswith(collection_of(urn) + "/")
                   for urn, m, row in self._top):
                return []
        raise CatalogMiss(k)


def encode_reads(reads: dict) -> list:
    return [[k[0], k[1], k[2], v] for k, v in sorted(reads.items(), key=lambda kv: kv[0])]


def decode_reads(rows) -> dict:
    return {_key(r[0], r[1], r[2]): r[3] for r in rows or [] if len(r) == 4}


def pack(payload: dict) -> bytes:
    return gzip.compress(json.dumps(payload, sort_keys=True, default=str,
                                    separators=(",", ":")).encode("utf-8"))


def unpack(blob: bytes) -> dict:
    return json.loads(gzip.decompress(blob).decode("utf-8"))


# ---------------------------------------------------------------------------
# one sweep
# ---------------------------------------------------------------------------

class CatalogSession:
    """The catalog as ONE deep sweep sees it. Pure: the variants are handed
    in, the outcomes are collected, a caller persists them.

    ``variants`` are dicts: ``id, kind, name, content_sha, top_sha, status,
    last_verified_at`` (datetime) and ``payload`` (the unpacked dict).
    ``force_walk`` reads every predefined profile in full this sweep (and
    still records it, which is how an entry is refreshed on demand).
    """

    def __init__(self, surface: dict, variants: list[dict] | None = None, *,
                 force_walk: bool = False, reverify: int | None = None,
                 now: datetime | None = None) -> None:
        self.surface = surface
        self.force_walk = force_walk
        self.reverify = reverify if reverify is not None else reverify_days()
        self.now = now or datetime.utcnow()
        self._by_name: dict = {}
        for v in variants or []:
            self._by_name.setdefault((v["kind"], v["name"]), []).append(v)
        self._lock = threading.Lock()
        self.outcomes: list[dict] = []

    # -- counters ------------------------------------------------------
    def counts(self) -> dict:
        c = {"reused": 0, "walked": 0, "incomplete": 0}
        for o in self.outcomes:
            if o["action"] == ACT_REUSED:
                c["reused"] += 1
            else:
                c["walked"] += 1
                if o.get("incomplete"):
                    c["incomplete"] += 1
        return c

    def _out(self, outcome: dict) -> None:
        with self._lock:
            self.outcomes.append(outcome)

    # -- the decision --------------------------------------------------
    def _stale(self, v: dict) -> bool:
        at = v.get("last_verified_at")
        return (not isinstance(at, datetime)
                or at < self.now - timedelta(days=self.reverify))

    def _replay(self, live, node, name, cache, v):
        """(tree, top, top_sha) of ``v`` replayed against ``live``, or None."""
        p = v.get("payload") or {}
        seen: set = set()
        try:
            tree = dc._collect_node(
                ReplayReader(live, decode_reads(p.get("reads")),
                             p.get("has_get_object", True)),
                node, name, seen, cache)
        except CatalogMiss:
            return None
        top = top_rows(seen, cache)
        return tree, top, sha(top)

    def collect(self, live: Any, node, name: str, cache: dict, kind: str):
        """The tree for profile ``name``: replayed when the catalog can vouch
        for it on this appliance, otherwise walked (and recorded)."""
        row = dc._find(dc._collection(live, node.urn, cache), name)
        if row is None or not clone_scope.is_factory(row):
            return dc._collect_node(live, node, name, set(), cache)

        candidates = [v for v in self._by_name.get((kind, name), [])]
        reason = "not in the catalog for this build" if not candidates else ""
        replayed = None
        if self.force_walk:
            reason = "full read requested"
        else:
            for v in candidates:
                r = self._replay(live, node, name, cache, v)
                if r is None:
                    continue
                tree, _top, top_sha = r
                twins = {o["content_sha"] for o in candidates
                         if o["top_sha"] == top_sha}
                if v.get("status") != "ok" or len(twins) > 1:
                    reason = ("two appliances on this build disagree below the "
                              "top-level rows")
                    break
                if sha(tree) != v["content_sha"]:
                    continue
                replayed = (v, tree)
                if self._stale(v):
                    reason = "last full read older than %d day(s)" % self.reverify
                    break
                self._out({"action": ACT_REUSED, "kind": kind, "name": name,
                           "variant_id": v["id"], "content_sha": v["content_sha"]})
                return tree
            else:
                if candidates and not reason:
                    reason = "this appliance's rows differ from every catalog variant"
        return self._walk(live, node, name, cache, kind, reason, replayed)

    def _walk(self, live, node, name, cache, kind, reason, replayed):
        rec = Recorder(live)
        seen: set = set()
        tree = dc._collect_node(rec, node, name, seen, cache)
        top = top_rows(seen, cache)
        content = sha(tree)
        outcome = {"action": ACT_WALKED, "kind": kind, "name": name,
                   "reason": reason, "urn": node.urn,
                   "content_sha": content, "top_sha": sha(top),
                   "incomplete": rec.incomplete,
                   "payload": {"tree": tree, "top": top,
                               "reads": encode_reads(rec.reads),
                               "has_get_object": callable(getattr(rec, "get_object", None))},
                   "node_count": count_nodes(tree), "read_count": len(rec.reads)}
        self._out(outcome)
        # A re-read that confirms the entry hands back the REPLAYED tree: the
        # two are equal under identity, and the replayed one is what every
        # sweep since the capture emitted, so the deep layer does not flip
        # on internal handles once a week.
        if replayed is not None and not rec.incomplete \
                and replayed[0]["content_sha"] == content:
            return replayed[1]
        return tree

    def summary(self) -> dict:
        c = self.counts()
        return {"surface": {k: self.surface.get(k) for k in
                            ("product", "firmware", "build_no", "api_version")},
                **c,
                "reused_names": sorted(o["name"] for o in self.outcomes
                                       if o["action"] == ACT_REUSED),
                "walked": [{"kind": o["kind"], "name": o["name"], "reason": o["reason"],
                            "incomplete": bool(o.get("incomplete"))}
                           for o in sorted(self.outcomes, key=lambda o: (o["kind"], o["name"]))
                           if o["action"] == ACT_WALKED],
                "walked_count": c["walked"]}


# ---------------------------------------------------------------------------
# database
# ---------------------------------------------------------------------------

def _model():
    from ..models_factory import FactoryObject
    return FactoryObject


def _rollback() -> None:
    try:
        from ..extensions import db
        db.session.rollback()
    except Exception:  # noqa: BLE001
        pass


def _surface_query(s: dict):
    FO = _model()
    return FO.query.filter_by(product=s["product"], firmware=s["firmware"],
                              build_no=s["build_no"], api_version=s["api_version"])


def open_session(appliance, *, force_walk: bool = False,
                 firmware_raw: str = "") -> CatalogSession | None:
    """The session for ``appliance``'s next deep sweep, or None (catalog off,
    appliance without a usable firmware, or the table cannot be read — in
    every one of those cases the sweep walks everything, as it always did)."""
    if not enabled():
        return None
    s = surface_for(appliance, firmware_raw)
    if s is None:
        return None
    try:
        rows = _surface_query(s).all()
        variants = [{"id": r.id, "kind": r.kind, "name": r.name,
                     "content_sha": r.content_sha, "top_sha": r.top_sha,
                     "status": r.status, "last_verified_at": r.last_verified_at,
                     "payload": unpack(r.payload)} for r in rows]
    except Exception:  # noqa: BLE001 — a catalog problem never sinks a sweep
        _rollback()
        return None
    return CatalogSession(s, variants, force_walk=force_walk)


def persist(session: CatalogSession, appliance) -> dict:
    """Store what one sweep learned. Never raises; returns the summary with
    ``new`` / ``verified`` / ``ambiguous`` / ``skipped_incomplete`` counts."""
    out = session.summary()
    out.update(new=0, verified=0, ambiguous=0, skipped_incomplete=0)
    if not session.outcomes:
        return out
    try:
        from ..extensions import db
        FO = _model()
        s = session.surface
        now = datetime.utcnow()
        name = getattr(appliance, "name", "") or ""
        touched: set = set()
        for o in session.outcomes:
            q = _surface_query(s).filter_by(kind=o["kind"], name=o["name"])
            if o["action"] == ACT_REUSED:
                row = q.filter_by(id=o["variant_id"]).first()
                if row is not None:
                    row.reuse_count = (row.reuse_count or 0) + 1
                    row.last_reused_at = now
                continue
            if o.get("incomplete"):
                out["skipped_incomplete"] += 1
                continue
            row = q.filter_by(content_sha=o["content_sha"]).first()
            if row is None:
                row = FO(product=s["product"], firmware=s["firmware"],
                         build_no=s["build_no"], api_version=s["api_version"],
                         firmware_raw=s.get("firmware_raw", ""),
                         kind=o["kind"], name=o["name"], urn=o.get("urn", ""),
                         content_sha=o["content_sha"], top_sha=o["top_sha"],
                         payload=pack(o["payload"]), node_count=o["node_count"],
                         read_count=o["read_count"],
                         captured_from_id=getattr(appliance, "id", None),
                         captured_from=name, captured_at=now,
                         last_verified_at=now, last_verified_from=name,
                         verify_count=1, status=FO.STATUS_OK)
                db.session.add(row)
                out["new"] += 1
            else:
                row.last_verified_at = now
                row.last_verified_from = name
                row.verify_count = (row.verify_count or 0) + 1
                out["verified"] += 1
            touched.add((o["kind"], o["name"]))
        db.session.flush()
        for kind, nm in touched:
            rows = _surface_query(s).filter_by(kind=kind, name=nm).all()
            by_top: dict = {}
            for r in rows:
                by_top.setdefault(r.top_sha, set()).add(r.content_sha)
            for r in rows:
                if len(by_top[r.top_sha]) > 1 and r.status != FO.STATUS_AMBIGUOUS:
                    r.status = FO.STATUS_AMBIGUOUS
                    r.status_reason = ("another appliance on this build serves the "
                                       "same top-level rows with different "
                                       "sub-tables; always read in full")[:255]
                    out["ambiguous"] += 1
        db.session.commit()
    except Exception as exc:  # noqa: BLE001
        _rollback()
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
    return out


# ---------------------------------------------------------------------------
# read side (pages)
# ---------------------------------------------------------------------------

def surfaces(product: str = "fortiweb") -> list[dict]:
    """Every surface the catalog holds, newest firmware first."""
    from . import firmware_versions as fv
    FO = _model()
    seen: dict = {}
    for r in FO.query.filter_by(product=product).all():
        k = (r.firmware, r.build_no, r.api_version)
        d = seen.setdefault(k, {"product": product, "firmware": r.firmware,
                                "build_no": r.build_no, "api_version": r.api_version,
                                "entries": 0, "ambiguous": 0, "names": set(),
                                "captured_from": set(), "last_verified_at": None})
        d["entries"] += 1
        d["names"].add((r.kind, r.name))
        d["captured_from"].add(r.captured_from)
        if r.status != FO.STATUS_OK:
            d["ambiguous"] += 1
        if d["last_verified_at"] is None or r.last_verified_at > d["last_verified_at"]:
            d["last_verified_at"] = r.last_verified_at
    out = []
    for d in seen.values():
        d["profiles"] = len(d.pop("names"))
        d["captured_from"] = sorted(x for x in d["captured_from"] if x)
        d["label"] = surface_label(d)
        out.append(d)
    return sorted(out, key=lambda d: (fv.sort_key(d["firmware"]), d["build_no"]),
                  reverse=True)


def entries(product: str = "fortiweb", firmware: str = "", build_no: str | None = None,
            api_version: str | None = None, name: str = "") -> list:
    FO = _model()
    q = FO.query.filter_by(product=product)
    if firmware:
        q = q.filter_by(firmware=firmware)
    if build_no is not None:
        q = q.filter_by(build_no=build_no)
    if api_version is not None:
        q = q.filter_by(api_version=api_version)
    if name:
        q = q.filter_by(name=name)
    return q.order_by(FO.kind, FO.name, FO.captured_at).all()


def get(entry_id: int):
    return _model().query.get(entry_id)


def stale(row) -> bool:
    return row.last_verified_at < datetime.utcnow() - timedelta(days=reverify_days())


def tree_of(row) -> dict:
    return unpack(row.payload).get("tree") or {}


# -- comparing two entries -------------------------------------------------

def _flatten(value, path: str, out: dict) -> None:
    if isinstance(value, dict):
        sub = {k: v for k, v in value.items() if k != dc.DEEP_KEY}
        for k in sorted(sub):
            _flatten(sub[k], "%s.%s" % (path, k) if path else str(k), out)
        for k, v in sorted((value.get(dc.DEEP_KEY) or {}).items()):
            _flatten(v, "%s/%s" % (path, k) if path else str(k), out)
        return
    if isinstance(value, list):
        if value and all(isinstance(v, dict) for v in value):
            for i, v in enumerate(value):
                tag = dc._mkey_of(v) or str(i)
                _flatten(v, "%s[%s]" % (path, tag), out)
            return
        out[path] = json.dumps(value, sort_keys=True, default=str)
        return
    out[path] = value


def diff(a: dict, b: dict) -> dict:
    """Field-level difference of two trees under :func:`identity`.

    ``{"added": [(path, new)], "removed": [(path, old)], "changed":
    [(path, old, new)]}`` — "added" is what ``b`` has and ``a`` does not.
    Paths read ``field`` for a profile field, ``sub-table[row]`` for a row and
    ``named_object[name].field`` below a referenced object.
    """
    fa, fb = {}, {}
    _flatten(identity(a), "", fa)
    _flatten(identity(b), "", fb)
    added = [(p, fb[p]) for p in sorted(set(fb) - set(fa))]
    removed = [(p, fa[p]) for p in sorted(set(fa) - set(fb))]
    changed = [(p, fa[p], fb[p]) for p in sorted(set(fa) & set(fb)) if fa[p] != fb[p]]
    return {"added": added, "removed": removed, "changed": changed,
            "total": len(added) + len(removed) + len(changed)}


# -- template from an entry ------------------------------------------------

def template_body(row, new_name: str = "") -> dict:
    """The Web Protection template body for an entry, built by the same
    planner "Save as template" uses on a live appliance, reading the entry
    instead of the box. Raises :class:`CatalogMiss` when the planner needs a
    read the entry does not hold (the template must then be saved from an
    appliance)."""
    payload = unpack(row.payload)
    reader = CatalogReader(payload)
    planner = clone.ClonePlanner(reader, reader)
    items = planner.collect(clone.ROOT_WPP, row.name, new_name=new_name or row.name)
    body = clone.template_body(items, new_name or row.name)
    if not body.get("data"):
        raise CatalogMiss(("obj", "web_protection_profile", row.name))
    return body


def template_stamp(row) -> dict:
    """The template stamp of an entry: its firmware and API version, the
    appliance it was read from, provenance ``factory``."""
    from ..models import Template
    return {"source_firmware": row.firmware, "api_version": row.api_version,
            "source_appliance_id": row.captured_from_id,
            "source_appliance": row.captured_from or "",
            "provenance": Template.PROV_FACTORY}


def save_as_template(row, *, name: str = "", author: str = ""):
    from ..models import Template
    from .templates import save_template
    name = (name or "").strip() or row.name
    body = template_body(row, name)
    b = (" build %s" % row.build_no) if row.build_no else ""
    return save_template(
        Template.KIND_WEB_PROTECTION, name, body,
        note=("From the factory catalog: predefined %s \"%s\", FortiWeb %s%s, API "
              "%s, read from %s (pending approval)"
              % (KIND_LABEL.get(row.kind, row.kind), row.name, row.firmware, b,
                 row.api_version or "—", row.captured_from or "an appliance")),
        author=author, stamp=template_stamp(row))
