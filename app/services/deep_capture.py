"""Deep capture — walk a device's Server Policy + WPP dependency trees doing
reliable scoped reads, emitting an enriched snapshot where by-parent sub-tables
AND named-rule objects are NESTED inline under a synthetic ``_deep`` key. The
existing ``device_store`` decomposer then lands the whole tree into
``device_objects`` at depth (``parent_id``) with NO schema change.

Captures customization DELTAS only — it follows the dependency tree's ``via``
edges (named references) and by-parent sub-tables (members, rule-lists, disabled
signatures, exceptions). It never enumerates the predefined signature/catalog
universe.

Pure: talks to the box only through a duck-typed reader exposing
``get_raw(urn, mkey)`` (path-style list) and ``get_object(logical, mkey)`` (the
reliable registry ``?mkey=`` read) — exactly the Reader the clone engine uses
(``clone.ClientReader``). Top-level object types are listed once via
``get_raw(urn, "")`` (cached per sweep) and filtered by mkey in Python; by-parent
sub-tables go through ``clone.scoped_rows`` (the leak-proof scoped read).
"""
from __future__ import annotations

import threading
from typing import Any

from ..registry.dependencies import (DepNode, SERVER_POLICY,
                                      WEB_PROTECTION_PROFILE)
from . import clone

# A nested object/sub-table is carried under this synthetic key so the
# device_store decomposer can split each entry out as a child row.
DEEP_KEY = "_deep"

_MKEY_FIELDS = ("name", "mkey", "id")

# The offline WPP shares the inline tree shape.
_WPP_OFFLINE_URN = "cmdb/waf/web-protection-profile.offline-protection"


def _lg(urn: str) -> str | None:
    """Registry logical name for a urn (matched on the normalised collection),
    or None when the urn is not a registry endpoint."""
    return clone.registry_urn_index().get(
        __import__("app.services.objform", fromlist=["collection_of"]).collection_of(urn)
    )


def _deep_key(urn: str) -> str:
    """The key a nested child is stored under: its registry logical name when it
    has one (e.g. ``server_pool``), else the last urn segment (sub-tables like
    ``pserver-list``)."""
    return _lg(urn) or urn.rsplit("/", 1)[-1]


def _mkey_of(obj: dict) -> str:
    for k in _MKEY_FIELDS:
        v = obj.get(k)
        if v not in (None, ""):
            return str(v)
    return ""


def _collection(reader: Any, urn: str, cache: dict) -> list[dict]:
    """All rows of a top-level object type, listed once and cached for the sweep.
    Uses path-style ``get_raw(urn, "")`` — reliable for top-level types (the
    empty-sub-table leak only affects by-parent reads, handled via scoped_rows)."""
    if urn not in cache:
        try:
            rows = reader.get_raw(urn, "")
        except Exception:  # noqa: BLE001 — one bad read never sinks the walk
            rows = []
        cache[urn] = [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []
    return cache[urn]


class _MemoReader:
    """Read-through memo over a clone Reader, for ONE deep sweep.

    Every object gets its own visited set (see :func:`deep_sections`), so a WPP
    named by 30 server policies used to be read 31 times: once per policy that
    names it, once on its own. The tree each walk BUILDS is unchanged; only the
    device reads behind it are shared. Keyed by the exact call, so a cached
    answer is the answer the same call would have got, read moments earlier.

    Thread-safe, and a key being read by one worker is waited for by the others
    instead of read twice. A read that raises is not cached (the next caller
    retries it), which is what the uncached reader did too.
    """

    def __init__(self, reader: Any) -> None:
        self._reader = reader
        self.client = getattr(reader, "client", None)
        self._lock = threading.Lock()
        self._done: dict = {}
        self._inflight: dict = {}
        self.reads = 0      # requests that reached the device
        self.reused = 0     # requests answered from the memo
        if not callable(getattr(reader, "get_object", None)):
            # scoped_rows falls back to get_raw for a reader without the
            # scoped read; the memo must not invent one.
            self.get_object = None

    @staticmethod
    def _copy(rows: Any) -> Any:
        if isinstance(rows, list):
            return list(rows)
        if isinstance(rows, dict):
            return dict(rows)
        return rows

    def _get(self, key: tuple, fetch) -> Any:
        while True:
            with self._lock:
                if key in self._done:
                    self.reused += 1
                    return self._copy(self._done[key])
                pending = self._inflight.get(key)
                if pending is None:
                    pending = self._inflight[key] = threading.Event()
                    self.reads += 1
                    break
            pending.wait()
        try:
            rows = fetch()
            with self._lock:
                self._done[key] = rows
            return self._copy(rows)
        finally:
            with self._lock:
                self._inflight.pop(key, None)
            pending.set()

    def get_raw(self, urn: str, mkey: str = "") -> Any:
        return self._get(("raw", urn, str(mkey or "")),
                         lambda: self._reader.get_raw(urn, mkey))

    def get_object(self, logical: str, mkey: str = "") -> Any:
        return self._get(("obj", logical, str(mkey or "")),
                         lambda: self._reader.get_object(logical, mkey))


def _find(rows: list[dict], mkey: str) -> dict | None:
    for r in rows:
        if _mkey_of(r) == str(mkey):
            return r
    return None


def _named_subs(reader: Any, parent: dict, child: DepNode, seen: set, cache: dict):
    """Collect the object(s) ``parent`` references through ``child.via``. Returns
    a single dict for one ref, a list for several, or None for none."""
    collected = []
    for ref in clone.referenced_names(parent, child.via):
        sub = _collect_node(reader, clone._rich(child), ref, seen, cache)
        if sub is not None:
            collected.append(sub)
    if not collected:
        return None
    return collected[0] if len(collected) == 1 else collected


def _collect_node(reader: Any, node: DepNode, mkey: str, seen: set,
                  cache: dict) -> dict | None:
    """Read object ``mkey`` for ``node`` and recurse its named-ref children +
    by-parent sub-tables, nesting everything under DEEP_KEY (deepest-first via
    the visited set, mirroring clone.ClonePlanner._visit)."""
    if not mkey or (node.urn, mkey) in seen:
        return None
    seen.add((node.urn, mkey))
    obj = _find(_collection(reader, node.urn, cache), mkey)
    if obj is None:
        return None

    deep: dict = {}

    # 1) named references (the dependency edges): a separate object named by a field
    for child in node.children:
        if clone._is_named_ref(child):
            sub = _named_subs(reader, obj, child, seen, cache)
            if sub is not None:
                deep[_deep_key(child.urn)] = sub

    # 2) by-parent sub-tables (members, rule-lists, disabled sigs, exceptions),
    #    each row may itself name deeper objects (the grandchildren).
    for child in node.children:
        if clone._is_named_ref(child) or not child.urn:
            continue
        rows = clone.scoped_rows(reader, child.urn, _lg(child.urn), mkey) or []
        out_rows: list[dict] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            row_deep: dict = {}
            for g in child.children:
                if clone._is_named_ref(g):
                    sub = _named_subs(reader, row, g, seen, cache)
                    if sub is not None:
                        row_deep[_deep_key(g.urn)] = sub
            out_rows.append({**row, DEEP_KEY: row_deep} if row_deep else row)
        if out_rows:
            deep[child.urn.rsplit("/", 1)[-1]] = out_rows

    return {**obj, DEEP_KEY: deep} if deep else obj


def collect_server_policy(reader: Any, mkey: str) -> dict | None:
    """Full dependency graph for one server policy, nested under DEEP_KEY."""
    return _collect_node(reader, SERVER_POLICY, mkey, set(), {})


def collect_wpp(reader: Any, mkey: str) -> dict | None:
    """Full subtree for one Web Protection Profile, nested under DEEP_KEY."""
    return _collect_node(reader, WEB_PROTECTION_PROFILE, mkey, set(), {})


import dataclasses as _dc

# Offline WPPs share the inline tree's children but live under their own urn.
_WPP_OFFLINE_NODE = _dc.replace(WEB_PROTECTION_PROFILE, urn=_WPP_OFFLINE_URN)


def _list_names(reader: Any, urn: str, cache: dict) -> list[str]:
    return [m for m in (_mkey_of(r) for r in _collection(reader, urn, cache)) if m]


# Top-level Server-Objects stores worth counting fleet-wide (certs + SNI). Cheap
# top-level GETs (no expensive sub-table walk); SNI also nests its small member
# list so the drill-down shows the domain->cert mapping. Any store absent on a
# firmware just yields an empty list.
_CERT_STORES = (
    ("certificate", "cmdb/system/certificate.local"),
    ("certificate_ca", "cmdb/system/certificate.ca"),
    ("certificate_ca_group", "cmdb/system/certificate.ca-group"),
    ("certificate_intermediate_group",
     "cmdb/system/certificate.intermediate-certificate-group"),
    ("certificate_letsencrypt", "cmdb/system/certificate.letsencrypt"),
)
_SNI_LOGICAL = "certificate_sni"
_SNI_URN = "cmdb/system/certificate.sni"
_SNI_MEMBERS_URN = "cmdb/system/certificate.sni/members"


def cert_sections(reader: Any, cache: dict) -> dict:
    """Top-level certificate + SNI stores -> a flat {logical: [objs]} section for
    the fleet inventory. SNI nests its members under DEEP_KEY. Box-gentle: one GET
    per store (cached for the sweep)."""
    out: dict = {}
    for logical, urn in _CERT_STORES:
        rows = [dict(r) for r in _collection(reader, urn, cache)]
        if rows:
            out[logical] = rows
    snis: list = []
    for sni in _collection(reader, _SNI_URN, cache):
        members = clone.scoped_rows(reader, _SNI_MEMBERS_URN, "certificate_sni_item",
                                    _mkey_of(sni)) or []
        members = [m for m in members if isinstance(m, dict)]
        snis.append({**sni, DEEP_KEY: {"members": members}} if members else dict(sni))
    if snis:
        out[_SNI_LOGICAL] = snis
    return out


class DeepCaptureStopped(Exception):
    """Raised by :func:`deep_sections` when ``should_stop`` says so.

    Carries where the walk was, because "stopped" alone cannot tell the
    operator how much of the box had been read. The partial graph is NOT
    returned: a deep layer missing the objects that were never reached would
    read as those objects having been deleted.
    """

    def __init__(self, done: int, total: int, phase: str, current: str):
        self.done, self.total, self.phase, self.current = done, total, phase, current
        super().__init__(f"stopped at {done}/{total} ({phase} {current})".strip())


def _app_for_workers():
    """The Flask app behind the caller, or None outside one. Worker threads
    need their OWN app context: the registry a read resolves names through
    (``loader.registry_for``) consults the evidence tables only inside one, and
    without it would silently fall back to the shipped baseline."""
    try:
        from flask import current_app, has_app_context
        return current_app._get_current_object() if has_app_context() else None
    except Exception:  # noqa: BLE001
        return None


def deep_sections(reader: Any, progress=None, should_stop=None,
                  workers: int = 1, stats: dict | None = None) -> dict:
    """Walk every WPP (inline + offline) + every server policy, returning the
    enriched ``{section: {logical_name: [obj-with-_deep, ...]}}`` snapshot shape
    that ``device_store.ingest_sections`` consumes. A single shared collection
    cache keeps the sweep box-gentle (each top-level object type is listed once);
    each object gets its OWN visited set so an object shared by two policies is
    captured in full under each.

    The WPPs are walked FIRST and every device read goes through a per-sweep
    memo (:class:`_MemoReader`): a server policy that names an already-walked
    WPP rebuilds its subtree from reads already made instead of asking the box
    again. The graph returned is the same one; only the reads are shared.

    ``workers`` > 1 walks that many objects at once (the rediscovery sweep
    passes its configured width; every other caller keeps 1, the serial walk).
    The result is assembled in list order whatever order the walks finish in.

    ``progress`` (optional) is called with a dict before every object and once
    at the end, so a caller can say WHICH policy or WPP is being walked and how
    many are left. The three lists are read up front for that reason: the total
    has to be known before the first object, or the bar can only say "running"
    (SI-0004). A broken callback never sinks the walk. Calls are serialised.

    ``should_stop`` (optional) is asked before every object and before the
    certificate stores; True raises :class:`DeepCaptureStopped`. An object
    already being walked is finished first -- one object is a handful of reads,
    and a half-walked object is the one thing worse than a skipped one.

    ``stats`` (optional) is filled with ``reads`` (requests that reached the
    device), ``reused`` (answered from the memo) and ``workers``.
    """
    memo = reader if isinstance(reader, _MemoReader) else _MemoReader(reader)
    workers = max(1, int(workers or 1))
    cache: dict = {}

    pol_names = _list_names(memo, SERVER_POLICY.urn, cache)
    wpp_names = _list_names(memo, WEB_PROTECTION_PROFILE.urn, cache)
    off_names = _list_names(memo, _WPP_OFFLINE_URN, cache)
    work = ([("WPP", WEB_PROTECTION_PROFILE, n, i, len(wpp_names))
             for i, n in enumerate(wpp_names, 1)]
            + [("offline WPP", _WPP_OFFLINE_NODE, n, i, len(off_names))
               for i, n in enumerate(off_names, 1)]
            + [("server policy", SERVER_POLICY, n, i, len(pol_names))
               for i, n in enumerate(pol_names, 1)])
    total = len(work) + 1   # +1: the certificate / SNI stores at the end
    lock = threading.Lock()

    def _stats() -> None:
        if stats is not None:
            stats.update(reads=memo.reads, reused=memo.reused, workers=workers)

    def _tick(done: int, phase: str, index: int, of: int, current: str) -> None:
        if progress is None:
            return
        try:
            progress({"done": done, "total": total, "phase": phase,
                      "index": index, "of": of, "current": current,
                      "policies": len(pol_names),
                      "wpps": len(wpp_names) + len(off_names),
                      "reads": memo.reads, "reused": memo.reused})
        except Exception:  # noqa: BLE001 — reporting never sinks the walk
            pass

    results: list = [None] * len(work)
    run = {"next": 0, "done": 0, "stop": None, "error": None}

    def _take() -> int | None:
        """Claim the next object, or None when there is nothing left to start
        (all claimed, a Stop, or another worker failed)."""
        with lock:
            if run["stop"] is not None or run["error"] is not None:
                return None
            i = run["next"]
            if i >= len(work):
                return None
            phase, _node, nm, idx, of = work[i]
            if should_stop is not None and should_stop():
                run["stop"] = DeepCaptureStopped(run["done"], total, phase, nm)
                return None
            run["next"] = i + 1
            _tick(run["done"], phase, idx, of, nm)
            return i

    def _worker() -> None:
        while True:
            i = _take()
            if i is None:
                return
            _phase, node, nm, _idx, _of = work[i]
            try:
                g = _collect_node(memo, node, nm, set(), cache)
            except BaseException as exc:  # noqa: BLE001 — re-raised below
                with lock:
                    run["error"] = run["error"] or exc
                return
            with lock:
                results[i] = g
                run["done"] += 1

    if workers == 1 or len(work) < 2:
        _worker()
    else:
        app = _app_for_workers()

        def _in_context() -> None:
            if app is None:
                _worker()
            else:
                with app.app_context():
                    _worker()

        threads = [threading.Thread(target=_in_context, daemon=True,
                                    name=f"deep-capture-{n}")
                   for n in range(min(workers, len(work)))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    _stats()
    if run["error"] is not None:
        raise run["error"]
    if run["stop"] is not None:
        raise run["stop"]

    policies = [g for (_p, node, *_r), g in zip(work, results)
                if g and node is SERVER_POLICY]
    wpps = [g for (_p, node, *_r), g in zip(work, results)
            if g and node is not SERVER_POLICY]

    if should_stop is not None and should_stop():
        raise DeepCaptureStopped(len(work), total, "certificates", "")
    _tick(len(work), "certificates", 1, 1, "")
    sections = {
        "Server Policy": {"server_policy": policies},
        "Web Protection": {"web_protection_profile": wpps},
    }
    certs = cert_sections(memo, cache)
    if certs:
        sections["Server Objects"] = certs
    _stats()
    _tick(total, "done", 0, 0, "")
    return sections
