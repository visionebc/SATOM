"""Tree-clone engine for the web app — recreate a WHOLE FortiWeb object tree on
the same (or another) appliance, validating at the destination.

This is the web port of the desktop ``services.clone`` engine. It walks the
in-repo dependency map (:mod:`app.registry.dependencies`) — a **Web Protection
Profile** (→ its ~40 protection sub-policies, each with child rule-lists) or a
**Server Policy** — against a SOURCE appliance, collecting every ``via``-
referenced named object DEEPEST-FIRST (a signature policy before the WPP that
references it; pool members after their pool), then classifies each item against
the DESTINATION:

    - ``exists``      → already on the target ⇒ NOT copied (the validation: "if
                        the WPP already exists, don't copy it").
    - ``create``      → missing ⇒ will be created.
    - ``cert``        → a certificate ⇒ SSH-only, never carried over REST.
    - ``no-endpoint`` → urn has no writable registry endpoint ⇒ reported, kept.
    - ``empty``       → not found on the source.

``apply_clone`` creates the ``create`` items via a caller-supplied ``write``
callable (so snapshot/audit/dry-run live with the route, through ``FortiWebOps``).

PURE PLANNER: it talks to the boxes only through a duck-typed reader exposing
``get_raw(urn, mkey) -> list[dict]`` (and optionally ``get_object(logical, mkey)``
for the reliable ``?mkey=`` scoped read), so ``tests/test_clone.py`` drives it
with in-memory fakes — no Flask, no network.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable, Protocol
from urllib.parse import quote

from ..registry.dependencies import (
    DepNode,
    SERVER_POLICY,
    WEB_PROTECTION_PROFILE,
    dep_node_for_urn,
)
from ..registry.loader import load_registry
from .fortiweb_ops import sanitize_payload as clean_for_write
from . import objform

# WPP root urns — splice the FULL profile subtree in wherever a parent only
# *points* at a profile by name.
_WPP_INLINE = WEB_PROTECTION_PROFILE.urn  # cmdb/waf/web-protection-profile.inline-protection
_WPP_OFFLINE = "cmdb/waf/web-protection-profile.offline-protection"

# Certificates can't move over REST (SSH-only) — flagged, never copied.
_CERT_URNS = {"cmdb/system/certificate.local", "cmdb/system/certificate.sni"}

# Values that mean "no reference" when read off a parent field.
_EMPTY_REFS = {"", "0", "disable", "enable", "none", "None", "http://", "https://"}

OnLog = Callable[[str], None]
_NOOP: OnLog = lambda _m: None  # noqa: E731


# --------------------------------------------------------------------------- #
#  registry urn -> logical index (the web registry is a flat {logical: urn})    #
# --------------------------------------------------------------------------- #
def registry_urn_index() -> dict[str, str]:
    """``{collection: logical}`` inverted from ``endpoints.yaml``.

    Keyed by the NORMALISED collection (``objform.collection_of``) because
    ``endpoints.yaml`` spells urns as full REST paths (``/api/v2.0/cmdb/waf/…``)
    while ``dependencies.py`` uses the bare ``cmdb/waf/…`` form — both reduce to
    the same ``waf/…`` collection, which is how a tree urn finds its logical name."""
    return {objform.collection_of(urn): logical for logical, urn in load_registry().items()}


def _logical_to_urn(logical: str) -> str:
    return load_registry().get(logical, "")


# --------------------------------------------------------------------------- #
#  pure helpers (replace library.inspector on the desktop)                      #
# --------------------------------------------------------------------------- #
def unwrap(value: Any) -> Any:
    return value


def attr(obj: dict, *names: str) -> Any:
    if isinstance(obj, dict):
        for n in names:
            if n in obj:
                return obj[n]
    return None


class Reader(Protocol):
    """Read side of an appliance: raw GET by concrete urn + path key."""

    def get_raw(self, urn: str, mkey: str = "") -> list[dict]: ...


# --------------------------------------------------------------------------- #
#  Client adapter — wraps the web FortiWebClient as a clone Reader              #
# --------------------------------------------------------------------------- #
def _unwrap_list(raw: Any) -> list[dict]:
    """Object list out of a FortiWeb ``{"results": …}`` envelope (errcode → [])."""
    if isinstance(raw, dict):
        res = raw.get("results", raw.get("data"))
        if isinstance(res, dict) and res.get("errcode") not in (None, 0):
            return []
        if isinstance(res, list):
            return [r for r in res if isinstance(r, dict)]
        if isinstance(res, dict):
            return [res]
        return [raw] if "name" in raw else []
    return [r for r in raw if isinstance(r, dict)] if isinstance(raw, list) else []


class ClientReader:
    """Duck-typed clone Reader over a web :class:`FortiWebClient`.

    ``get_object(logical, mkey)`` is the RELIABLE scoped read (logical → urn via
    the registry → ``?mkey=``); ``get_raw(urn, mkey)`` is the path-style fallback.
    Neither raises (returns ``[]`` on any transport failure)."""

    def __init__(self, client: Any) -> None:
        self.client = client

    def get_raw(self, urn: str, mkey: str = "") -> list[dict]:
        try:
            path = objform.rest_path(urn)
            if mkey:
                path += "?mkey=%s" % quote(str(mkey), safe="")
            return _unwrap_list(self.client.get(path).json())
        except Exception:  # noqa: BLE001
            return []

    def get_object(self, logical: str, mkey: str = "") -> list[dict]:
        urn = _logical_to_urn(logical)
        if not urn:
            return []
        try:
            path = objform.rest_path(urn) + "?mkey=%s" % quote(str(mkey), safe="")
            return _unwrap_list(self.client.get(path).json())
        except Exception:  # noqa: BLE001
            return []


# --------------------------------------------------------------------------- #
#  Plan item                                                                   #
# --------------------------------------------------------------------------- #
@dataclass
class CloneItem:
    """One object (or sub-table row) in a clone plan, with its destination verdict."""

    label: str
    urn: str
    logical: str | None
    mkey: str
    parent_mkey: str
    kind: str               # "object" | "subrow"
    depth: int
    payload: dict
    status: str = "create"  # create | exists | cert | no-endpoint | empty
    note: str = ""
    applied: bool = False
    result: str = ""

    @property
    def will_create(self) -> bool:
        return self.status == "create"

    def to_dict(self) -> dict:
        return {
            "label": self.label, "urn": self.urn, "logical": self.logical,
            "mkey": self.mkey, "parent_mkey": self.parent_mkey, "kind": self.kind,
            "depth": self.depth, "status": self.status, "note": self.note,
            "result": self.result,
        }


# --------------------------------------------------------------------------- #
#  Reference-field parsing                                                      #
# --------------------------------------------------------------------------- #
def _is_named_ref(node: DepNode) -> bool:
    return bool(node.via) and "=" not in node.via


def referenced_names(obj: dict, via: str) -> list[str]:
    """Names referenced by ``obj`` through the ``via`` edge (handles ``a / b``)."""
    names: list[str] = []
    for token in via.split("/"):
        token = token.strip()
        if not token or "=" in token or " " in token:
            continue
        val = unwrap(attr(obj, token, token.replace("-", "_")))
        if isinstance(val, str) and val and val not in _EMPTY_REFS and val not in names:
            names.append(val)
    return names


def _row_key(row: dict) -> str:
    for k in ("name", "id", "_mkey"):
        v = row.get(k)
        if v not in (None, ""):
            return str(v)
    return ""


def scoped_rows(reader: Any, urn: str, logical: str | None, parent_mkey: str) -> list[dict]:
    """A by-parent sub-table's rows SCOPED to ``parent_mkey``.

    Prefer ``get_object(logical, parent)`` (the reliable ``?mkey=`` read); fall
    back to ``get_raw`` for in-memory test fakes. The path-style read leaks the
    WHOLE parent collection when the sub-table is empty (FortiWeb quirk)."""
    get_object = getattr(reader, "get_object", None)
    if logical and callable(get_object):
        rows = get_object(logical, parent_mkey)
        if isinstance(rows, dict):
            return [rows]
        if isinstance(rows, list):
            return [r for r in rows if isinstance(r, dict)]
    return reader.get_raw(urn, parent_mkey)


def _rich(node: DepNode) -> DepNode:
    """Splice the FULL WPP subtree wherever a node only names a profile."""
    if node.urn == _WPP_INLINE and not node.children:
        return WEB_PROTECTION_PROFILE
    return node


# --------------------------------------------------------------------------- #
#  Planner                                                                      #
# --------------------------------------------------------------------------- #
class ClonePlanner:
    """Builds (and validates) a clone plan for a dependency-tree root."""

    def __init__(self, src: Reader, dst: Reader) -> None:
        self.src = src
        self.dst = dst
        self.urn_index = registry_urn_index()  # collection -> logical

    def _lg(self, urn: str) -> str | None:
        """Logical name for a urn, matched on the normalised collection so a
        ``cmdb/…`` tree urn finds its ``/api/v2.0/cmdb/…`` registry entry."""
        return self.urn_index.get(objform.collection_of(urn))

    def _fetch(self, urn: str, mkey: str) -> dict:
        rows = scoped_rows(self.src, urn, self._lg(urn), mkey)
        if not rows and urn == _WPP_INLINE:
            rows = scoped_rows(self.src, _WPP_OFFLINE, self._lg(_WPP_OFFLINE), mkey)
        return rows[0] if rows else {}

    def _visit(
        self, node: DepNode, mkey: str, depth: int,
        items: list[CloneItem], visited: set[tuple[str, str]],
    ) -> None:
        if not mkey:
            return
        key = (node.urn, mkey)
        if key in visited:
            return
        visited.add(key)
        obj = self._fetch(node.urn, mkey)

        # 1) referenced named objects FIRST (deepest-first: deps before dependents)
        for child in node.children:
            if _is_named_ref(child):
                for ref in referenced_names(obj, child.via):
                    self._visit(_rich(child), ref, depth + 1, items, visited)

        # 2) THIS object
        items.append(CloneItem(
            label=node.fortiweb, urn=node.urn,
            logical=self._lg(node.urn), mkey=mkey,
            parent_mkey="", kind="object", depth=depth,
            payload=clean_for_write(obj) if obj else {},
        ))

        # 3) child sub-tables (by_parent), created AFTER this object.
        for child in node.children:
            if _is_named_ref(child) or not child.urn:
                continue
            for row in scoped_rows(self.src, child.urn, self._lg(child.urn), mkey) or []:
                for g in child.children:
                    if _is_named_ref(g):
                        for ref in referenced_names(row, g.via):
                            self._visit(_rich(g), ref, depth + 2, items, visited)
                items.append(CloneItem(
                    label="%s · %s" % (node.fortiweb, child.fortiweb), urn=child.urn,
                    logical=self._lg(child.urn), mkey=_row_key(row),
                    parent_mkey=mkey, kind="subrow", depth=depth + 1,
                    payload=clean_for_write(row),
                ))

    def _exists_at_dst(self, urn: str, mkey: str) -> bool:
        if not mkey:
            return False
        return bool(scoped_rows(self.dst, urn, self._lg(urn), mkey))

    def collect(self, root: DepNode, mkey: str, *, new_name: str = "") -> list[CloneItem]:
        """Walk the source tree and return every object + sub-table row WITH ITS
        LIVE PAYLOAD, deepest-first, WITHOUT destination classification."""
        items: list[CloneItem] = []
        self._visit(_rich(root), mkey, 0, items, set())

        if new_name:
            root_item = next(
                (it for it in items if it.depth == 0 and it.kind == "object"), None)
            if root_item is not None:
                old = root_item.mkey
                root_item.mkey = new_name
                if isinstance(root_item.payload, dict):
                    root_item.payload = {**root_item.payload, "name": new_name}
                if new_name != old:
                    for it in items:
                        if it.kind == "subrow" and it.parent_mkey == old:
                            it.parent_mkey = new_name
        return items

    def plan(self, root: DepNode, mkey: str, *, new_name: str = "") -> list[CloneItem]:
        """Walk the source tree and classify each item vs the destination."""
        items = self.collect(root, mkey, new_name=new_name)
        existing_parents: set[str] = set()
        created_parents: set[str] = set()
        for it in items:
            if it.urn in _CERT_URNS:
                it.status, it.note = "cert", "Certificate — SSH-only, not cloned over REST"
            elif not it.payload:
                it.status, it.note = "empty", "not found on source"
            elif it.logical is None:
                it.status, it.note = "no-endpoint", "no write endpoint in the registry"
            elif it.kind == "object" and self._exists_at_dst(it.urn, it.mkey):
                it.status, it.note = "exists", "already exists on destination"
                existing_parents.add(it.mkey)
            elif it.kind == "subrow" and it.parent_mkey not in created_parents:
                if it.parent_mkey in existing_parents:
                    it.status, it.note = "exists", "the parent already exists on destination"
                else:
                    it.status, it.note = "empty", "parent object is not being created"
            else:
                it.status = "create"
                if it.kind == "object":
                    created_parents.add(it.mkey)
        return items


# --------------------------------------------------------------------------- #
#  Apply                                                                        #
# --------------------------------------------------------------------------- #
def apply_clone(
    items: list[CloneItem],
    write: Callable[[CloneItem], None],
    *,
    dry_run: bool = True,
    on_log: OnLog = _NOOP,
) -> list[CloneItem]:
    """Create every ``create`` item via ``write`` (skipping the rest)."""
    for it in items:
        if it.status != "create":
            it.result = it.status
            continue
        if dry_run:
            it.result = "dry-run"
            on_log("[dry] create %s (%s)" % (it.label, it.mkey))
            continue
        try:
            write(it)
            it.applied, it.result = True, "created"
            on_log("created %s (%s)" % (it.label, it.mkey))
        except Exception as e:  # noqa: BLE001 — best-effort, keep going
            it.result = "error: %s: %s" % (type(e).__name__, e)
            on_log("error %s: %s" % (it.label, it.result))
    return items


# --------------------------------------------------------------------------- #
#  Plan post-processing                                                         #
# --------------------------------------------------------------------------- #
_STATUS_FIELDS = ("status", "enable", "enabled")


def disable_root(items: list[CloneItem]) -> None:
    """Leave the cloned ROOT object disabled (safe until manual cutover)."""
    for it in items:
        if it.depth == 0 and it.kind == "object" and isinstance(it.payload, dict):
            payload = {k: v for k, v in it.payload.items() if k not in _STATUS_FIELDS}
            payload["status"] = "disable"
            it.payload = payload
            return


# --------------------------------------------------------------------------- #
#  Summary helpers                                                              #
# --------------------------------------------------------------------------- #
_STATUS_LABELS = {
    "create": "to create",
    "exists": "already exists (skipped)",
    "cert": "certificate (SSH, skipped)",
    "no-endpoint": "no REST endpoint (skipped)",
    "empty": "empty on source (skipped)",
}


def summarize(items: list[CloneItem]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for it in items:
        counts[it.status] = counts.get(it.status, 0) + 1
    return counts


def render_plan(items: list[CloneItem]) -> str:
    marks = {"create": "+", "exists": "=", "cert": "lock", "no-endpoint": "!", "empty": "."}
    lines: list[str] = []
    for it in items:
        indent = "  " * it.depth
        mark = marks.get(it.status, "?")
        label = it.label + ("  " + it.mkey if it.mkey else "")
        suffix = "   - %s" % it.note if it.note and it.status != "create" else ""
        lines.append("%s %s%s%s" % (mark, indent, label, suffix))
    return "\n".join(lines)


def template_body(items: list[CloneItem], new_name: str) -> dict:
    """A multi-object template body (root + subobjects, deepest-first) from a
    collected clone — the desired-state snapshot saved to the template library.

    Mirrors the desktop ``node_to_template_body``: the ROOT object's payload is
    ``data``; every other collected item rides in ``subobjects`` (sub-objects
    FIRST = dependency order, which ``items`` already is)."""
    root = next((it for it in items if it.depth == 0 and it.kind == "object"), None)
    sub = [it for it in items if it is not root and it.payload]
    return {
        "endpoint": (root.logical or root.urn) if root else "",
        "mkey": new_name or (root.mkey if root else ""),
        "data": root.payload if root else {},
        "subobjects": [
            {
                "endpoint": it.logical or it.urn,
                "mkey": it.mkey,
                "parent_mkey": it.parent_mkey,
                "kind": it.kind,
                "data": it.payload,
            }
            for it in sub
        ],
    }


# Root nodes exposed by name.
ROOT_SERVER_POLICY = SERVER_POLICY
ROOT_WPP = WEB_PROTECTION_PROFILE


__all__ = [
    "CloneItem", "ClonePlanner", "ClientReader", "Reader",
    "apply_clone", "summarize", "render_plan", "referenced_names",
    "disable_root", "template_body", "registry_urn_index",
    "ROOT_SERVER_POLICY", "ROOT_WPP",
]
