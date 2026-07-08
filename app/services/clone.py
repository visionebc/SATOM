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

# The VIP address object — the one payload a clone rewrites when the copy must
# come up on a dummy IP (bulk clones, or the IP the operator typed).
_VIP_URN = "cmdb/system/vip"
_WPP_URNS = (_WPP_INLINE, _WPP_OFFLINE)

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
    verified: str = ""   # after a real clone: present | missing | unverifiable

    @property
    def will_create(self) -> bool:
        return self.status == "create"

    def to_dict(self) -> dict:
        return {
            "label": self.label, "urn": self.urn, "logical": self.logical,
            "mkey": self.mkey, "parent_mkey": self.parent_mkey, "kind": self.kind,
            "depth": self.depth, "status": self.status, "note": self.note,
            "result": self.result, "verified": self.verified,
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


def _content_keys(payload) -> list:
    """The distinguishing (business) fields of a by-parent row: scalar, non-empty,
    server-managed keys stripped, and the auto-assigned ``id`` excluded (it differs
    per box). These identify "the same row" across two appliances."""
    if not isinstance(payload, dict):
        return []
    clean = clean_for_write(payload)
    return [k for k, v in clean.items()
            if k != "id" and not isinstance(v, (dict, list)) and str(v) != ""]


def _subrow_in(payload, rows) -> bool:
    """Is a by-parent row with this CONTENT already present in ``rows``?

    Matched by business content (:func:`_content_keys`), NOT by ``id`` — sub-table
    ids are auto-assigned, so the same logical row has different ids on source vs
    destination. A row with no distinguishing content is treated as present (never
    recreate ⇒ never risk a duplicate)."""
    keys = _content_keys(payload)
    if not keys:
        return True
    clean_src = clean_for_write(payload)
    for r in rows:
        cr = clean_for_write(r) if isinstance(r, dict) else {}
        if all(str(clean_src.get(k, "")) == str(cr.get(k, "")) for k in keys):
            return True
    return False


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
        self._follow_wpp = True  # set per-plan; False prunes the WPP subtree

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
                if not self._follow_wpp and child.urn in _WPP_URNS:
                    continue  # "don't copy the WPP" — prune the whole subtree
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
                        if not self._follow_wpp and g.urn in _WPP_URNS:
                            continue  # content-routing rows can name a WPP too
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

    def _dst_subrows(self, urn: str, logical, parent_mkey: str):
        """Destination sub-table rows for (urn, parent), cached per ``plan()``.
        ``None`` means the destination could not be read (never recreate then)."""
        cache = getattr(self, "_subrow_cache", None)
        if cache is None:
            cache = self._subrow_cache = {}
        key = (urn, parent_mkey)
        if key not in cache:
            try:
                cache[key] = scoped_rows(self.dst, urn, logical, parent_mkey)
            except Exception:  # noqa: BLE001 — unreadable dst ⇒ assume present
                cache[key] = None
        return cache[key]

    def _subrow_exists_at_dst(self, it: "CloneItem") -> bool:
        """Is THIS by-parent row already present under its (existing) parent on the
        destination? The gap that left a partial clone's binding rows uncreated:
        a parent that survived a failed run existed, so its missing sub-rows were
        wrongly assumed present. Matched by content, so recovery re-clones only the
        rows that are genuinely absent."""
        rows = self._dst_subrows(it.urn, it.logical, it.parent_mkey)
        if rows is None:
            return True
        return _subrow_in(it.payload, rows)

    def collect(self, root: DepNode, mkey: str, *, new_name: str = "",
                follow_wpp: bool = True) -> list[CloneItem]:
        """Walk the source tree and return every object + sub-table row WITH ITS
        LIVE PAYLOAD, deepest-first, WITHOUT destination classification."""
        items: list[CloneItem] = []
        self._follow_wpp = follow_wpp
        try:
            self._visit(_rich(root), mkey, 0, items, set())
        finally:
            self._follow_wpp = True

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

    def plan(self, root: DepNode, mkey: str, *, new_name: str = "",
             follow_wpp: bool = True, wpp_new_name: str = "",
             wpp_suffix: str = "") -> list[CloneItem]:
        """Walk the source tree and classify each item vs the destination.

        ``follow_wpp=False`` prunes the Web Protection Profile subtree (the copy
        keeps naming the profile — the destination must already have it).
        ``wpp_new_name`` re-labels the copied WPP (and re-points the root
        policy's reference) so a differing same-name profile on the destination
        is never silently reused; ``wpp_suffix`` does the same per-profile
        (``<wpp>-suffix``) — the bulk form, where one fixed name would collide
        across policies binding different profiles."""
        items = self.collect(root, mkey, new_name=new_name, follow_wpp=follow_wpp)
        self._subrow_cache = {}
        if follow_wpp and (wpp_new_name or wpp_suffix):
            wpp = next((it for it in items
                        if it.urn in _WPP_URNS and it.kind == "object"), None)
            if wpp is not None:
                rename_wpp(items, wpp_new_name or (wpp.mkey + wpp_suffix))
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
                    if self._subrow_exists_at_dst(it):
                        it.status, it.note = "exists", "row already present under the existing parent"
                    else:
                        it.status, it.note = "create", "missing under an existing parent \u2014 recreating"
                else:
                    it.status, it.note = "empty", "parent object is not being created"
            else:
                it.status = "create"
                if it.kind == "object":
                    created_parents.add(it.mkey)
        return items
def validate_completeness(items: list["CloneItem"]) -> list[dict]:
    """Referential-completeness gate over a LIVE-collected tree. Returns the
    BLOCKING issues: every ``object`` node that was referenced on the source but
    whose live payload came back empty (renamed, deleted, or the read did not
    resolve). Certificates are exempt \u2014 their key material never travels over
    REST, so an empty cert payload is expected, not a gap. Empty by-parent
    sub-tables are trusted: the caller only validates a tree collected from a
    source that already answered live + healthy, so an empty sub-table is a real
    empty table, not a failed read (which the caller blocks upstream)."""
    # A name that resolved on ANY node covers the predefined -> custom fallback
    # (a policy naming "HTTP" visits service.predefined [resolves] AND
    # service.custom [empty]; the empty one is not a gap). Only a name that
    # resolved NOWHERE is a real missing object.
    resolved = {it.mkey for it in items
                if it.kind == "object" and it.payload and it.urn not in _CERT_URNS}
    issues: list[dict] = []
    seen: set[str] = set()
    for it in items:
        if it.kind != "object" or it.urn in _CERT_URNS:
            continue
        if it.payload or it.mkey in resolved or it.mkey in seen:
            continue
        seen.add(it.mkey)
        issues.append({
            "object": it.label, "mkey": it.mkey, "urn": it.urn,
            "reason": "referenced on the source tree but not found live "
                      "(renamed, deleted, or unreadable)",
        })
    return issues




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


def vip_items(items: list[CloneItem]) -> list[CloneItem]:
    """The VIP address objects in a plan (source of the current IPs)."""
    return [it for it in items if it.urn == _VIP_URN and it.kind == "object"]


def set_vip_ip(items: list[CloneItem], ip: str = "",
               transform: Callable[[str], str] | None = None) -> list[str]:
    """Rewrite every TO-CREATE VIP's address, keeping its mask.

    ``ip``        — one explicit address for all VIPs (the single-policy dialog).
    ``transform`` — per-VIP mapping old-IP → new-IP (the bulk dummy rules).

    Only ``create`` items are touched — a VIP that already exists on the
    destination is never mutated. Returns the list of ``old → new`` notes."""
    changed: list[str] = []
    for it in items:
        if it.urn != _VIP_URN or it.kind != "object" or it.status != "create":
            continue
        if not isinstance(it.payload, dict):
            continue
        cur = str(it.payload.get("vip") or "")
        cur_ip, _, mask = cur.partition("/")
        new_ip = ip or (transform(cur_ip) if transform else "")
        if not new_ip or new_ip == cur_ip:
            continue
        it.payload = {**it.payload, "vip": new_ip + (("/" + mask) if mask else "")}
        it.note = (it.note + " · " if it.note else "") + "IP %s → %s" % (cur_ip or "?", new_ip)
        changed.append("%s: %s → %s" % (it.mkey, cur_ip or "?", new_ip))
    return changed


def rename_wpp(items: list[CloneItem], new_name: str) -> str:
    """Re-label the copied Web Protection Profile as ``new_name`` and re-point
    every reference to it (the root policy's ``web-protection-profile`` field,
    content-routing rows, and any WPP-owned sub-rows). Returns the old name
    ('' when the plan carries no WPP)."""
    wpp = next((it for it in items if it.urn in _WPP_URNS and it.kind == "object"), None)
    if wpp is None or not new_name or new_name == wpp.mkey:
        return ""
    old = wpp.mkey
    wpp.mkey = new_name
    if isinstance(wpp.payload, dict):
        wpp.payload = {**wpp.payload, "name": new_name}
    for it in items:
        if it.kind == "subrow" and it.urn.startswith(wpp.urn) and it.parent_mkey == old:
            it.parent_mkey = new_name
        if it.kind in ("object", "subrow") and isinstance(it.payload, dict) \
                and it.urn not in _WPP_URNS \
                and it.payload.get("web-protection-profile") == old:
            it.payload = {**it.payload, "web-protection-profile": new_name}
    return old


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


# --------------------------------------------------------------------------- #
#  Clone RESULT reconciliation (what was planned vs created vs verified live)    #
# --------------------------------------------------------------------------- #
def verify_created(items: list[CloneItem], reader: Any) -> list[CloneItem]:
    """Re-read the DESTINATION for every item we actually created and annotate
    it ``present`` | ``missing`` | ``unverifiable``. Best-effort and read-only —
    a device that can't be read (license flap) yields ``unverifiable``, never an
    exception. This is the post-apply confirmation the operator asked for: the
    box, not our optimism, is the source of truth about what landed."""
    for it in items:
        if not it.applied:
            continue
        try:
            if it.kind == "subrow":
                rows = scoped_rows(reader, it.urn, it.logical, it.parent_mkey)
                found = _subrow_in(it.payload, rows)
            else:
                rows = scoped_rows(reader, it.urn, it.logical, it.mkey)
                found = bool(rows)
            it.verified = "present" if found else "missing"
        except Exception:  # noqa: BLE001 — verification never sinks the clone
            it.verified = "unverifiable"
    return items


def outcome(items: list[CloneItem]) -> dict:
    """A JSON-able reconciliation of a planned/applied clone: the full item list
    plus the three buckets the operator compares — what SHOULD have been created
    (``planned_create``), what WAS created (``created``, with the live-verify
    verdict), and what FAILED (``failed``, with the device error). Feeds the
    clone-result report page linked from the job."""
    def row(it: CloneItem) -> dict:
        d = it.to_dict()
        d["applied"] = bool(it.applied)
        return d
    rows = [row(it) for it in items]
    created = [r for r in rows if r["applied"]]
    return {
        "total": len(rows),
        "counts": summarize(items),
        "items": rows,
        "planned_create": [r for r in rows if r["status"] == "create"],
        "created": created,
        "failed": [r for r in rows if (r["result"] or "").startswith("error")],
        "verified_missing": [r for r in created if r.get("verified") == "missing"],
        "unverifiable": [r for r in created if r.get("verified") == "unverifiable"],
    }


# Root nodes exposed by name.
ROOT_SERVER_POLICY = SERVER_POLICY
ROOT_WPP = WEB_PROTECTION_PROFILE


__all__ = [
    "CloneItem", "ClonePlanner", "ClientReader", "Reader",
    "apply_clone", "summarize", "render_plan", "referenced_names",
    "disable_root", "template_body", "registry_urn_index",
    "outcome", "verify_created",
    "ROOT_SERVER_POLICY", "ROOT_WPP", "validate_completeness",
]
