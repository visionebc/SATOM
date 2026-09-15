"""FortiWeb **structure catalog** — the shape of a config, cross-referenced
against the endpoint registry.

Port of the desktop ``services/structure.py``. The built-in dependency tree from
:mod:`app.registry.dependencies` (the in-repo capture of the USB exporter) is the
**seed**. On top of it the app applies a small, admin-editable **overlay**
(add / edit / remove / reorder elements and sub-elements, plus a function
inventory delta) so the shape can be tweaked without touching code. An empty
overlay renders exactly like ``dependencies.ROOTS``.

This is the layer that ties the dependency tree to the **endpoint registry**:
for every node carrying a REST ``urn`` it resolves the matching ``endpoints.yaml``
logical name (via :mod:`app.registry.loader`), which powers the coverage
cross-reference (matched / fetchable / missing) the Structure page shows.

URN-format bridge. The dependency tree stores bare URNs (``cmdb/waf/signature``)
while the registry stores fully-qualified ones (``/api/v2.0/cmdb/waf/signature``).
:func:`_normalize_urn` strips the ``/api/v2.X/`` prefix so the two conventions
compare, and :func:`_base_urn` additionally drops a trailing ``.action`` suffix
so e.g. ``web-protection-profile.inline-protection`` matches the registry's
``web-protection-profile``.

Pure data + matching — no Qt, no network. The registry file is only read lazily,
when :func:`load_catalog` is called at request time (never at import).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterator

from ..registry import dependencies as deps
from ..registry import loader

# The overlay keys the catalog understands (a single overlay, not version-keyed —
# the web registry is a flat endpoints.yaml, not version-aware like the desktop).
_OVERLAY_KEYS = ("added", "edited", "removed", "order", "functions")
_EDITABLE_FIELDS = ("label", "urn", "via", "section", "endpoint")


# --------------------------------------------------------------------------- #
#  Node model (a value-free superset of dependencies.DepNode)                  #
# --------------------------------------------------------------------------- #
@dataclass
class StructureNode:
    """One object in the editable structure tree.

    ``key`` is a stable slug unique among its siblings — it addresses the node in
    the overlay (a slash-joined key-path such as
    ``web-protection-profile/signatures``). ``label`` is the FortiWeb GUI name,
    ``urn`` the REST path, ``via`` the parent field, ``section`` the GUI
    section/note, ``endpoint`` the registry logical name resolved from ``urn``
    (blank when the URN isn't in the registry). ``builtin`` marks nodes that came
    from the ``dependencies.py`` seed.
    """

    key: str
    label: str
    urn: str = ""
    via: str = ""
    section: str = ""
    endpoint: str = ""
    builtin: bool = False
    children: list["StructureNode"] = field(default_factory=list)
    #: Set only on nodes synthesised from a CLI configuration dump. ``cli_path``
    #: is the ``config …`` block that produced the node; the others describe how
    #: much configuration it actually holds on the box that was dumped. They are
    #: real fields rather than attributes bolted on at build time so that a
    #: template asking for them on a seed node gets the neutral default instead
    #: of an AttributeError at render time.
    cli_path: str = ""
    cli_configured: bool = False
    cli_instances: int = 0
    cli_settings: int = 0

    @property
    def in_registry(self) -> bool:
        """True when this node's URN resolves to a registry endpoint."""
        return bool(self.endpoint)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"key": self.key, "label": self.label}
        for f in ("urn", "via", "section", "endpoint"):
            v = getattr(self, f)
            if v:
                d[f] = v
        if self.children:
            d["children"] = [c.to_dict() for c in self.children]
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any], *, builtin: bool = False) -> "StructureNode":
        label = d.get("label", "")
        return cls(
            key=d.get("key") or _slug(label),
            label=label,
            urn=d.get("urn", ""),
            via=d.get("via", ""),
            section=d.get("section", ""),
            endpoint=d.get("endpoint", ""),
            builtin=builtin,
            children=[cls.from_dict(c, builtin=builtin) for c in d.get("children", []) or []],
        )


@dataclass
class FunctionEntry:
    """An editable mirror of ``dependencies.ExporterFunc`` (the function inventory)."""

    name: str
    role: str
    ported: str = ""
    builtin: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "role": self.role, "ported": self.ported}

    @classmethod
    def from_dict(cls, d: dict[str, Any], *, builtin: bool = False) -> "FunctionEntry":
        return cls(d.get("name", ""), d.get("role", ""), d.get("ported", ""), builtin=builtin)


def _slug(label: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (label or "").strip().lower()).strip("-")
    return s or "node"


# --------------------------------------------------------------------------- #
#  Registry cross-reference — ties the tree to the endpoint library            #
# --------------------------------------------------------------------------- #
_API_PREFIX_RE = re.compile(r"^/?api/v[0-9][0-9.]*/")


def _normalize_urn(urn: str) -> str:
    """Bridge the two URN conventions: strip a ``/api/v2.X/`` prefix and any
    leading slash so a registry URN (``/api/v2.0/cmdb/waf/signature``) compares
    equal to a dependency-tree URN (``cmdb/waf/signature``).
    """
    s = (urn or "").split("?")[0]
    s = _API_PREFIX_RE.sub("", s)
    return s.lstrip("/")


def _base_urn(norm: str) -> str:
    """Drop a trailing ``.action`` on the final path segment so e.g.
    ``cmdb/waf/web-protection-profile.inline-protection`` reduces to
    ``cmdb/waf/web-protection-profile`` (the form the registry usually stores).
    """
    if not norm:
        return norm
    head, _, tail = norm.rpartition("/")
    tail = tail.split(".")[0]
    return f"{head}/{tail}" if head else tail


def registry_urn_index(endpoints: list[dict] | None = None) -> dict[str, str]:
    """``{normalized_urn: logical endpoint name}`` for every registry endpoint.

    Both the exact normalized URN and its action-stripped base form are indexed
    (exact wins) so a dependency node matches whether or not it carries a
    ``.action`` suffix. ``endpoints`` defaults to ``loader.get_all_endpoints()``.
    """
    if endpoints is None:
        endpoints = loader.get_all_endpoints()
    index: dict[str, str] = {}
    for ep in endpoints:
        name = ep.get("name", "")
        norm = _normalize_urn(ep.get("urn") or ep.get("path") or "")
        if not norm:
            continue
        index.setdefault(norm, name)
        index.setdefault(_base_urn(norm), name)
    return index


def _endpoint_for(index: dict[str, str], urn: str) -> str:
    """The registry logical name backing ``urn`` (exact then base match), or ""."""
    if not urn:
        return ""
    norm = _normalize_urn(urn)
    return index.get(norm) or index.get(_base_urn(norm), "")


# --------------------------------------------------------------------------- #
#  Seed adapter — reuse dependencies.py, never duplicate it                     #
# --------------------------------------------------------------------------- #
def from_depnode(dn: deps.DepNode, _sibling_keys: set[str] | None = None) -> StructureNode:
    """Convert a built-in ``DepNode`` (+ its subtree) into a ``StructureNode``.

    Sibling keys are de-duplicated (``-2`` …) so overlay key-paths stay unique.
    ``endpoint`` is left blank here and filled in one pass by
    :func:`_resolve_endpoints` so resolution is centralised.
    """
    sibs = _sibling_keys if _sibling_keys is not None else set()
    key = base = _slug(dn.fortiweb)
    i = 2
    while key in sibs:
        key = f"{base}-{i}"
        i += 1
    sibs.add(key)
    node = StructureNode(
        key=key,
        label=dn.fortiweb,
        urn=dn.urn,
        via=dn.via,
        section=dn.note,
        builtin=True,
    )
    child_sibs: set[str] = set()
    node.children = [from_depnode(c, child_sibs) for c in dn.children]
    return node


def seed_tree() -> list[StructureNode]:
    """The built-in dependency tree as editable nodes (one per ``dependencies.ROOTS``)."""
    root_sibs: set[str] = set()
    return [from_depnode(r, root_sibs) for r in deps.ROOTS]


def seed_functions() -> list[FunctionEntry]:
    """The built-in exporter function inventory as editable entries."""
    return [
        FunctionEntry(f.name, f.role, f.ported, builtin=True)
        for f in deps.EXPORTER_FUNCTIONS
    ]


# --------------------------------------------------------------------------- #
#  Traversal + path addressing                                                 #
# --------------------------------------------------------------------------- #
def iter_nodes(nodes: list[StructureNode]) -> Iterator[tuple[int, StructureNode]]:
    """Yield ``(depth, node)`` pre-order; roots are depth 0."""

    def _walk(ns: list[StructureNode], depth: int) -> Iterator[tuple[int, StructureNode]]:
        for n in ns:
            yield depth, n
            yield from _walk(n.children, depth + 1)

    yield from _walk(nodes, 0)


def node_count(nodes: list[StructureNode]) -> int:
    return sum(1 for _ in iter_nodes(nodes))


def find(nodes: list[StructureNode], path: str) -> StructureNode | None:
    """The node at a slash-joined key-path (``""`` => None)."""
    keys = [k for k in path.split("/") if k] if path else []
    if not keys:
        return None
    cur = nodes
    node: StructureNode | None = None
    for k in keys:
        node = next((n for n in cur if n.key == k), None)
        if node is None:
            return None
        cur = node.children
    return node


def _sibling_list(nodes: list[StructureNode], path: str) -> list[StructureNode] | None:
    """The list that holds the node at ``path`` (its parent's children, or roots)."""
    keys = [k for k in path.split("/") if k] if path else []
    if not keys:
        return None
    if len(keys) == 1:
        return nodes
    parent = find(nodes, "/".join(keys[:-1]))
    return parent.children if parent else None


# --------------------------------------------------------------------------- #
#  Overlay application (seed + deltas -> merged tree)                           #
# --------------------------------------------------------------------------- #
def _added_path(entry: dict[str, Any]) -> str:
    parent = entry.get("parent", "") or ""
    key = (entry.get("node") or {}).get("key", "")
    return f"{parent}/{key}" if parent else key


def _apply_overlay(nodes: list[StructureNode], overlay: dict[str, Any]) -> None:
    """Mutate ``nodes`` in place: added -> edited -> removed -> reorder.

    Tolerant of dangling paths (a seed change that orphans an overlay entry just
    skips it) so the page never crashes on stale data.
    """
    for entry in overlay.get("added", []) or []:
        parent_path = entry.get("parent", "") or ""
        new = StructureNode.from_dict(entry.get("node") or {}, builtin=False)
        if not parent_path:
            nodes.append(new)
        else:
            parent = find(nodes, parent_path)
            if parent is not None:
                parent.children.append(new)

    for path, fields in (overlay.get("edited") or {}).items():
        node = find(nodes, path)
        if node is None:
            continue
        for f in _EDITABLE_FIELDS:
            if f in fields:
                setattr(node, f, fields[f])

    for path in overlay.get("removed", []) or []:
        siblings = _sibling_list(nodes, path)
        if siblings is None:
            continue
        key = path.split("/")[-1]
        siblings[:] = [n for n in siblings if n.key != key]

    for parent_path, order in (overlay.get("order") or {}).items():
        siblings = nodes if not parent_path else (
            find(nodes, parent_path).children if find(nodes, parent_path) else None
        )
        if not siblings:
            continue
        rank = {k: i for i, k in enumerate(order)}
        siblings.sort(key=lambda n: rank.get(n.key, len(rank)))


def _resolve_endpoints(nodes: list[StructureNode], index: dict[str, str]) -> None:
    """Fill ``node.endpoint`` for every node from the registry index, so the
    cross-reference reflects the *actual* registry (seed and overlay nodes alike).
    """
    for _depth, node in iter_nodes(nodes):
        node.endpoint = _endpoint_for(index, node.urn)


# --------------------------------------------------------------------------- #
#  Rendering (same styles as dependencies.py, but over StructureNode)          #
# --------------------------------------------------------------------------- #
def render_box(nodes: list[StructureNode], *, show_urn: bool = False) -> str:
    """The exporter's ``├──/└──`` box style. On the pure seed this is identical to
    ``dependencies.render_tree_box``.
    """
    lines: list[str] = []

    def _label(n: StructureNode) -> str:
        return f"{n.label}   ({n.urn})" if show_urn and n.urn else n.label

    def _walk(ns: list[StructureNode], prefix: str) -> None:
        for i, n in enumerate(ns):
            last = i == len(ns) - 1
            lines.append(f"{prefix}{'└── ' if last else '├── '}{_label(n)}")
            if n.children:
                _walk(n.children, prefix + ("    " if last else "│   "))

    for idx, root in enumerate(nodes):
        lines.append(_label(root))
        _walk(root.children, "")
        if idx != len(nodes) - 1:
            lines.append("")
    return "\n".join(lines)


def render_arrows(nodes: list[StructureNode], *, show_urn: bool = True) -> str:
    """The lighter ``-->`` arrow style (mirrors ``dependencies.render_tree``)."""
    lines: list[str] = []
    for depth, node in iter_nodes(nodes):
        prefix = "" if depth == 0 else ("-" * (depth + 1) + "> ")
        line = f"{prefix}{node.label}"
        if show_urn and node.urn:
            line += f"   ({node.urn})"
        lines.append(line)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
#  Cross-reference + coverage over a built tree                                 #
# --------------------------------------------------------------------------- #
def coverage(nodes: list[StructureNode]) -> tuple[int, int, list[str]]:
    """``(matched, fetchable, missing_urns)`` over the tree.

    *fetchable* counts nodes that carry a URN; *matched* those whose URN resolves
    to a registry endpoint. A URN that isn't in the registry is a dependency the
    library doesn't cover yet — exactly the gap this analysis exposes.
    """
    matched = fetchable = 0
    missing: list[str] = []
    for _depth, node in iter_nodes(nodes):
        if not node.urn:
            continue
        fetchable += 1
        if node.endpoint:
            matched += 1
        elif node.urn not in missing:
            missing.append(node.urn)
    return matched, fetchable, missing


def cross_reference(nodes: list[StructureNode]) -> list[dict[str, Any]]:
    """One display row per node: object label (depth-indented), URN, via, section,
    resolved endpoint and a coverage ``status`` (``matched`` / ``missing`` /
    ``none`` for grouping nodes that carry no URN).
    """
    rows: list[dict[str, Any]] = []
    for depth, node in iter_nodes(nodes):
        if not node.urn:
            status = "none"
        elif node.endpoint:
            status = "matched"
        else:
            status = "missing"
        rows.append({
            "depth": depth,
            "label": node.label,
            "urn": node.urn,
            "via": node.via,
            "section": node.section,
            "endpoint": node.endpoint,
            "builtin": node.builtin,
            "status": status,
        })
    return rows


# --------------------------------------------------------------------------- #
#  Overlay validation (for the admin save path)                                 #
# --------------------------------------------------------------------------- #
def _clean_node_dict(d: Any) -> dict[str, Any]:
    """Coerce an arbitrary value into a well-formed structure-node dict."""
    if not isinstance(d, dict):
        raise ValueError("each node must be a JSON object")
    label = str(d.get("label", "")).strip()
    if not label:
        raise ValueError("each node needs a non-empty 'label'")
    node: dict[str, Any] = {"key": _slug(str(d.get("key") or label)), "label": label}
    for f in ("urn", "via", "section", "endpoint"):
        v = d.get(f)
        if isinstance(v, str) and v.strip():
            node[f] = v.strip()
    children = d.get("children")
    if isinstance(children, list) and children:
        node["children"] = [_clean_node_dict(c) for c in children]
    return node


def validate_overlay(raw: Any) -> dict[str, Any]:
    """Validate + normalise an arbitrary value into the overlay schema the catalog
    understands. Raises ``ValueError`` on a non-object so the view can flash it.
    Unknown keys are dropped; missing keys default empty.
    """
    if not isinstance(raw, dict):
        raise ValueError("overlay must be a JSON object")

    added: list[dict[str, Any]] = []
    for entry in raw.get("added") or []:
        if not isinstance(entry, dict):
            continue
        added.append({
            "parent": str(entry.get("parent", "") or ""),
            "node": _clean_node_dict(entry.get("node") or {}),
        })

    edited: dict[str, Any] = {}
    for path, fields in (raw.get("edited") or {}).items():
        if not isinstance(fields, dict):
            continue
        clean = {k: str(v) for k, v in fields.items() if k in _EDITABLE_FIELDS}
        if clean:
            edited[str(path)] = clean

    removed = [str(p) for p in (raw.get("removed") or []) if str(p).strip()]

    order: dict[str, Any] = {}
    for parent_path, keys in (raw.get("order") or {}).items():
        if isinstance(keys, list):
            order[str(parent_path)] = [str(k) for k in keys]

    fns_raw = raw.get("functions") or {}
    functions = {
        "added": [
            FunctionEntry.from_dict(d).to_dict()
            for d in (fns_raw.get("added") or []) if isinstance(d, dict)
        ],
        "edited": {
            str(name): {k: str(v) for k, v in fields.items() if k in ("role", "ported")}
            for name, fields in (fns_raw.get("edited") or {}).items()
            if isinstance(fields, dict)
        },
        "removed": [str(n) for n in (fns_raw.get("removed") or []) if str(n).strip()],
    }

    return {"added": added, "edited": edited, "removed": removed,
            "order": order, "functions": functions}


# --------------------------------------------------------------------------- #
#  The catalog — seed + overlay + registry cross-reference                      #
# --------------------------------------------------------------------------- #
class StructureCatalog:
    """A view over the built-in seed + an overlay, cross-referenced against the
    endpoint registry. Cheap to build; the registry index is captured once.
    """

    def __init__(self, endpoints: list[dict] | None = None,
                 overlay: dict[str, Any] | None = None) -> None:
        self._index = registry_urn_index(endpoints)
        self.overlay = overlay or {}

    def tree(self) -> list[StructureNode]:
        """The merged tree (seed + overlay) with endpoints resolved."""
        nodes = seed_tree()
        if self.overlay:
            _apply_overlay(nodes, self.overlay)
        _resolve_endpoints(nodes, self._index)
        return nodes

    def functions(self) -> list[FunctionEntry]:
        """The exporter function inventory (seed + overlay delta)."""
        funcs = seed_functions()
        ov = (self.overlay or {}).get("functions") or {}
        removed = set(ov.get("removed", []) or [])
        funcs = [f for f in funcs if f.name not in removed]
        edited = ov.get("edited") or {}
        for f in funcs:
            if f.name in edited:
                fields = edited[f.name]
                f.role = fields.get("role", f.role)
                f.ported = fields.get("ported", f.ported)
        for d in ov.get("added", []) or []:
            funcs.append(FunctionEntry.from_dict(d, builtin=False))
        return funcs

    def coverage(self) -> tuple[int, int, list[str]]:
        return coverage(self.tree())


def load_catalog(overlay: dict[str, Any] | None = None) -> StructureCatalog:
    """The catalog the page uses: built-in seed + the supplied overlay, with the
    registry index built from ``endpoints.yaml`` (read lazily here, never at
    import time). The overlay is normally ``settings_store.get_json(
    'structure.overlay', {})`` passed in by the view.
    """
    return StructureCatalog(loader.get_all_endpoints(), overlay or {})


# --------------------------------------------------------------------------- #
#  CLI-only elements — the part of the shape the dependency tree cannot see     #
# --------------------------------------------------------------------------- #
# The seed tree was captured from the exporter, which walks REST. Anything the
# REST catalog never names is therefore absent from it BY CONSTRUCTION — not
# because it does not exist on the box, but because the instrument that built
# the tree could not see it. ``cli_coverage`` measures exactly that set.
#
# THEY GET THEIR OWN ROOT, and this is the load-bearing decision. A CLI block
# has no ``via`` — no field on a parent object references it — because these are
# global/system tables, not children of a Server Policy. Grafting them into the
# WPP or Server-Policy subtree would mean INVENTING that edge, and this repo
# already measured what an invented edge costs: ``dependencies.py`` records that
# a payload carrying a reference the destination cannot resolve is rejected by
# the appliance with HTTP 500 and no message. A separate root says "these exist,
# and we do not know where they hang" — which is the truth.

#: Key/label of the synthetic root the CLI-only elements hang from.
CLI_ROOT_KEY = "cli-only"
CLI_ROOT_LABEL = "CLI-only configuration (no REST endpoint in the catalog)"

#: Status a cross-reference row carries when it came from the CLI dump. A value
#: of its own, never ``missing``: ``missing`` means "the tree names a URN the
#: catalog lacks", and this means "there is no URN at all".
STATUS_CLI = "cli-only"


def tree_urns(nodes: list[StructureNode]) -> set[str]:
    """Every normalised URN the tree addresses (for de-duplication)."""
    out: set[str] = set()
    for _d, n in iter_nodes(nodes):
        if n.urn:
            out.add(_normalize_urn(n.urn))
            out.add(_base_urn(_normalize_urn(n.urn)))
    return out


def cli_only_nodes(diff: dict[str, Any], *,
                   configured_only: bool = False) -> list[StructureNode]:
    """The CLI-only blocks of a coverage diff, as one synthetic root.

    Grouped by CLI family (``system``, ``waf``, ``router``…) so ~50 blocks read
    as a shape instead of a flat list. ``urn`` is left EMPTY on purpose: these
    blocks have no REST path, and writing a derived one here would put a guess
    in the same column as the measured URNs above it. The CLI path travels in
    ``section``, which is where the tree already carries "where does this live".
    """
    rows = list((diff or {}).get("cli_only") or [])
    if configured_only:
        rows = [r for r in rows if r.get("configured")]
    if not rows:
        return []

    families: dict[str, StructureNode] = {}
    order: list[str] = []
    for rec in sorted(rows, key=lambda r: r.get("path") or ""):
        path = rec.get("path") or ""
        words = path.split()
        if not words:
            continue
        fam = words[0]
        if fam not in families:
            families[fam] = StructureNode(key=_slug(fam), label=fam,
                                          section="CLI family")
            order.append(fam)
        leaf = StructureNode(
            key=_slug(" ".join(words[1:]) or fam),
            label=" ".join(words[1:]) or fam,
            section=path,
        )
        # Carried as plain attributes so the template can badge them without a
        # parallel dict keyed by label — two containers for one row is how a
        # table starts showing another row's numbers.
        leaf.cli_path = path
        leaf.cli_configured = bool(rec.get("configured"))
        leaf.cli_instances = int(rec.get("instances") or 0)
        leaf.cli_settings = len(rec.get("settings") or ())
        families[fam].children.append(leaf)

    root = StructureNode(key=CLI_ROOT_KEY, label=CLI_ROOT_LABEL,
                         section="from the CLI configuration dump")
    root.children = [families[f] for f in order]
    return [root]


def cli_cross_reference(nodes: list[StructureNode]) -> list[dict[str, Any]]:
    """Display rows for the CLI-only subtree.

    Same shape as :func:`cross_reference` plus the CLI-specific columns, so one
    template macro renders both tables and they cannot drift into describing the
    same thing two ways.
    """
    rows: list[dict[str, Any]] = []
    for depth, node in iter_nodes(nodes):
        cli_path = getattr(node, "cli_path", "")
        rows.append({
            "depth": depth,
            "label": node.label,
            "urn": "",
            "via": "",
            "section": node.section,
            "endpoint": "",
            "builtin": False,
            "status": STATUS_CLI if cli_path else "none",
            "cli_path": cli_path,
            "configured": bool(getattr(node, "cli_configured", False)),
            "instances": int(getattr(node, "cli_instances", 0)),
            "settings": int(getattr(node, "cli_settings", 0)),
        })
    return rows


def clone_gap(diff: dict[str, Any]) -> list[dict[str, Any]]:
    """What a clone of this device would NOT carry, and why — stated, not implied.

    A clone recreates objects over REST (``clone.apply_clone`` writes through
    ``FortiWebOps``). A block with no REST endpoint therefore cannot be written
    by it at all, and a block that is not in the dependency tree is never even
    VISITED — so today its absence from a cloned device is silent. This list is
    that silence, printed.

    Only blocks that HOLD configuration are listed. An empty table is a catalog
    gap but not a clone gap: there is nothing on the source to carry.
    """
    out: list[dict[str, Any]] = []
    for rec in sorted((diff or {}).get("cli_only") or [],
                      key=lambda r: r.get("path") or ""):
        if not rec.get("configured"):
            continue
        out.append({
            "path": rec.get("path") or "",
            "instances": int(rec.get("instances") or 0),
            "settings": len(rec.get("settings") or ()),
            "reason": ("no REST endpoint in the catalog — a clone writes over "
                       "REST, so this is not carried"),
        })
    return out


def overlay_snippet(cli_path: str, urn: str, *, via: str = "",
                    label: str = "") -> dict[str, Any]:
    """The overlay entry that would move a promoted block INTO the tree.

    Deliberately a snippet the operator pastes and edits rather than a write:
    the missing piece is ``via`` — the field on the parent that references this
    object — and only a human who has read the parent's schema knows it. A tool
    that filled it in with a plausible guess would produce a tree that looks
    complete and a clone that the appliance rejects.
    """
    words = (cli_path or "").split()
    return {
        "path": "",
        "label": label or (" ".join(words[1:]) or cli_path),
        "urn": urn,
        "via": via,
        "section": "promoted from the CLI dump (%s)" % cli_path,
    }


__all__ = [
    "StructureNode",
    "FunctionEntry",
    "StructureCatalog",
    "from_depnode",
    "seed_tree",
    "seed_functions",
    "iter_nodes",
    "node_count",
    "find",
    "render_box",
    "render_arrows",
    "registry_urn_index",
    "coverage",
    "cross_reference",
    "validate_overlay",
    "load_catalog",
    "CLI_ROOT_KEY",
    "CLI_ROOT_LABEL",
    "STATUS_CLI",
    "tree_urns",
    "cli_only_nodes",
    "cli_cross_reference",
    "clone_gap",
    "overlay_snippet",
]
