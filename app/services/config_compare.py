"""Full source↔destination comparison of a service, from a list of
``source;policy;destination`` lines.

The operator has the same file the Backend Reachability page takes, and a
different question: **is this service configured the SAME on both boxes, and if
not, exactly what differs?** Nothing here writes. Not to an appliance, not to
the database. It reads two dependency trees and subtracts them.

WHY IT IS NOT A SECOND CLONE PLANNER
    The walk is :meth:`clone.ClonePlanner.collect` — the same one the clone
    dialog and the cascade-delete planner use, and the only thing in the
    product that knows which fields of a FortiWeb object are references. A
    second walk here would let this page and the clone report disagree about
    what a service even CONSISTS OF, which is the one thing they must never do.
    What this module owns is the SUBTRACTION: pairing, field diffing, the
    package rule for WPPs, and the per-line verdict.

THE FOUR RULES THIS FILE EXISTS TO HOLD

    1. **Counterparts are paired by ROLE, not by name.** A cross-box clone
       routinely lands the web-protection profile under a different name
       (:func:`clone.wpp_landing_name`), and pool/vserver names drift too.
       Pairing on the name would report the SAME object as "missing on the
       destination" plus "extra on the destination" — two false findings that
       hide the real answer. Objects reached from the same parent through the
       same reference field are counterparts; a name difference between them is
       a *reported difference*, never a failure to match.

    2. **A WPP is compared as ONE PACKAGE.** Never entry by entry. An inline
       protection profile drags in a dozen sub-profiles and each of those can
       hold hundreds of rows; rendering that as rows produces a report nobody
       reads, and a signature list that legitimately tracks a different FortiGuard
       revision would drown the one field that matters. The package is reduced to
       a fingerprint plus WHICH sub-profiles differ and by how much.

    3. **The diff is symmetric.** :func:`clone.subrow_diff` deliberately looks
       only at fields the source carries, because it answers "what would I have
       to write?". This page answers "how do these two differ?", and a field the
       DESTINATION carries alone is exactly as much of a difference as one the
       source carries alone. Reusing the write-shaped diff here would silently
       hide every destination-only setting.

    4. **Nothing is dropped silently.** Over-limit lines, the format header,
       lines skipped when the time budget expired and subtrees that could not be
       read are each reported by name. A comparison that quietly covered less
       than it was asked to reads exactly like a clean run — which is the worst
       possible failure for a tool whose whole output is "these are the same".
"""
from __future__ import annotations

import hashlib
import json
import time

from . import clone as _clone
from .reach_batch import build_index, parse_batch, resolve  # noqa: F401

#: Hard caps. Each one is REPORTED when it bites — see rule 4.
#: Lower than the reachability page's on purpose: one line here is TWO full
#: dependency-tree walks, and a tree walk is tens of API reads, not one.
MAX_LINES = 100
DEFAULT_BUDGET_S = 180.0
MAX_BUDGET_S = 600.0

#: Per-object field cap. A payload with more differing fields than this is a
#: different object, not a drifted one, and the extra rows say nothing new.
MAX_FIELD_ROWS = 40

#: Fields that are per-box bookkeeping, not configuration. ``id`` is assigned
#: by the appliance when a sub-table row is created, so two identical rows on
#: two boxes carry different ids — comparing it would mark every by-parent row
#: on every line as changed, which is a report that says nothing.
_IGNORED_FIELDS = frozenset({"id", "_mkey", "q_ref", "q_type", "q_path"})

#: Line verdicts, worst first. A line carries ONE verdict: the worst state
#: among its rows.
VERDICTS = ("error", "missing", "differs", "identical")
_SEVERITY = {v: i for i, v in enumerate(reversed(VERDICTS))}  # identical=0 … error=3

#: Row state -> the line verdict it implies.
_STATE_VERDICT = {
    "same": "identical",
    "renamed": "differs",
    "changed": "differs",
    "only_source": "differs",
    "only_destination": "differs",
    "unreadable": "error",
}


# --------------------------------------------------------------------------- #
#  Canonical values                                                             #
# --------------------------------------------------------------------------- #
def _scalar(value) -> str:
    """One spelling for a field value, so two boxes that mean the same thing
    compare equal. FortiWeb answers ``1``/``"1"`` and ``enable``/``"enable"``
    for the same setting depending on the collection, and an int/str mismatch
    reported as a difference is a false finding on nearly every object."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "enable" if value else "disable"
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          default=str)
    return str(value).strip()


def _fields(payload) -> dict:
    """Comparable fields of a payload — bookkeeping stripped, values canonical.

    An ABSENT field and a field present-but-empty are folded together on
    purpose: FortiWeb omits unset fields from some collections and returns them
    as ``""`` in others, and every one of those would otherwise be reported as
    a difference between two boxes holding identical config.
    """
    if not isinstance(payload, dict):
        return {}
    out = {}
    for key, val in payload.items():
        if key in _IGNORED_FIELDS:
            continue
        text = _scalar(val)
        if text == "":
            continue
        out[str(key)] = text
    return out


def _diff_fields(src, dst, *, suppress=None) -> list:
    """``[{field, src, dst}]`` — SYMMETRIC (rule 3), sorted, capped.

    ``suppress`` is ``{field: (src_value, dst_value)}`` — pairs that are NOT
    configuration drift but the same rename already reported elsewhere on the
    page. Without it a renamed object reads as ``changed`` twice over: once
    because its own ``name`` field differs, and once because the parent's
    reference field now points at the new name. Both are the rename, and
    letting either through collapses the distinction between "this object was
    renamed" and "this object was reconfigured" — which is the distinction rule
    1 exists to draw. A field is only suppressed when BOTH values match the
    pair exactly; anything else is real drift and stays.

    The cap is applied by the caller and reported through ``truncated``; it is
    never a silent trim.
    """
    a, b = _fields(src), _fields(dst)
    hide = suppress or {}
    rows = []
    for key in sorted(set(a) | set(b)):
        sval, dval = a.get(key, ""), b.get(key, "")
        if sval == dval:
            continue
        if hide.get(key) == (sval, dval):
            continue
        rows.append({"field": key, "src": sval, "dst": dval})
    return rows


def _identity_suppression(src_item, dst_item) -> dict:
    """The object's OWN name, when it is pure identity.

    ``name`` normally echoes the mkey. A rename is then already stated by the
    row's ``src_name``/``dst_name`` columns, and repeating it as a field
    difference is what turned every ``renamed`` into ``changed``. When the
    payload's ``name`` does NOT match the mkey the two have genuinely diverged
    on that box, which is an anomaly worth showing — so it is not suppressed.
    """
    src_name = _fields(src_item.payload).get("name", "")
    dst_name = _fields(dst_item.payload).get("name", "")
    if src_name == src_item.mkey and dst_name == dst_item.mkey:
        return {"name": (src_name, dst_name)}
    return {}


def _rename_suppression(pairs) -> dict:
    """``{via: (src_name, dst_name)}`` for children paired by role — the
    parent's reference field to each of them.

    Every paired child is recorded, renamed or not. Guarding on ``s != d``
    here READ like a safety clause and was not one: the entry it would have
    skipped is ``(name, name)``, which can only suppress a field whose two
    values are equal — and an equal field is never reported in the first place.
    The clause was inert, and an inert clause that looks protective is worse
    than none. The real guard is the exact-pair match in :func:`_diff_fields`.
    """
    out = {}
    for via, src_node, dst_node in pairs:
        if not via or src_node is None or dst_node is None:
            continue
        out[via] = (src_node["item"].mkey, dst_node["item"].mkey)
    return out


# --------------------------------------------------------------------------- #
#  Tree building — from the flat collect() output + its reference edges         #
# --------------------------------------------------------------------------- #
def build_tree(items, edges) -> dict:
    """``(items, edges)`` from one ``collect()`` → a nested tree.

    ``edges`` is ``[(parent_urn, parent_mkey, via, child_urn, child_mkey), …]``
    recorded by the planner as it walks. The ``via`` field is what makes rule 1
    possible: it is the ROLE the child plays for its parent, and it is the only
    thing that survives a rename.

    A node reached from two parents (a pool shared by the policy and by a
    content-routing rule) appears under BOTH — the tree describes roles, and
    the same object genuinely fills two of them.
    """
    objs: dict = {}
    root = None
    for it in items or []:
        if it.kind == "object":
            objs[(it.urn, it.mkey)] = it
            if it.depth == 0:
                root = it
    if root is None:
        return {}

    # -- which OBJECT owns each by-parent row --------------------------------
    # A row carries its parent's mkey but not its parent's urn, so matching on
    # the mkey alone would hand the same rows to every object that happens to
    # share a name across collections. ``collect`` appends a row immediately
    # after its parent, one depth deeper: the nearest preceding object at
    # ``depth - 1`` with that mkey is the owner, uniquely.
    owned: dict = {}
    at_depth: dict = {}
    for it in items or []:
        if it.kind == "object":
            at_depth[it.depth] = (it.urn, it.mkey)
            continue
        owner = at_depth.get(it.depth - 1)
        if owner is None or owner[1] != it.parent_mkey:
            # Never drop the row (rule 4): fall back to any object carrying the
            # parent's name, and to the root if even that is gone. A row that
            # vanishes here is a difference the report would claim not to exist.
            owner = next((k for k in objs if k[1] == it.parent_mkey),
                         (root.urn, root.mkey))
        owned.setdefault(owner, []).append(it)

    kids: dict = {}
    for parent_urn, parent_mkey, via, child_urn, child_mkey in edges or []:
        kids.setdefault((parent_urn, parent_mkey), []).append(
            (str(via or ""), child_urn, child_mkey))

    def node(key, seen):
        item = objs.get(key)
        if item is None:
            return None
        out = {"item": item, "children": [], "subrows": list(owned.get(key, []))}
        if key in seen:          # cycle guard: a ref loop must not hang the page
            return out
        seen = seen | {key}
        for via, child_urn, child_mkey in kids.get(key, []):
            child = node((child_urn, child_mkey), seen)
            if child is not None:
                out["children"].append({"via": via, "node": child})
        return out

    return node((root.urn, root.mkey), set()) or {}


def collect_tree(reader, policy: str, *, root=None, planner=None) -> tuple:
    """``(tree, error)`` for one policy on one box.

    A policy that is NOT on the appliance does not come back as an empty walk:
    :meth:`ClonePlanner.collect` still emits its depth-0 item, with an EMPTY
    payload. Checking ``if not items`` would read a missing service as an empty
    tree and then declare it identical to another empty tree — two boxes
    agreeing that nothing is there. The emptiness of the ROOT PAYLOAD is what
    says "absent", and it is checked here.
    """
    planner = planner if planner is not None else _clone.ClonePlanner(reader, reader)
    root = root if root is not None else _clone.ROOT_SERVER_POLICY
    try:
        items = planner.collect(root, policy)
    except Exception as exc:  # noqa: BLE001
        return {}, "could not read the policy tree: %s" % exc
    root = next((it for it in items if it.depth == 0 and it.kind == "object"),
                None)
    if root is None or not root.payload:
        return {}, ""      # absent — not an error, and the caller says which
    return build_tree(items, list(getattr(planner, "edges", []) or [])), ""


# --------------------------------------------------------------------------- #
#  WPP — compared as a package, never entry by entry (rule 2)                    #
# --------------------------------------------------------------------------- #
def _is_wpp(urn: str) -> bool:
    return str(urn or "") in _clone.WPP_URNS


def _flatten(node, path="", out=None) -> dict:
    """Every object and by-parent row under ``node``, keyed by ROLE PATH.

    The key is the chain of ``via`` fields from the package root plus the
    object's own name — never the parent's name — so a package whose root was
    renamed at landing still lines up with its counterpart, sub-profile by
    sub-profile.
    """
    out = {} if out is None else out
    for edge in node.get("children", []):
        child = edge["node"]
        item = child["item"]
        key = "%s/%s:%s" % (path, edge["via"], item.mkey)
        out[key] = ("object", item.label, _fields(item.payload))
        for row in child.get("subrows", []):
            out["%s#%s:%s" % (key, row.urn, _row_id(row))] = (
                "subrow", row.label, _fields(row.payload))
        _flatten(child, key, out)
    return out


def _row_id(row) -> str:
    """A by-parent row's identity ACROSS TWO BOXES.

    The declared unique-key fields when the sub-table has them; otherwise the
    row's content. Never the appliance-assigned ``id``: it is allocated per box,
    so two identical rows on two appliances carry different ones and every row
    would pair with nothing.
    """
    keys = _clone.subrow_key_fields(row.urn)
    payload = row.payload if isinstance(row.payload, dict) else {}
    if keys:
        return "|".join("%s=%s" % (k, _scalar(payload.get(k))) for k in keys)
    return _fingerprint(_fields(payload))


def _fingerprint(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"),
                   default=str).encode("utf-8")).hexdigest()[:16]


def compare_package(src_node, dst_node, via: str) -> dict:
    """One WPP package on each side → ONE row (rule 2).

    Reports the package verdict, WHICH sub-profiles differ and by how much —
    and deliberately NOT the differing entries. The name of the package itself
    is excluded from the fingerprint and reported separately: a landed clone
    normally carries a derived name, and letting that one string flip a
    500-object package to "different" would make the verdict useless.
    """
    src_item, dst_item = src_node["item"], dst_node["item"]
    src_map, dst_map = _flatten(src_node), _flatten(dst_node)

    # The package ROOT's own fields, minus its name (see docstring).
    root_src = {k: v for k, v in _fields(src_item.payload).items() if k != "name"}
    root_dst = {k: v for k, v in _fields(dst_item.payload).items() if k != "name"}
    root_fields = [r for r in _diff_fields(root_src, root_dst)]

    added = sorted(set(dst_map) - set(src_map))
    removed = sorted(set(src_map) - set(dst_map))
    changed = sorted(k for k in (set(src_map) & set(dst_map))
                     if src_map[k][2] != dst_map[k][2])

    # Which SUB-PROFILES differ — the package's own granularity, one level in.
    detail: dict = {}
    for key in removed:
        _bump(detail, _profile_of(key, src_map), "only_source")
    for key in added:
        _bump(detail, _profile_of(key, dst_map), "only_destination")
    for key in changed:
        _bump(detail, _profile_of(key, src_map), "changed")

    same = (not root_fields and not added and not removed and not changed)
    renamed = src_item.mkey != dst_item.mkey
    return {
        "kind": "wpp",
        "via": via,
        "label": src_item.label,
        "urn": src_item.urn,
        "src_name": src_item.mkey,
        "dst_name": dst_item.mkey,
        "state": "same" if same and not renamed else ("renamed" if same else "changed"),
        "fields": root_fields[:MAX_FIELD_ROWS],
        "truncated": max(0, len(root_fields) - MAX_FIELD_ROWS),
        "package": {
            "src_objects": len(src_map),
            "dst_objects": len(dst_map),
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "src_fingerprint": _fingerprint(
                {k: v[2] for k, v in src_map.items()} | {"__root__": root_src}),
            "dst_fingerprint": _fingerprint(
                {k: v[2] for k, v in dst_map.items()} | {"__root__": root_dst}),
            "profiles": [
                {"profile": name, **counts}
                for name, counts in sorted(detail.items())
            ],
        },
    }


def _bump(detail: dict, name: str, bucket: str) -> None:
    entry = detail.setdefault(name, {"changed": 0, "only_source": 0,
                                     "only_destination": 0})
    entry[bucket] = entry.get(bucket, 0) + 1


def _profile_of(key: str, table: dict) -> str:
    """The sub-profile a package entry belongs to — its FIRST role hop.

    Grouping by the leaf would produce one bucket per entry, which is the
    entry-by-entry report rule 2 exists to prevent.
    """
    head = key.lstrip("/").split("/", 1)[0]
    field = head.split(":", 1)[0]
    # The LABEL comes from the first-hop object too, never from the entry that
    # differed. Taking it from the entry buckets by (label, hop): two objects
    # of different classes under the SAME sub-profile land in separate buckets,
    # which reads as two sub-profiles drifting when one did.
    label = table.get("/" + head, ("", "", {}))[1]
    return "%s (%s)" % (label, field) if label else (field or "package")


# --------------------------------------------------------------------------- #
#  Pairing + diffing                                                            #
# --------------------------------------------------------------------------- #
def _pair(src_kids, dst_kids) -> list:
    """``[(via, src_node|None, dst_node|None)]`` — rule 1.

    Grouped by the reference FIELD first. When a field holds exactly one object
    on each side, those two are counterparts WHATEVER they are called, and the
    name difference is reported by the caller as ``renamed``. When the field
    holds several (a space-separated list of names), they are paired by name,
    because with more than one candidate a name is the only evidence of which
    is which — and guessing would be worse than reporting an add and a remove.
    """
    by_via: dict = {}
    for edge in src_kids:
        by_via.setdefault(edge["via"], ([], []))[0].append(edge["node"])
    for edge in dst_kids:
        by_via.setdefault(edge["via"], ([], []))[1].append(edge["node"])

    out = []
    for via in sorted(by_via):
        src_list, dst_list = by_via[via]
        if len(src_list) == 1 and len(dst_list) == 1:
            out.append((via, src_list[0], dst_list[0]))
            continue
        src_by = {n["item"].mkey: n for n in src_list}
        dst_by = {n["item"].mkey: n for n in dst_list}
        for name in sorted(set(src_by) | set(dst_by)):
            out.append((via, src_by.get(name), dst_by.get(name)))
    return out


def _subrow_rows(via, src_node, dst_node) -> list:
    """By-parent rows of one paired object, matched on content identity."""
    rows = []
    src_by, dst_by = {}, {}
    for row in (src_node.get("subrows") if src_node else []) or []:
        src_by[(row.urn, _row_id(row))] = row
    for row in (dst_node.get("subrows") if dst_node else []) or []:
        dst_by[(row.urn, _row_id(row))] = row
    for key in sorted(set(src_by) | set(dst_by), key=lambda k: (k[0], k[1])):
        src_row, dst_row = src_by.get(key), dst_by.get(key)
        if src_row is not None and dst_row is not None:
            continue          # identical by construction: the key IS the content
        item = src_row or dst_row
        rows.append({
            "kind": "subrow", "via": via, "label": item.label, "urn": item.urn,
            "src_name": src_row.mkey if src_row else "",
            "dst_name": dst_row.mkey if dst_row else "",
            "state": "only_source" if src_row is not None else "only_destination",
            "fields": [{"field": k, "src": v if src_row is not None else "",
                        "dst": "" if src_row is not None else v}
                       for k, v in sorted(_fields(item.payload).items())
                       ][:MAX_FIELD_ROWS],
            "truncated": 0,
            "package": None,
        })
    return rows


def compare_trees(src_tree: dict, dst_tree: dict) -> list:
    """Both trees → the flat list of report rows, deepest role first."""
    rows: list = []
    if not src_tree and not dst_tree:
        return rows

    def walk(via, src_node, dst_node, seen):
        if not src_node or not dst_node:
            item = (src_node or dst_node)["item"]
            rows.append({
                "kind": "object", "via": via, "label": item.label,
                "urn": item.urn,
                "src_name": item.mkey if src_node else "",
                "dst_name": item.mkey if dst_node else "",
                "state": "only_source" if src_node else "only_destination",
                "fields": [{"field": k, "src": v if src_node else "",
                            "dst": "" if src_node else v}
                           for k, v in sorted(_fields(item.payload).items())
                           ][:MAX_FIELD_ROWS],
                "truncated": 0, "package": None,
            })
            return

        src_item, dst_item = src_node["item"], dst_node["item"]
        key = (src_item.urn, src_item.mkey, dst_item.mkey)
        if key in seen:
            return
        seen = seen | {key}

        if _is_wpp(src_item.urn) and _is_wpp(dst_item.urn):
            rows.append(compare_package(src_node, dst_node, via))
            return                       # rule 2: the package IS the row

        # Children are paired BEFORE this object is diffed: a reference field
        # that now names a renamed child must be recognised as that rename, and
        # only the pairing knows which children were renamed.
        pairs = _pair(src_node["children"], dst_node["children"])
        suppress = dict(_identity_suppression(src_item, dst_item))
        suppress.update(_rename_suppression(pairs))

        fields = _diff_fields(src_item.payload, dst_item.payload,
                              suppress=suppress)
        renamed = src_item.mkey != dst_item.mkey
        rows.append({
            "kind": "object", "via": via, "label": src_item.label,
            "urn": src_item.urn,
            "src_name": src_item.mkey, "dst_name": dst_item.mkey,
            "state": "changed" if fields else ("renamed" if renamed else "same"),
            "fields": fields[:MAX_FIELD_ROWS],
            "truncated": max(0, len(fields) - MAX_FIELD_ROWS),
            "package": None,
        })
        rows.extend(_subrow_rows(via, src_node, dst_node))
        for child_via, src_child, dst_child in pairs:
            walk(child_via, src_child, dst_child, seen)

    walk("", src_tree or None, dst_tree or None, set())
    return rows


# --------------------------------------------------------------------------- #
#  Running the batch                                                            #
# --------------------------------------------------------------------------- #
def _verdict(rows, base="identical") -> str:
    worst = base
    for row in rows:
        cand = _STATE_VERDICT.get(row.get("state"), "differs")
        if _SEVERITY[cand] > _SEVERITY[worst]:
            worst = cand
    return worst


def _counts(rows) -> dict:
    out = {"same": 0, "renamed": 0, "changed": 0,
           "only_source": 0, "only_destination": 0}
    for row in rows:
        state = row.get("state")
        if state in out:
            out[state] += 1
    return out


def run_batch(rows, *, budget_s: float = DEFAULT_BUDGET_S, user=None,
              appliances=None, client_factory=None, reader_factory=None,
              collect=None, clock=time.monotonic) -> dict:
    """Compare every line's source against its destination. Returns the report.

    ``appliances`` / ``client_factory`` / ``reader_factory`` / ``clock`` are
    injection seams for the tests; production passes none of them. ``clock`` is
    one of them because patching the global clock to exercise the budget breaks
    every other thing in the run that reads the time.

    SOURCES ARE READ BEFORE DESTINATIONS, per line, for the same reason the
    reachability page does it: the source tree is the reference the destination
    is subtracted from, and when the budget expires it is the half that has to
    already be on the page.
    """
    t0 = clock()
    budget = max(10.0, min(float(budget_s or DEFAULT_BUDGET_S), MAX_BUDGET_S))
    deadline = t0 + budget
    report = {"lines": [], "dropped": [], "skipped": [], "appliances": [],
              "budget_hit": False, "elapsed_s": 0.0,
              "totals": {v: 0 for v in VERDICTS}}

    if appliances is None:
        from ..models import visible_appliances
        appliances = visible_appliances(user=user).all()
    index = build_index(appliances)

    if client_factory is None:
        from ..clients.fortiweb import FortiWebClient
        client_factory = FortiWebClient
    if reader_factory is None:
        reader_factory = _clone.ClientReader
    if collect is None:
        collect = collect_tree

    readers: dict = {}
    seen_appliances: dict = {}
    trees: dict = {}          # (aid, policy) -> (tree, error, absent)

    def reader_for(appl):
        aid = getattr(appl, "id", None) or getattr(appl, "name", "")
        if aid not in readers:
            name = str(getattr(appl, "name", "") or "")
            entry = {"name": name, "error": ""}
            seen_appliances[aid] = entry
            report["appliances"].append(entry)
            try:
                readers[aid] = reader_factory(client_factory(appl))
            except Exception as exc:  # noqa: BLE001
                entry["error"] = "could not connect: %s" % exc
                readers[aid] = None
        return aid, readers[aid]

    def tree_for(appl, policy):
        aid, reader = reader_for(appl)
        if reader is None:
            return {}, seen_appliances[aid]["error"] or "no session", False
        key = (aid, policy)
        if key not in trees:
            tree, err = collect(reader, policy)
            trees[key] = (tree, err, not tree and not err)
        return trees[key]

    for row in rows:
        line = {"lineno": row.get("lineno"), "raw": row.get("raw", ""),
                "source": row.get("source", ""), "policy": row.get("policy", ""),
                "destination": row.get("destination", ""),
                "verdict": "error", "error": row.get("error", ""),
                "rows": [], "counts": _counts([]),
                "src_absent": False, "dst_absent": False}

        if not line["error"] and clock() >= deadline:
            report["budget_hit"] = True
            report["skipped"].append(
                {"lineno": row.get("lineno"), "raw": row.get("raw", ""),
                 "why": "the %ds time budget expired before this line ran — "
                        "raise it or split the file" % int(budget)})
            continue

        if not line["error"]:
            src_appl, err = resolve(row["source"], index)
            if err:
                line["error"] = err
            elif not row.get("destination"):
                line["error"] = ("this line has no destination — a comparison "
                                 "needs both sides")
            else:
                dst_appl, derr = resolve(row["destination"], index)
                if derr:
                    line["error"] = derr
                else:
                    src_tree, serr, sabsent = tree_for(src_appl, row["policy"])
                    dst_tree, derr2, dabsent = tree_for(dst_appl, row["policy"])
                    line["src_absent"], line["dst_absent"] = sabsent, dabsent
                    if serr:
                        line["error"] = "%s: %s" % (row["source"], serr)
                    elif derr2:
                        line["error"] = "%s: %s" % (row["destination"], derr2)
                    elif sabsent and dabsent:
                        line["error"] = ("neither %s nor %s has a server policy "
                                         "called %r"
                                         % (row["source"], row["destination"],
                                            row["policy"]))
                    elif sabsent or dabsent:
                        line["verdict"] = "missing"
                        line["error"] = ""
                        missing = row["destination"] if dabsent else row["source"]
                        line["rows"] = [{
                            "kind": "object", "via": "", "label": "Server Policy",
                            "urn": "cmdb/server-policy/policy",
                            "src_name": row["policy"] if not sabsent else "",
                            "dst_name": row["policy"] if not dabsent else "",
                            "state": "only_source" if dabsent else "only_destination",
                            "fields": [], "truncated": 0, "package": None,
                            "note": "the policy is not configured on %s at all — "
                                    "there is nothing to compare against"
                                    % missing,
                        }]
                    else:
                        line["rows"] = compare_trees(src_tree, dst_tree)
                        line["verdict"] = _verdict(line["rows"])

        line["counts"] = _counts(line["rows"])
        if line["error"]:
            line["verdict"] = "error"
        report["lines"].append(line)
        report["totals"][line["verdict"]] += 1

    report["elapsed_s"] = round(clock() - t0, 2)
    return report


# --------------------------------------------------------------------------- #
#  Export                                                                       #
# --------------------------------------------------------------------------- #
def to_tsv(report: dict) -> str:
    """One tab-separated line per REPORT ROW, not per input line.

    The operator's next step is a spreadsheet filtered on ``state``; a per-input
    export would collapse the answer back into a sentence they would have to
    re-read the page to expand.
    """
    out = ["\t".join(("lineno", "source", "policy", "destination", "verdict",
                      "object", "role", "state", "src_name", "dst_name",
                      "field", "src_value", "dst_value"))]
    for line in report.get("lines", []):
        head = [str(line.get("lineno", "")), line.get("source", ""),
                line.get("policy", ""), line.get("destination", ""),
                line.get("verdict", "")]
        if line.get("error"):
            out.append("\t".join(head + ["", "", "error", "", "",
                                         "", line["error"], ""]))
            continue
        for row in line.get("rows", []):
            base = head + [row.get("label", ""), row.get("via", ""),
                           row.get("state", ""), row.get("src_name", ""),
                           row.get("dst_name", "")]
            pkg = row.get("package")
            if pkg:
                out.append("\t".join(base + [
                    "package",
                    "%d objects / fp %s" % (pkg["src_objects"],
                                            pkg["src_fingerprint"]),
                    "%d objects / fp %s" % (pkg["dst_objects"],
                                            pkg["dst_fingerprint"])]))
                for prof in pkg.get("profiles", []):
                    out.append("\t".join(base + [
                        "package:%s" % prof["profile"],
                        "-%d ~%d" % (prof.get("only_source", 0),
                                     prof.get("changed", 0)),
                        "+%d" % prof.get("only_destination", 0)]))
            if not row.get("fields"):
                if not pkg:
                    out.append("\t".join(base + ["", "", ""]))
                continue
            for fld in row["fields"]:
                out.append("\t".join(base + [fld["field"], fld["src"],
                                             fld["dst"]]))
    return "\n".join(out) + "\n"
