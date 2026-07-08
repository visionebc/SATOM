"""Unit tests for the web tree-clone planner (services.clone).

Drives ``ClonePlanner`` with in-memory fakes (no Flask request, no network) over
a small synthetic dependency tree, locking the behaviours the WPP clone relies
on: deepest-first collection, root rename + sub-row re-pointing, and skip-if-
exists destination validation.
"""
from app.services import clone
from app.registry.dependencies import DepNode


def _node(name, urn, via="", children=()):
    return DepNode(name, urn, via, "", tuple(children))


# WPP-shaped synthetic tree: a profile that NAMES a signature rule (via edge) and
# owns a by-parent member sub-table.
_SIG = _node("Signature Rule", "u/sig")
_MEMBER = _node("Member", "u/wpp/member")  # by-parent sub-table (no via)
_WPP = _node("Web Protection Profile", "u/wpp",
             children=(_node("Signature Rule", "u/sig", via="signature-rule"), _MEMBER))

_URN_INDEX = {"u/wpp": "wpp_l", "u/sig": "sig_l", "u/wpp/member": "mem_l"}


class FakeReader:
    """``{(urn, mkey): dict|list}`` lookup; mirrors get_raw scoping."""

    def __init__(self, data):
        self.data = data

    def get_raw(self, urn, mkey=""):
        v = self.data.get((urn, mkey))
        if v is None:
            return []
        return v if isinstance(v, list) else [v]


def _planner(src, dst):
    p = clone.ClonePlanner(src, dst)
    p.urn_index = dict(_URN_INDEX)  # decouple from the real registry yaml
    return p


_SRC = {
    ("u/wpp", "wpp1"): {"name": "wpp1", "signature-rule": "sig1"},
    ("u/sig", "sig1"): {"name": "sig1"},
    ("u/wpp/member", "wpp1"): [{"id": "1"}, {"id": "2"}],
}


def test_collect_is_deepest_first():
    items = _planner(FakeReader(_SRC), FakeReader({})).collect(_WPP, "wpp1")
    seq = [(it.kind, it.mkey) for it in items]
    # named dep (sig) BEFORE the object that references it (wpp), members AFTER.
    assert seq == [("object", "sig1"), ("object", "wpp1"),
                   ("subrow", "1"), ("subrow", "2")]


def test_rename_root_and_repoint_subrows():
    items = _planner(FakeReader(_SRC), FakeReader({})).collect(_WPP, "wpp1", new_name="wpp2")
    root = next(it for it in items if it.depth == 0 and it.kind == "object")
    assert root.mkey == "wpp2"
    assert root.payload["name"] == "wpp2"
    members = [it for it in items if it.kind == "subrow"]
    assert members and all(m.parent_mkey == "wpp2" for m in members)


def test_plan_all_create_on_empty_destination():
    items = _planner(FakeReader(_SRC), FakeReader({})).plan(_WPP, "wpp1", new_name="wpp2")
    assert {it.mkey: it.status for it in items} == {
        "sig1": "create", "wpp2": "create", "1": "create", "2": "create"}
    assert clone.summarize(items)["create"] == 4


def test_plan_skips_existing_objects():
    dst = FakeReader({
        ("u/sig", "sig1"): {"name": "sig1"},
        ("u/wpp", "wpp2"): {"name": "wpp2"},
    })
    items = _planner(FakeReader(_SRC), dst).plan(_WPP, "wpp1", new_name="wpp2")
    by = {it.mkey: it.status for it in items}
    # the existing signature + the existing renamed profile are NOT recreated;
    # the profile's own members ride on the existing parent (skipped too).
    assert by["sig1"] == "exists"
    assert by["wpp2"] == "exists"
    assert all(by[m] == "exists" for m in ("1", "2"))
    assert "create" not in clone.summarize(items)


def test_missing_source_object_is_empty():
    src = {("u/wpp", "ghost"): {"name": "ghost", "signature-rule": "nope"}}
    items = _planner(FakeReader(src), FakeReader({})).plan(_WPP, "ghost")
    sig = next(it for it in items if it.urn == "u/sig")
    assert sig.status == "empty"


def test_template_body_shape():
    items = _planner(FakeReader(_SRC), FakeReader({})).collect(_WPP, "wpp1", new_name="wpp2")
    body = clone.template_body(items, "wpp2")
    assert body["mkey"] == "wpp2"
    assert body["data"]["name"] == "wpp2"
    # the named signature dep + the members ride along as subobjects
    sub_keys = {s["mkey"] for s in body["subobjects"]}
    assert {"sig1", "1", "2"} <= sub_keys


def test_disable_root():
    items = _planner(FakeReader(_SRC), FakeReader({})).collect(_WPP, "wpp1", new_name="wpp2")
    clone.disable_root(items)
    root = next(it for it in items if it.depth == 0 and it.kind == "object")
    assert root.payload["status"] == "disable"


def test_subrow_missing_under_existing_parent_is_recreated():
    """Partial-clone recovery: the parent object already exists on the destination
    but one of its by-parent rows is absent. The planner must flag the MISSING row
    as ``create`` (matched by CONTENT, not the per-box id) and the present one as
    ``exists`` — the exact gap that left a broken clone's content-routing binding
    row uncreated on a re-clone."""
    src = {
        ("u/wpp", "wpp1"): {"name": "wpp1", "signature-rule": "sig1"},
        ("u/sig", "sig1"): {"name": "sig1"},
        ("u/wpp/member", "wpp1"): [{"id": "1", "host": "a.com"},
                                   {"id": "2", "host": "b.com"}],
    }
    dst = {
        ("u/wpp", "wpp1"): {"name": "wpp1", "signature-rule": "sig1"},
        ("u/sig", "sig1"): {"name": "sig1"},
        # parent exists, but only the a.com row is present (b.com is MISSING)
        ("u/wpp/member", "wpp1"): [{"id": "9", "host": "a.com"}],
    }
    items = _planner(FakeReader(src), FakeReader(dst)).plan(_WPP, "wpp1")
    status = {it.payload.get("host"): it.status
              for it in items if it.kind == "subrow"}
    assert status == {"a.com": "exists", "b.com": "create"}


def test_subrow_all_present_under_existing_parent_are_skipped():
    """The safe side: when every row is already present under an existing parent,
    nothing is recreated (no duplicates)."""
    data = {
        ("u/wpp", "wpp1"): {"name": "wpp1", "signature-rule": "sig1"},
        ("u/sig", "sig1"): {"name": "sig1"},
        ("u/wpp/member", "wpp1"): [{"id": "1", "host": "a.com"},
                                   {"id": "2", "host": "b.com"}],
    }
    dst = {**data, ("u/wpp/member", "wpp1"): [{"id": "7", "host": "a.com"},
                                              {"id": "8", "host": "b.com"}]}
    items = _planner(FakeReader(data), FakeReader(dst)).plan(_WPP, "wpp1")
    subs = [it.status for it in items if it.kind == "subrow"]
    assert subs == ["exists", "exists"]


def test_content_routing_pools_carry_their_members():
    """Regression: every server-pool node in the SERVER_POLICY tree (incl. the
    content-routing default/per-match pools) must carry its pserver-list members
    child. Without it the planner discovers the pool but never walks its backends,
    so a cloned content-routing policy lands with an EMPTY pool (no backends).
    See the fw6->fw7 pol-full-cr incident (2026-07-08)."""
    from app.registry.dependencies import SERVER_POLICY

    POOL_URN = "cmdb/server-policy/server-pool"
    MEMBERS_URN = "cmdb/server-policy/server-pool/pserver-list"

    pools = []

    def walk(node):
        if node.urn == POOL_URN:
            pools.append(node)
        for c in node.children:
            walk(c)

    walk(SERVER_POLICY)
    assert pools, "expected at least one server-pool node in the tree"
    for pool in pools:
        child_urns = {c.urn for c in pool.children}
        assert MEMBERS_URN in child_urns, (
            "server-pool node %r is missing its pserver-list members child "
            "(would clone as an empty pool)" % pool.name
        )
