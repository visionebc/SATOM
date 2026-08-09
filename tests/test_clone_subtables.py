"""By-parent sub-table integrity for the clone/migrate engine.

Two failures met here, and they compound.

1. **A declared object with undeclared sub-tables loses config silently.** The
   planner only walks ``node.children``; a sub-table nobody wrote down is never
   read, so the object clones with its NAME and none of its content, and the job
   still reports success. That is how ``car-ratelimit`` migrated from fortiweb08
   to fortiweb09 with its url-filter and access-limit-filter empty.

2. **Widening the tree is itself dangerous**, because FortiWeb answers a
   sub-table path it doesn't implement by echoing the PARENT OBJECT instead of
   404ing. Every name added to the tree is a path that may be absent on some
   firmware, and each absent one would manufacture a bogus row built out of the
   parent.

So the two halves are pinned together: the registry cross-check keeps the tree
complete, and the echo guard keeps completeness safe.
"""
import os

import yaml

from app.registry import dependencies as deps
from app.registry.dependencies import DepNode, ROOTS, iter_nodes
from app.services import clone

_YAML = os.path.join(os.path.dirname(__file__), '..', 'endpoints.yaml')


def _registry_collections() -> dict[str, str]:
    """``{collection: friendly_key}`` for every cmdb entry in endpoints.yaml."""
    reg = yaml.safe_load(open(_YAML)) or {}
    return {v.replace('/api/v2.0/', ''): k
            for k, v in reg.items()
            if isinstance(v, str) and '/cmdb/' in v}


def _declared_children() -> dict[str, set[str]]:
    """``{object urn: {declared child urn, …}}`` over the whole dependency tree."""
    out: dict[str, set[str]] = {}
    for _depth, node in iter_nodes(ROOTS):
        if not node.urn:
            continue
        out.setdefault(node.urn, set()).update(c.urn for c in node.children if c.urn)
    return out


# Object nodes whose registry sub-tables are deliberately NOT walked. An entry
# here is a decision with a reason, not a backlog item — that is the whole point
# of listing them instead of loosening the assertion.
_INTENTIONALLY_NOT_EXPANDED = {
    # The tree already says so at the node: replacement-message pages are a
    # GLOBAL catalog shared by every policy, not per-policy content, so copying
    # them would rewrite the destination's own block pages.
    'cmdb/system/replacemsg': 'pages are a global catalog, not per-policy',
}


# --------------------------------------------------------------------------- #
#  1. the tree is complete against the endpoint registry                        #
# --------------------------------------------------------------------------- #
def test_every_declared_object_walks_all_of_its_registry_subtables():
    colls = _registry_collections()
    declared = _declared_children()
    holes = {}
    for urn, kids in declared.items():
        if urn in _INTENTIONALLY_NOT_EXPANDED:
            continue
        depth = urn.count('/')
        registry_kids = {c for c in colls
                         if c.startswith(urn + '/') and c.count('/') == depth + 1}
        missing = registry_kids - kids
        if missing:
            holes[urn] = sorted(missing)
    assert holes == {}, (
        "these objects are cloned without sub-tables the registry knows about, "
        "so their content is dropped silently: %r" % holes)


def test_the_allow_list_only_names_objects_that_are_in_the_tree():
    # A stale allow-list entry would mask a real hole under a renamed urn.
    declared = _declared_children()
    for urn in _INTENTIONALLY_NOT_EXPANDED:
        assert urn in declared, "allow-listed urn is no longer in the tree: %s" % urn


def test_allow_listed_objects_do_have_registry_subtables():
    # If the registry stopped listing sub-tables for an allow-listed object the
    # entry is dead weight and should go, not linger as a blanket exemption.
    colls = _registry_collections()
    for urn in _INTENTIONALLY_NOT_EXPANDED:
        assert any(c.startswith(urn + '/') for c in colls), urn


# --------------------------------------------------------------------------- #
#  2. the custom-access rule specifically                                       #
# --------------------------------------------------------------------------- #
def _node_for(urn: str) -> DepNode:
    for _d, node in iter_nodes(ROOTS):
        if node.urn == urn:
            return node
    raise AssertionError('no node for %s' % urn)


def test_custom_access_rule_is_not_a_leaf():
    # The regression itself: the rule used to be declared childless, so a
    # migrate carried the name and none of the conditions.
    node = _node_for('cmdb/waf/custom-access.rule')
    assert node.children, 'Custom Access Rule must carry its filter sub-tables'


def test_custom_access_rule_declares_exactly_the_registry_filters():
    colls = _registry_collections()
    expected = {c for c in colls
                if c.startswith('cmdb/waf/custom-access.rule/')
                and c.count('/') == 'cmdb/waf/custom-access.rule'.count('/') + 1}
    got = {c.urn for c in _node_for('cmdb/waf/custom-access.rule').children}
    assert got == expected


def test_the_two_filters_the_incident_lost_are_declared():
    # Named explicitly: these are the rows that existed on fortiweb08 and did
    # not arrive on fortiweb09. A future "tidy up the list" must trip here.
    got = {c.urn for c in _node_for('cmdb/waf/custom-access.rule').children}
    assert 'cmdb/waf/custom-access.rule/url-filter' in got
    assert 'cmdb/waf/custom-access.rule/access-limit-filter' in got


def test_custom_access_filters_are_by_parent_rows_not_named_references():
    # A `via` here would make the planner treat a filter as a separate object to
    # create and re-point, which it is not.
    for child in _node_for('cmdb/waf/custom-access.rule').children:
        assert not child.via, child.urn


def test_every_declared_filter_is_a_real_registry_path():
    # The echo quirk means a typo'd path cannot be caught at runtime by a 404.
    colls = _registry_collections()
    for child in _node_for('cmdb/waf/custom-access.rule').children:
        assert child.urn in colls, 'not in endpoints.yaml: %s' % child.urn


def test_filters_are_labelled_for_the_operator():
    for child in _node_for('cmdb/waf/custom-access.rule').children:
        assert child.fortiweb and child.fortiweb != child.urn


# --------------------------------------------------------------------------- #
#  3. the echo guard                                                            #
# --------------------------------------------------------------------------- #
class _Reader:
    """Reader whose ``get_raw`` mimics FortiWeb: a known sub-table returns its
    rows, an UNKNOWN one echoes the parent object back."""

    def __init__(self, rows, parent):
        self.rows = rows
        self.parent = parent

    def get_raw(self, urn, mkey=""):
        if urn in self.rows:
            return list(self.rows[urn])
        return [dict(self.parent)]


_PARENT = {"name": "car-ratelimit", "action": "alert", "severity": "Medium"}
_URL_ROW = {"id": "1", "request-file": "^/api/"}


def test_parent_echo_is_not_a_subtable_row():
    r = _Reader({}, _PARENT)
    assert subtable(r, 'cmdb/waf/custom-access.rule/geo-filter') == []


def subtable(reader, urn, parent='car-ratelimit'):
    return clone.subtable_rows(reader, urn, None, parent)


def test_real_rows_survive_the_guard():
    r = _Reader({'cmdb/waf/custom-access.rule/url-filter': [_URL_ROW]}, _PARENT)
    assert subtable(r, 'cmdb/waf/custom-access.rule/url-filter') == [_URL_ROW]


def test_guard_drops_only_the_echo_from_a_mixed_read():
    r = _Reader({'u/s': [_URL_ROW, dict(_PARENT)]}, _PARENT)
    assert subtable(r, 'u/s') == [_URL_ROW]


def test_a_row_named_differently_from_its_parent_is_kept():
    # The one live sub-row that carries a name (x-frame-options under hhs-full)
    # must not be mistaken for an echo.
    row = {"id": "1", "name": "x-frame-options"}
    r = _Reader({'u/s': [row]}, {"name": "hhs-full"})
    assert clone.subtable_rows(r, 'u/s', None, 'hhs-full') == [row]


def test_guard_is_inert_without_a_parent_mkey():
    """A top-level collection read is not a by-parent read; there is nothing to
    compare against. The sample row deliberately has NO ``name``: drop the
    early return and ``row.get("name", "")`` becomes ``""``, which equals the
    empty parent — so every nameless row in the collection would vanish."""
    row = {"id": "1", "request-file": "^/api/"}
    r = _Reader({'u/s': [row]}, _PARENT)
    assert clone.subtable_rows(r, 'u/s', None, '') == [row]


def test_object_reads_still_return_the_object_itself():
    # The object read legitimately has name == mkey; the guard must not be
    # wired into it or every object in the tree would vanish.
    r = _Reader({'cmdb/waf/custom-access.rule': [_PARENT]}, _PARENT)
    assert clone.scoped_rows(r, 'cmdb/waf/custom-access.rule', None,
                             'car-ratelimit') == [_PARENT]


# --------------------------------------------------------------------------- #
#  4. planner integration                                                       #
# --------------------------------------------------------------------------- #
_RULE = DepNode(
    "Custom Access Rule", "u/rule", "", "",
    (DepNode("URL Filter", "u/rule/url-filter", "", "", ()),
     DepNode("Geo Filter", "u/rule/geo-filter", "", "", ())),
)


def _planner(reader):
    p = clone.ClonePlanner(reader, _Reader({}, {}))
    p.urn_index = {}
    return p


def test_planner_collects_the_filter_rows():
    r = _Reader({'u/rule': [_PARENT], 'u/rule/url-filter': [_URL_ROW]}, _PARENT)
    items = _planner(r).collect(_RULE, 'car-ratelimit')
    rows = [i for i in items if i.kind == 'subrow']
    assert [i.urn for i in rows] == ['u/rule/url-filter']
    assert rows[0].parent_mkey == 'car-ratelimit'
    assert rows[0].payload.get('request-file') == '^/api/'


def test_planner_does_not_manufacture_a_row_from_the_echo():
    # geo-filter is absent, so the fake echoes the rule back. Without the guard
    # the plan would carry a "filter" whose body is the rule itself.
    r = _Reader({'u/rule': [_PARENT], 'u/rule/url-filter': [_URL_ROW]}, _PARENT)
    items = _planner(r).collect(_RULE, 'car-ratelimit')
    assert not [i for i in items
                if i.kind == 'subrow' and i.urn == 'u/rule/geo-filter']
    assert not [i for i in items
                if i.kind == 'subrow' and i.payload.get('action') == 'alert']


def test_the_rule_object_itself_is_still_planned():
    r = _Reader({'u/rule': [_PARENT], 'u/rule/url-filter': [_URL_ROW]}, _PARENT)
    items = _planner(r).collect(_RULE, 'car-ratelimit')
    objs = [i for i in items if i.kind == 'object']
    assert [i.mkey for i in objs] == ['car-ratelimit']


def test_filters_are_ordered_after_the_rule_that_owns_them():
    # A filter POSTed before its rule exists is a dangling-reference error.
    r = _Reader({'u/rule': [_PARENT], 'u/rule/url-filter': [_URL_ROW]}, _PARENT)
    items = _planner(r).collect(_RULE, 'car-ratelimit')
    kinds = [i.kind for i in items]
    assert kinds.index('object') < kinds.index('subrow')


def test_shared_filter_tuple_is_immutable():
    # It is spliced into a frozen DepNode; a list would let one caller's edit
    # leak into every plan built afterwards.
    assert isinstance(deps._CUSTOM_ACCESS_RULE_FILTERS, tuple)


# --------------------------------------------------------------------------- #
#  5. the echo on the DESTINATION side                                          #
# --------------------------------------------------------------------------- #
def test_destination_echo_cannot_mark_a_missing_row_as_present():
    """The dangerous half: ``_subrow_exists_at_dst`` matches a source row against
    the destination rows BY CONTENT. If the destination echoes the parent object,
    a sub-row whose fields are a subset of the parent's — same names, same values
    — matches that echo and is classified ``exists``. The row is then never
    created and the clone reports success with the row missing, which is the
    exact silent-skip this whole module exists to stop.
    """
    parent = {"name": "r1", "action": "alert"}
    dst = _Reader({}, parent)          # every sub-table path echoes the parent
    p = clone.ClonePlanner(_Reader({}, parent), dst)
    p.urn_index = {}
    item = clone.CloneItem(
        label="URL Filter", urn="u/rule/url-filter", logical=None,
        mkey="1", parent_mkey="r1", kind="subrow", depth=2,
        payload={"id": "1", "action": "alert"},
    )
    assert p._subrow_exists_at_dst(item) is False


def test_a_row_genuinely_present_on_the_destination_is_still_exists():
    # The guard must not flip every row to "create" — that would re-POST rows
    # that are already there and duplicate them.
    parent = {"name": "r1", "action": "alert"}
    dst = _Reader({"u/rule/url-filter": [{"id": "7", "request-file": "^/api/"}]}, parent)
    p = clone.ClonePlanner(_Reader({}, parent), dst)
    p.urn_index = {}
    item = clone.CloneItem(
        label="URL Filter", urn="u/rule/url-filter", logical=None,
        mkey="1", parent_mkey="r1", kind="subrow", depth=2,
        payload={"id": "1", "request-file": "^/api/"},
    )
    assert p._subrow_exists_at_dst(item) is True
