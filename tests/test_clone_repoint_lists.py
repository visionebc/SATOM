"""Re-pointing a MULTI-VALUED reference field (``services.clone.repoint_value``).

``referenced_names`` knew that a declared list field holds several names;
``deep_rename`` did not, and matched the field WHOLE. Measured honestly, that
was LATENT, not live: ``deep_rename`` runs only on the WPP root today, and no
field there is a list (``test_clone_list_refs`` pins that scope). But the trap
was armed — widening the same-device deep clone to the Server Policy root, a
one-argument change, would have made the plan copy every script, rename every
copy, report success, and leave the copied policy naming the ORIGINALS.
Nothing would have failed.

These guards cover both halves, because a fix to either one alone re-opens it:
whatever the reader splits, the writer must re-point.
"""
from app.services import clone


SCRIPT_URN = "cmdb/waf/scripting"
POLICY_URN = "cmdb/server-policy/policy"


def _coll():
    return clone.objform.collection_of(SCRIPT_URN)


def _item(**kw):
    base = dict(label="x", urn=SCRIPT_URN, logical="scripting", mkey="",
                parent_mkey="", kind="object", depth=1, payload={})
    base.update(kw)
    return clone.CloneItem(**base)


# --------------------------------------------------------------------- #
#  repoint_value — the unit
# --------------------------------------------------------------------- #
def test_every_name_in_a_list_field_is_repointed():
    out = clone.repoint_value("scripting-list", "lua1 lua2 ",
                              [_coll()],
                              {_coll(): {"lua1": "lua1-copy", "lua2": "lua2-copy"}})
    assert out == "lua1-copy lua2-copy "


def test_the_trailing_space_survives():
    """FortiWeb returns ``"a b "``. Rejoining with a plain " ".join() eats the
    trailing space and hands the appliance a value it did not send."""
    out = clone.repoint_value("scripting-list", "a b ", [_coll()],
                              {_coll(): {"a": "a-copy", "b": "b-copy"}})
    assert out.endswith(" "), out
    assert out == "a-copy b-copy "


def test_a_name_that_was_not_renamed_survives_byte_for_byte():
    """Only ``a`` moved. ``b`` must be left EXACTLY as the appliance sent it —
    including the double space, which is the appliance's separator, not ours."""
    out = clone.repoint_value("scripting-list", "a  b ", [_coll()],
                              {_coll(): {"a": "a-copy"}})
    assert out == "a-copy  b "


def test_nothing_renamed_returns_none():
    """``None`` means "no edit" — it is what stops ``deep_rename`` from copying
    a payload it did not change."""
    assert clone.repoint_value("scripting-list", "a b ", [_coll()],
                               {_coll(): {"zz": "zz-copy"}}) is None


def test_a_non_list_field_is_matched_whole_including_its_trailing_space():
    """The declared set governs BOTH halves. A field outside it keeps the old
    verbatim semantics: the trailing space may be part of the name."""
    colls = [_coll()]
    assert clone.repoint_value("health", "zztrail ", colls,
                               {_coll(): {"zztrail ": "zztrail -copy"}}) == "zztrail -copy"
    # ... and the same value must NOT resolve through the space-stripped name.
    assert clone.repoint_value("health", "zztrail ", colls,
                               {_coll(): {"zztrail": "zztrail-copy"}}) is None


def test_a_non_list_field_is_never_split():
    """Splitting an undeclared field would rewrite one word of a two-word NAME."""
    out = clone.repoint_value("health", "zz probe", [_coll()],
                              {_coll(): {"zz": "zz-copy"}})
    assert out is None, out


def test_an_unindexed_field_is_never_touched():
    """No collection for this field means the dependency map does not say it
    names an object. Matching anyway rewrites descriptions and host headers."""
    assert clone.repoint_value("comment", "lua1", (),
                               {_coll(): {"lua1": "lua1-copy"}}) is None


def test_a_disabled_marker_inside_a_list_is_not_a_name():
    out = clone.repoint_value("scripting-list", "disable", [_coll()],
                              {_coll(): {"lua1": "lua1-copy"}})
    assert out is None


# --------------------------------------------------------------------- #
#  read and re-point must agree — the actual defect
# --------------------------------------------------------------------- #
def test_read_and_repoint_agree_on_every_declared_list_field():
    """Whatever ``referenced_names`` extracts as a name (and therefore COPIES)
    must be a name ``repoint_value`` can move. This is the invariant that broke:
    the reader split, the writer did not."""
    for field in sorted(clone._LIST_REF_FIELDS):
        value = "alpha beta "
        names = clone.referenced_names({field: value}, field)
        assert names == ["alpha", "beta"], (field, names)
        by_coll = {_coll(): {n: n + "-copy" for n in names}}
        out = clone.repoint_value(field, value, [_coll()], by_coll)
        for n in names:
            assert n + "-copy" in out, (field, n, out)
        assert out == "alpha-copy beta-copy "


def test_scripting_list_is_indexed_so_the_repoint_can_fire_at_all():
    """A correct ``repoint_value`` is dead code if the dependency map never
    records the field as a reference edge."""
    assert clone.via_field_index().get("scripting-list")


# --------------------------------------------------------------------- #
#  end to end through deep_rename
# --------------------------------------------------------------------- #
def _plan_with_two_scripts(value="lua1 lua2 "):
    pol = clone.CloneItem(label="Policy", urn=POLICY_URN, logical="server_policy",
                          mkey="pol1", parent_mkey="", kind="object", depth=0,
                          payload={"name": "pol1", "scripting-list": value})
    s1 = _item(mkey="lua1", payload={"name": "lua1"})
    s2 = _item(mkey="lua2", payload={"name": "lua2"})
    return [pol, s1, s2]


def test_deep_rename_repoints_the_copied_policy_at_the_copied_scripts():
    items = _plan_with_two_scripts()
    created = {(SCRIPT_URN, "lua1"), (SCRIPT_URN, "lua2")}
    renames = clone.deep_rename(items, "-copy", created,
                                index={"scripting-list": {_coll()}})
    assert {r["old"] for r in renames} == {"lua1", "lua2"}
    assert items[0].payload["scripting-list"] == "lua1-copy lua2-copy "


def test_the_copy_shares_nothing_with_the_source():
    """The failure mode in one assertion: no ORIGINAL name may survive in the
    copied policy's reference field."""
    items = _plan_with_two_scripts()
    created = {(SCRIPT_URN, "lua1"), (SCRIPT_URN, "lua2")}
    clone.deep_rename(items, "-copy", created,
                      index={"scripting-list": {_coll()}})
    tokens = items[0].payload["scripting-list"].split()
    assert "lua1" not in tokens and "lua2" not in tokens, tokens


def test_a_single_name_with_a_trailing_space_is_still_repointed():
    """The shape measured live on fw12: one script, one trailing space. Whole-
    value matching missed even this."""
    items = _plan_with_two_scripts(value="lua1 ")
    created = {(SCRIPT_URN, "lua1")}
    clone.deep_rename(items, "-copy", created,
                      index={"scripting-list": {_coll()}})
    assert items[0].payload["scripting-list"] == "lua1-copy "


def test_deep_rename_leaves_an_untouched_payload_identical():
    items = _plan_with_two_scripts()
    before = items[0].payload
    clone.deep_rename(items, "-copy", set(),
                      index={"scripting-list": {_coll()}})
    assert items[0].payload is before


def test_the_collections_are_walked_once_per_name_not_once_in_total():
    """``colls`` arrives as whatever the index yields. If it is consumed lazily,
    the first name eats it and every later name in the list silently keeps
    naming the original."""
    colls = (c for c in [_coll()])
    out = clone.repoint_value("scripting-list", "a b ", colls,
                              {_coll(): {"a": "a-copy", "b": "b-copy"}})
    assert out == "a-copy b-copy "
