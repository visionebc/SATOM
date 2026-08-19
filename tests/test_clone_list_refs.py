"""Multi-valued reference fields (services.clone._LIST_REF_FIELDS).

FortiWeb 7.6.8 returns ``scripting-list`` as a SPACE-SEPARATED LIST with a
TRAILING SPACE — ``"zzprobe-lua "`` for one script, ``"a b "`` for two. Read as
a single name the trailing space lands in the mkey, the source read answers
``-3 The entry is not found``, the item's payload comes back empty and
``validate_completeness`` refuses the whole clone. The one-script case failed
too, which is why "but the script IS on the destination" never helped.

The split is declared PER FIELD on purpose: a space is a legal character in a
FortiWeb object name nearly everywhere, so a global split/strip would turn one
legal name into two that do not exist — the same block, moved.
"""
from app.services import clone
from app.registry.dependencies import DepNode


def _node(name, urn, via="", children=()):
    return DepNode(name, urn, via, "", tuple(children))


_POLICY = _node("Server Policy", "u/pol", children=(
    _node("Scripting", "u/script", via="scripting-list"),
    _node("Health Check", "u/health", via="health"),
))
_URN_INDEX = {"u/pol": "pol_l", "u/script": "script_l", "u/health": "health_l"}


class FakeReader:
    def __init__(self, data):
        self.data = data
        self.asked = []

    def get_raw(self, urn, mkey=""):
        self.asked.append((urn, mkey))
        v = self.data.get((urn, mkey))
        if v is None:
            return []
        return v if isinstance(v, list) else [v]


def _planner(src, dst):
    p = clone.ClonePlanner(src, dst)
    p.urn_index = dict(_URN_INDEX)
    return p


# --------------------------------------------------------------------------- #
#  The parse itself                                                             #
# --------------------------------------------------------------------------- #
def test_one_script_drops_the_trailing_space():
    # THE reported bug: a single script already failed, because the device
    # appends a trailing space even to a one-entry list.
    assert clone.referenced_names({"scripting-list": "zzprobe-lua "},
                                  "scripting-list") == ["zzprobe-lua"]


def test_two_scripts_are_two_names():
    assert clone.referenced_names({"scripting-list": "a b "},
                                  "scripting-list") == ["a", "b"]


def test_repeated_name_in_a_list_is_collected_once():
    assert clone.referenced_names({"scripting-list": "a a b"},
                                  "scripting-list") == ["a", "b"]


def test_empty_tokens_in_a_list_are_dropped():
    assert clone.referenced_names({"scripting-list": "disable"},
                                  "scripting-list") == []
    assert clone.referenced_names({"scripting-list": "   "},
                                  "scripting-list") == []


def test_an_undeclared_field_keeps_a_name_with_an_INNER_space():
    # measured: a health check may legally be called "zz probe space". Splitting
    # it would ask the device for two objects that do not exist.
    assert clone.referenced_names({"health": "zz probe space"},
                                  "health") == ["zz probe space"]


def test_an_undeclared_field_keeps_a_TRAILING_space():
    # measured: a health check named "zztrail " keeps the space and can only be
    # deleted WITH it — so stripping it would address the wrong object.
    assert clone.referenced_names({"health": "zztrail "},
                                  "health") == ["zztrail "]


def test_the_split_is_declared_per_field_not_global():
    assert "scripting-list" in clone._LIST_REF_FIELDS
    assert "health" not in clone._LIST_REF_FIELDS


def test_every_declared_list_field_is_a_real_via_token():
    # a typo in the table is silent: the field simply never splits.
    tokens = set(clone.via_field_index())
    assert clone._LIST_REF_FIELDS <= tokens, sorted(clone._LIST_REF_FIELDS - tokens)


# --------------------------------------------------------------------------- #
#  Through the planner — the path the operator actually runs                    #
# --------------------------------------------------------------------------- #
def _src_with(scripting_list):
    return FakeReader({
        ("u/pol", "pol1"): {"name": "pol1", "scripting-list": scripting_list},
        ("u/script", "s1"): {"name": "s1"},
        ("u/script", "s2"): {"name": "s2"},
    })


def test_planner_collects_the_script_and_does_not_block():
    src = _src_with("s1 ")
    items = _planner(src, FakeReader({})).collect(_POLICY, "pol1")
    scripts = [it for it in items if it.urn == "u/script"]
    assert [it.mkey for it in scripts] == ["s1"]
    assert scripts[0].payload, "the script resolved on the source"
    assert clone.validate_completeness(items) == []


def test_planner_collects_BOTH_scripts():
    src = _src_with("s1 s2 ")
    items = _planner(src, FakeReader({})).collect(_POLICY, "pol1")
    assert [it.mkey for it in items if it.urn == "u/script"] == ["s1", "s2"]
    assert clone.validate_completeness(items) == []


def test_the_source_is_asked_for_the_TRIMMED_name():
    # the -3 came from asking for "s1 "; pin the actual read key.
    src = _src_with("s1 ")
    _planner(src, FakeReader({})).collect(_POLICY, "pol1")
    assert ("u/script", "s1") in src.asked
    assert ("u/script", "s1 ") not in src.asked


def test_a_script_missing_on_the_source_still_blocks():
    # the fix must not turn a REAL dangling reference into a silent pass.
    src = FakeReader({("u/pol", "pol1"): {"name": "pol1",
                                          "scripting-list": "ghost "}})
    items = _planner(src, FakeReader({})).collect(_POLICY, "pol1")
    issues = clone.validate_completeness(items)
    assert [i["mkey"] for i in issues] == ["ghost"]


def test_a_second_script_missing_blocks_naming_ONLY_that_one():
    src = FakeReader({
        ("u/pol", "pol1"): {"name": "pol1", "scripting-list": "s1 ghost "},
        ("u/script", "s1"): {"name": "s1"},
    })
    items = _planner(src, FakeReader({})).collect(_POLICY, "pol1")
    assert [i["mkey"] for i in clone.validate_completeness(items)] == ["ghost"]


def test_each_script_is_planned_as_its_own_create():
    src = _src_with("s1 s2 ")
    items = _planner(src, FakeReader({})).plan(_POLICY, "pol1")
    created = {it.mkey for it in items if it.urn == "u/script" and it.status == "create"}
    assert created == {"s1", "s2"}


def test_a_script_already_on_the_destination_is_exists_not_create():
    src = _src_with("s1 ")
    dst = FakeReader({("u/script", "s1"): {"name": "s1"}})
    items = _planner(src, dst).plan(_POLICY, "pol1")
    script = next(it for it in items if it.urn == "u/script")
    assert script.status == "exists"


def test_the_policy_payload_keeps_the_list_verbatim():
    # the copy must name BOTH scripts exactly as the source did — the split is a
    # read-side parse, never a rewrite of what gets written.
    src = _src_with("s1 s2 ")
    items = _planner(src, FakeReader({})).collect(_POLICY, "pol1")
    root = next(it for it in items if it.urn == "u/pol")
    assert root.payload["scripting-list"] == "s1 s2 "


# --------------------------------------------------------------------------- #
#  Premise guard for the OTHER consumer of a reference field                    #
# --------------------------------------------------------------------------- #
def test_deep_rename_never_meets_a_list_field_today():
    """``deep_rename`` re-points a reference by WHOLE-VALUE lookup, which cannot
    re-point one name inside a list. That is correct only while the same-device
    deep clone is scoped to the WPP tree, which owns no list field. If someone
    scopes it to the Server Policy root, this fails — and the list-aware
    re-point has to be written THEN, with a device measurement, instead of
    being guessed now against a case that cannot happen."""
    wpp_fields = set(clone.via_field_index(clone.ROOT_WPP))
    assert not (clone._LIST_REF_FIELDS & wpp_fields), (
        "deep_rename would now silently leave a list reference pointing at the "
        "ORIGINAL object: %s" % sorted(clone._LIST_REF_FIELDS & wpp_fields))


# --------------------------------------------------------------------------- #
#  deep_capture shares the parser — a snapshot lost the script too              #
# --------------------------------------------------------------------------- #
def test_deep_capture_nests_both_scripts():
    # deep_capture lists a collection whole (get_raw(urn, "")) and matches the
    # row by mkey, so the trailing space simply found NOTHING: every SoT
    # snapshot of a policy with a Lua script was missing the script.
    from app.services import deep_capture
    src = FakeReader({("u/script", ""): [{"name": "s1"}, {"name": "s2"}]})
    node = _node("Scripting", "u/script", via="scripting-list")
    got = deep_capture._named_subs(src, {"scripting-list": "s1 s2 "},
                                   node, set(), {})
    assert isinstance(got, list) and [g["name"] for g in got] == ["s1", "s2"]


def test_deep_capture_nests_a_SINGLE_script():
    from app.services import deep_capture
    src = FakeReader({("u/script", ""): [{"name": "s1"}]})
    node = _node("Scripting", "u/script", via="scripting-list")
    got = deep_capture._named_subs(src, {"scripting-list": "s1 "},
                                   node, set(), {})
    assert isinstance(got, dict) and got["name"] == "s1"
