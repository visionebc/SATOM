"""The two NON-INTERACTIVE profile policies ported from the standalone cloner.

* **reuse a profile the destination already owns** (standalone 1.13.0,
  ``dst_wpp``) — the destination has an equivalent profile under a DIFFERENT
  name. Nothing of the source's profile is copied and the policy's
  ``web-protection-profile`` field is rewritten.
* **create it only if it is missing** (standalone 1.15.0,
  ``wpp_only_if_missing``) — and the second half is the point. Leaving the
  subtree ON does NOT already promise that: an existing profile's OBJECT is
  classified ``exists`` and left alone, but its ~40 sub-tables are still
  classified one by one, so a signature list or a constraint the destination's
  profile does not have gets ADDED to it — a live profile, possibly shared with
  other policies, edited by the clone of a different one.

Behaviour tests: each one CALLS ``clone_policy`` with the combination and asks
what it did. A test that asserts a phrase is present in the source cannot tell a
live refusal from a commented-out one — ``if False and …`` contains every
fragment.
"""
import pytest

from app.services import clone, policy_ops

WPP = clone._WPP_INLINE
POL = "cmdb/server-policy/policy"


class FakeClient:
    """Only the checked lister matters here — that is the whole safety property."""

    def __init__(self, names, status="ok", err=""):
        self._names, self._status, self._err = names, status, err

    def cmdb_names_checked(self, endpoint):
        return list(self._names), self._status, self._err


class FakeReader:
    def __init__(self, rows=None, client=None):
        self.rows, self.client = rows or {}, client

    def get_raw(self, urn, mkey=""):
        return [dict(r) for r in self.rows.get((urn, mkey), [])]


def _items(with_wpp_object=True, profile="wpp-src"):
    root = clone.CloneItem(label="Server Policy", urn=POL, logical=None,
                           mkey="pol1", parent_mkey="", kind="object", depth=0,
                           payload={"name": "pol1",
                                    "web-protection-profile": profile})
    out = []
    if with_wpp_object:
        out.append(clone.CloneItem(
            label="Web Protection Profile", urn=WPP, logical=None,
            mkey=profile, parent_mkey="", kind="object", depth=1,
            payload={"name": profile}))
    out.append(root)
    return out


class FakePlanner:
    """Records what ``follow_wpp`` the plan was asked for — that IS the pruning."""

    def __init__(self, items, dst_names=("wpp-dst",), status="ok",
                 src_profile="wpp-src"):
        self._items = items
        self.asked = {}
        self.dst = FakeReader(client=FakeClient(dst_names, status))
        self.src = FakeReader({(POL, "pol1"): [
            {"name": "pol1", "web-protection-profile": src_profile}]})

    def plan(self, root, mkey, **kw):
        self.asked = dict(kw)
        return list(self._items)


class FakeRes:
    ok = True

    def get(self, k, d=None):
        return d


class FakeOps:
    def create(self, ep, data, *, mkey=None, dry_run=True):
        return FakeRes()

    def update(self, ep, mkey, data, *, dry_run=True, sub_mkey=None):
        return FakeRes()


def _run(**kw):
    p = kw.pop("planner")
    return p, policy_ops.clone_policy(p, FakeOps(), "pol1", new_name="pol1-copy",
                                      dry_run=True, **kw)


# --------------------------------------------------------------------------- #
#  wpp_landing_name — which name the collision check must ask about             #
# --------------------------------------------------------------------------- #
def test_the_landing_name_is_the_new_one_when_a_rename_is_in_play():
    # Asking about the SOURCE's name under a rename answers a question nobody
    # asked: the copy lands on the new name.
    assert clone.wpp_landing_name({"web-protection-profile": "a"}, "b") == "b"


def test_no_profile_is_written_by_fortiweb_as_the_word_disable():
    # A truthiness test on the field alone would treat "no profile" as a profile
    # NAMED `disable` and then report the destination as missing an object that
    # exists nowhere.
    assert clone.wpp_landing_name({"web-protection-profile": "disable"}) == ""
    assert clone.wpp_landing_name({"web-protection-profile": ""}) == ""


# --------------------------------------------------------------------------- #
#  only-if-missing                                                              #
# --------------------------------------------------------------------------- #
def test_an_existing_profile_prunes_the_whole_subtree():
    p = FakePlanner(_items(), dst_names=("wpp-src", "other"))
    _run(planner=p, wpp_only_if_missing=True)
    assert p.asked["follow_wpp"] is False


def test_a_missing_profile_is_still_copied_in_full():
    p = FakePlanner(_items(), dst_names=("something-else",))
    _run(planner=p, wpp_only_if_missing=True)
    assert p.asked["follow_wpp"] is True


def test_the_default_is_unchanged_behaviour():
    # OFF by default: this changes what a run WRITES, and that must not change
    # without someone choosing it.
    p = FakePlanner(_items(), dst_names=("wpp-src",))
    _run(planner=p)
    assert p.asked["follow_wpp"] is True


def test_an_unreadable_profile_list_refuses_instead_of_un_pruning():
    # The failure this exists to prevent, produced by the SAFETY read failing:
    # an empty set does not mean "the destination has no profiles", it means
    # every profile is missing — which un-prunes the subtree.
    p = FakePlanner(_items(), dst_names=(), status="error")
    with pytest.raises(RuntimeError) as e:
        _run(planner=p, wpp_only_if_missing=True)
    assert "cannot be treated as an empty one" in str(e.value)


def test_the_rename_decides_which_name_is_looked_for():
    # With a rename the copy lands on the NEW name, so a destination that has
    # the SOURCE's name is not a collision at all.
    p = FakePlanner(_items(), dst_names=("wpp-src",))
    _run(planner=p, wpp_only_if_missing=True, wpp_new_name="wpp-copy")
    assert p.asked["follow_wpp"] is True


# --------------------------------------------------------------------------- #
#  reuse the destination's profile                                              #
# --------------------------------------------------------------------------- #
def test_reusing_a_destination_profile_prunes_and_repoints():
    p = FakePlanner(_items(with_wpp_object=False), dst_names=("wpp-dst",))
    _p, items = _run(planner=p, dst_wpp="wpp-dst")
    assert p.asked["follow_wpp"] is False
    root = [i for i in items if i.urn == POL][0]
    # Pruning alone is NOT the feature: the copy would still NAME the source's
    # profile and the create would answer -651.
    assert root.payload["web-protection-profile"] == "wpp-dst"


def test_a_name_the_destination_does_not_have_is_refused_with_the_real_list():
    p = FakePlanner(_items(with_wpp_object=False), dst_names=("a", "b"))
    with pytest.raises(RuntimeError) as e:
        _run(planner=p, dst_wpp="nope")
    assert "a, b" in str(e.value)


def test_repoint_leaves_a_plan_that_still_carries_a_profile_alone():
    # Repointing then would create the source's profile at the destination and
    # then not use it — an orphan that looks like a successful copy.
    items = _items(with_wpp_object=True)
    assert clone.repoint_wpp(items, "wpp-dst") == []
    assert [i for i in items if i.urn == POL][0].payload[
        "web-protection-profile"] == "wpp-src"


def test_an_empty_destination_name_is_a_no_op_never_a_blank_write():
    # "" does not mean "no profile" to a FortiWeb policy — it means an
    # unparsable one.
    items = _items(with_wpp_object=False)
    assert clone.repoint_wpp(items, "   ") == []
    assert [i for i in items if i.urn == POL][0].payload[
        "web-protection-profile"] == "wpp-src"


# --------------------------------------------------------------------------- #
#  The combinations that ask for two different migrations                       #
# --------------------------------------------------------------------------- #
def test_reuse_and_only_if_missing_is_refused_not_silently_ordered():
    p = FakePlanner(_items(with_wpp_object=False))
    with pytest.raises(RuntimeError):
        _run(planner=p, dst_wpp="wpp-dst", wpp_only_if_missing=True)


def test_reuse_and_rename_is_refused():
    p = FakePlanner(_items(with_wpp_object=False))
    with pytest.raises(RuntimeError):
        _run(planner=p, dst_wpp="wpp-dst", wpp_new_name="wpp-copy")


def test_a_contradiction_is_answered_before_any_device_read():
    # A refusal already knowable from the arguments must not cost a round trip
    # to an appliance — on the bulk path that is one per policy.
    class Exploding(FakePlanner):
        @property
        def dst(self):
            raise AssertionError("the destination was read before the refusal")

        @dst.setter
        def dst(self, v):
            pass

    with pytest.raises(RuntimeError):
        _run(planner=Exploding(_items(with_wpp_object=False)),
             dst_wpp="x", wpp_new_name="y")


def test_both_modes_reach_the_dialog_and_the_bulk_job_from_one_place():
    import inspect
    src = inspect.getsource(policy_ops.perform_one)
    assert 'opts.get("dst_wpp")' in src
    assert 'opts.get("wpp_only_if_missing", False)' in src
    assert src.count("dst_wpp=dst_wpp") == 3
    assert src.count("wpp_only_if_missing=wpp_only_if_missing") == 3
