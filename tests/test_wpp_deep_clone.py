"""Guards for the SAME-DEVICE deep WPP clone (services.clone + services.clone_scope).

The defect these lock down did not look like a defect. ``ClonePlanner`` copies a
tree from one appliance to another and skips whatever already exists at the
destination — correct, and the reason ``tests/test_clone.py`` passes. Point it
at ONE appliance (``clone_and_rebind`` builds it with ``src is dst``) and that
same rule skips EVERYTHING: the "clone" renamed the root profile and left ~40
sub-policies shared with the original. Nothing failed. The plan said
``exists`` for every child, which is true and means the opposite of safe.

Live consequence, fortiweb08 2026-08-08: ``wpp-shop-full`` cloned to
``wpp-pol-shop-cms``, whose ``allow-method-policy`` was still ``am-std`` —
shared by three other profiles — so an allow-list written "for pol-shop-cms"
went live for five Server Policies.

Every guard here is written against a SYNTHETIC tree, so it runs with no Flask
and no device, and each one has been checked to fail when the behaviour it
describes is removed.
"""
import pytest

from app.registry.dependencies import DepNode
from app.services import clone, clone_scope


# --------------------------------------------------------------------------- #
#  Synthetic tree — WPP -> allow-method policy -> exception container (+ rows)  #
#  plus a signature set, which is where the "predefined" objects live.          #
# --------------------------------------------------------------------------- #
def _node(name, urn, via="", children=()):
    return DepNode(name, urn, via, "", tuple(children))


_EXC_ROW = _node("Exception List", "u/amexc/list")
_AMEXC = _node("Method Exception", "u/amexc", via="allow-method-exception",
               children=(_EXC_ROW,))
_AMPOL = _node("Allow Method Policy", "u/ampol", via="allow-method-policy",
               children=(_AMEXC,))
_SIG = _node("Signatures", "u/sig", via="signature-rule")
_WPP = _node("Web Protection Profile", "u/wpp", children=(_AMPOL, _SIG))

#: Same tree, except the signature set ALSO names the allow-method policy — so
#: ``am-std`` has two referrers and can only move if both of them move.
_SIG_2P = _node("Signatures", "u/sig", via="signature-rule", children=(_AMPOL,))
_WPP_2P = _node("Web Protection Profile", "u/wpp", children=(_AMPOL, _SIG_2P))

#: The REAL index builder, captured before the autouse fixture swaps it out.
_REAL_VIA_INDEX = clone.via_field_index

_URN_INDEX = {"u/wpp": "wpp_l", "u/ampol": "ampol_l", "u/amexc": "amexc_l",
              "u/amexc/list": "amexclist_l", "u/sig": "sig_l"}

#: What ``via_field_index`` would derive from the tree above. Passed explicitly
#: because the real index is built from the REAL dependency map.
_VIA = {"allow-method-policy": {"u/ampol"},
        "allow-method-exception": {"u/amexc"},
        "signature-rule": {"u/sig"}}


class FakeReader:
    def __init__(self, data):
        self.data = data

    def get_raw(self, urn, mkey=""):
        v = self.data.get((urn, mkey))
        if v is None:
            return []
        return v if isinstance(v, list) else [v]


def _device(*, sig_factory=False, extra=None):
    data = {
        ("u/wpp", "wpp-shop"): {"name": "wpp-shop", "allow-method-policy": "am-std",
                                "signature-rule": "sig-std"},
        ("u/ampol", "am-std"): {"name": "am-std", "allow-method-exception": "am-exc"},
        ("u/amexc", "am-exc"): {"name": "am-exc"},
        ("u/amexc/list", "am-exc"): [{"id": "1", "allow-request": "get"}],
        ("u/sig", "sig-std"): {"name": "sig-std",
                               **({"can_view": 1} if sig_factory else {})},
    }
    data.update(extra or {})
    return data


def _plan(data, *, managed=None, clone_anyway=(), src=None, tree=None):
    reader = FakeReader(data)
    p = clone.ClonePlanner(reader, reader)          # src IS dst — the whole point
    p.urn_index = dict(_URN_INDEX)
    items = p.plan(tree or _WPP, src or "wpp-shop", new_name="wpp-pol-shop-cms",
                   deep_suffix="pol-shop-cms", managed=managed or {},
                   clone_anyway=clone_anyway)
    return p, items


def _obj(items, urn):
    return next((it for it in items if it.kind == "object" and it.urn == urn), None)


# Real dependency map -> the index has to come from it, so the synthetic tests
# feed their own. Patch it in for the plan() path.
@pytest.fixture(autouse=True)
def _synthetic_via(monkeypatch):
    monkeypatch.setattr(clone, "via_field_index",
                        lambda root=None: {k: set(v) for k, v in _VIA.items()})


# --------------------------------------------------------------------------- #
#  1. The regression itself                                                     #
# --------------------------------------------------------------------------- #
def test_same_device_clone_copies_children_instead_of_sharing_them():
    """The bug: every child classified ``exists`` and nothing was created."""
    _p, items = _plan(_device())
    ampol = _obj(items, "u/ampol")
    assert ampol.mkey == "am-std-pol-shop-cms"
    assert ampol.renamed_from == "am-std"
    assert ampol.status == "create"
    assert ampol.payload["name"] == "am-std-pol-shop-cms"


def test_parent_reference_is_repointed_to_the_copy():
    """A copy nobody points at is not isolation — it is a second orphan."""
    _p, items = _plan(_device())
    root = _obj(items, "u/wpp")
    assert root.payload["allow-method-policy"] == "am-std-pol-shop-cms"
    assert root.payload["signature-rule"] == "sig-std-pol-shop-cms"


def test_the_whole_chain_is_copied_not_only_the_first_level():
    """``am-exc`` is where the carve-out row physically lands. A clone that
    isolates the policy but shares the exception container fixes nothing."""
    _p, items = _plan(_device())
    amexc = _obj(items, "u/amexc")
    assert amexc.mkey == "am-exc-pol-shop-cms"
    ampol = _obj(items, "u/ampol")
    assert ampol.payload["allow-method-exception"] == "am-exc-pol-shop-cms"


def test_subrows_follow_their_renamed_parent_and_are_created():
    rows = [it for it in items_of(_device()) if it.kind == "subrow"]
    assert rows, "the exception row must be in the plan"
    assert all(r.parent_mkey == "am-exc-pol-shop-cms" for r in rows)
    assert all(r.status == "create" for r in rows)


def items_of(data, **kw):
    return _plan(data, **kw)[1]


def test_nothing_is_left_classified_exists_when_the_tree_is_all_clonable():
    _p, items = _plan(_device())
    shared = [it for it in items if it.kind == "object" and it.status == "exists"]
    assert shared == [], (
        "a same-device clone that reports 'exists' is sharing that object with "
        "the source profile: %s" % [it.mkey for it in shared])


def test_without_deep_suffix_the_old_shared_behaviour_is_unchanged():
    """The cross-appliance contract must not move: ``deep_suffix`` is opt-in."""
    reader = FakeReader(_device())
    p = clone.ClonePlanner(reader, reader)
    p.urn_index = dict(_URN_INDEX)
    items = p.plan(_WPP, "wpp-shop", new_name="wpp-pol-shop-cms")
    ampol = _obj(items, "u/ampol")
    assert ampol.mkey == "am-std" and ampol.status == "exists"
    assert p.renames == []


# --------------------------------------------------------------------------- #
#  2. Predefined (factory) objects                                              #
# --------------------------------------------------------------------------- #
def test_factory_objects_are_detected_from_can_view_not_is_default():
    """Verified on fortiweb08 7.6.8: user objects carry ``can_view: 0``,
    FortiWeb's own carry ``can_view: 1``, and ``is_default`` was ``None`` on
    BOTH — keying on it would clone the vendor's baselines."""
    assert clone_scope.is_factory({"can_view": 1}) is True
    assert clone_scope.is_factory({"can_view": 0}) is False
    assert clone_scope.is_factory({"is_default": None, "can_view": 1}) is True
    assert clone_scope.is_factory({"is_default": 1}) is False
    assert clone_scope.is_factory(None) is False


def test_predefined_object_is_not_copied_and_is_reported():
    _p, items = _plan(_device(sig_factory=True))
    sig = _obj(items, "u/sig")
    assert sig.mkey == "sig-std", "a FortiGuard-maintained object was duplicated"
    assert sig.scope == clone_scope.FACTORY
    root = _obj(items, "u/wpp")
    assert root.payload["signature-rule"] == "sig-std"
    qs = clone_scope.questions(items)
    assert [q["mkey"] for q in qs] == ["sig-std"]
    assert qs[0]["overridable"] is True


def test_clone_anyway_overrides_a_predefined_refusal_and_clears_the_question():
    ref = "u/sig|sig-std"
    _p, items = _plan(_device(sig_factory=True), clone_anyway=[ref])
    sig = _obj(items, "u/sig")
    assert sig.mkey == "sig-std-pol-shop-cms"
    assert clone_scope.questions(items) == [], (
        "an object the operator chose to copy is not staying shared, so it "
        "cannot still be a question — and the apply gate counts questions")


def test_clone_anyway_needs_the_exact_object_not_just_the_name():
    """The override is keyed ``urn|name``: two collections can hold the same
    name, and 'clone anyway' for one must not silently authorise the other."""
    _p, items = _plan(_device(sig_factory=True), clone_anyway=["sig-std"])
    assert _obj(items, "u/sig").mkey == "sig-std"


# --------------------------------------------------------------------------- #
#  3. Template-governed objects                                                 #
# --------------------------------------------------------------------------- #
def test_template_governed_object_is_not_copied():
    managed = {"u/ampol": {"am-std"}}
    _p, items = _plan(_device(), managed=managed)
    ampol = _obj(items, "u/ampol")
    assert ampol.mkey == "am-std"
    assert ampol.scope == clone_scope.TEMPLATE
    assert "template" in ampol.scope_reason.lower()


def test_template_governance_is_matched_per_collection():
    """A name approved as a WPP template must not lock a signature policy that
    happens to share it — the live library had exactly that mis-attribution."""
    managed = {"u/wpp": {"am-std"}}          # right name, WRONG collection
    _p, items = _plan(_device(), managed=managed)
    assert _obj(items, "u/ampol").scope == clone_scope.CLONABLE


# --------------------------------------------------------------------------- #
#  4. The cascade: re-pointing a reference is a WRITE TO THE PARENT             #
# --------------------------------------------------------------------------- #
def test_child_of_a_shared_parent_is_not_copied():
    """``am-exc`` may only be duplicated if ``am-std`` is duplicated too:
    otherwise re-pointing ``am-std.allow-method-exception`` at the copy edits an
    object every other profile still reads — the same leak, one level up."""
    managed = {"u/ampol": {"am-std"}}        # am-std stays shared
    _p, items = _plan(_device(), managed=managed)
    amexc = _obj(items, "u/amexc")
    assert amexc.mkey == "am-exc", "a shared parent was about to be re-pointed"
    assert amexc.scope == clone_scope.BLOCKED_BY_PARENT
    assert _obj(items, "u/ampol").payload["allow-method-exception"] == "am-exc"


def test_blocked_by_parent_is_never_offered_as_clone_anyway():
    """It is a consequence, not a decision. Offering an override would invite
    the operator to authorise the exact write this guard exists to prevent."""
    managed = {"u/ampol": {"am-std"}}
    _p, items = _plan(_device(), managed=managed)
    q = next(q for q in clone_scope.questions(items) if q["mkey"] == "am-exc")
    assert q["overridable"] is False
    assert clone_scope.BLOCKED_BY_PARENT not in clone_scope.OVERRIDABLE


def test_blocked_reason_names_the_parent_that_stays_shared():
    """'It stays shared' without 'behind what?' cannot be acted on."""
    managed = {"u/ampol": {"am-std"}}
    _p, items = _plan(_device(), managed=managed)
    assert "am-std" in _obj(items, "u/amexc").scope_reason


def test_overriding_the_parent_unblocks_the_child():
    managed = {"u/ampol": {"am-std"}}
    _p, items = _plan(_device(), managed=managed, clone_anyway=["u/ampol|am-std"])
    assert _obj(items, "u/ampol").mkey == "am-std-pol-shop-cms"
    assert _obj(items, "u/amexc").mkey == "am-exc-pol-shop-cms"
    assert clone_scope.questions(items) == []


def test_an_object_named_by_two_parents_is_only_copied_if_both_are():
    """The second referrer is what makes a re-point unsafe, and ``visited``
    would hide it — the refs map has to record it anyway."""
    data = _device()
    data[("u/sig", "sig-std")] = {"name": "sig-std", "allow-method-policy": "am-std"}
    _p, items = _plan(data, managed={"u/sig": {"sig-std"}}, tree=_WPP_2P)
    # sig-std stays shared and also names am-std, so am-std cannot move.
    assert _obj(items, "u/ampol").mkey == "am-std"
    assert _obj(items, "u/ampol").scope == clone_scope.BLOCKED_BY_PARENT
    # ...and with BOTH referrers moving, it moves.
    _p2, items2 = _plan(data, tree=_WPP_2P)
    assert _obj(items2, "u/ampol").mkey == "am-std-pol-shop-cms"


# --------------------------------------------------------------------------- #
#  5. Derived names                                                             #
# --------------------------------------------------------------------------- #
def test_derived_name_truncates_the_base_and_never_the_suffix():
    """The suffix is what makes the name unique per policy; trimming it is how
    two policies end up sharing a 'private' object again."""
    long = "x" * 200
    name = clone_scope.derive_name(long, "pol-shop-cms")
    assert len(name) <= clone_scope.MAX_NAME
    assert name.endswith("-pol-shop-cms")


def test_derived_name_avoids_a_name_already_on_the_box():
    taken = {"am-std-p"}
    name = clone_scope.derive_name("am-std", "p", lambda n: n in taken)
    assert name not in taken and name.startswith("am-std")


def test_derived_name_gives_up_rather_than_returning_a_collision():
    assert clone_scope.derive_name("a", "p", lambda n: True) == ""
    assert clone_scope.derive_name("a", "") == ""
    assert clone_scope.derive_name("", "p") == ""
    assert clone_scope.derive_name("a", "y" * clone_scope.MAX_NAME) == ""


def test_an_object_with_no_derivable_name_stays_shared_and_says_so():
    reader = FakeReader(_device())
    p = clone.ClonePlanner(reader, reader)
    p.urn_index = dict(_URN_INDEX)
    items = p.collect(_WPP, "wpp-shop", new_name="wpp-pol-shop-cms")
    clone.classify_scope(items, {})
    created = clone.resolve_shared(items, p._refs, root_mkey="wpp-shop")
    renames = clone.deep_rename(items, "p", created, exists=lambda u, n: True,
                                index=_VIA)
    assert renames == []
    ampol = _obj(items, "u/ampol")
    assert ampol.mkey == "am-std"
    assert ampol.scope == clone_scope.BLOCKED_BY_PARENT
    assert "limit" in ampol.scope_reason


# --------------------------------------------------------------------------- #
#  6. Reference rewriting is field-scoped                                       #
# --------------------------------------------------------------------------- #
def test_only_dependency_fields_are_rewritten():
    """Rewriting 'any string equal to the old name' would edit descriptions,
    host headers and rule bodies that merely mention it."""
    data = _device()
    data[("u/wpp", "wpp-shop")] = {"name": "wpp-shop", "allow-method-policy": "am-std",
                                   "signature-rule": "sig-std", "comment": "am-std"}
    _p, items = _plan(data)
    root = _obj(items, "u/wpp")
    assert root.payload["allow-method-policy"] == "am-std-pol-shop-cms"
    assert root.payload["comment"] == "am-std"


def test_via_index_is_derived_from_the_dependency_map():
    """Two authors of the same fact diverge on the first FortiWeb release."""
    index = _REAL_VIA_INDEX()
    assert "allow-method-policy" in index
    assert "waf/allow-method-policy" in index["allow-method-policy"]
    assert "signature-rule" in index
    # A by-parent sub-table is not a named reference and must not be indexed.
    assert "id" not in index


# --------------------------------------------------------------------------- #
#  7. Capacity is checked per object TYPE, not once for the profile             #
# --------------------------------------------------------------------------- #
def test_wants_by_logical_counts_only_created_objects():
    _p, items = _plan(_device())
    wants = clone.wants_by_logical(items)
    assert wants.get("ampol_l") == 1
    assert "amexclist_l" not in wants, "a sub-table row is not an object"
    for it in items:
        it.status = "exists"
    assert clone.wants_by_logical(items) == {}
